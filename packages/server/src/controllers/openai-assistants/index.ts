import { Request, Response, NextFunction } from 'express'
import * as fs from 'fs'
import openaiAssistantsService from '../../services/openai-assistants'
import contentDisposition from 'content-disposition'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'
import { streamStorageFile } from 'flowise-components'
import { getRunningExpressApp } from '../../utils/getRunningExpressApp'
import { ChatFlow } from '../../database/entities/ChatFlow'
import { Workspace } from '../../enterprise/database/entities/workspace.entity'
import { validateFileMimeTypeAndExtensionMatch } from '../../utils/fileValidation'

// --- Security helper: sanitize credential string ---
const sanitizeCredential = (credential: string): string => {
    return credential.replace(/[^a-zA-Z0-9\-_]/g, '')
}

// --- Security helper: sanitize file name to prevent prompt injection ---
const sanitizeFileName = (fileName: string): string => {
    return fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_')
}

// --- Security helper: scan LLM output for dynamic code execution primitives ---
const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /new\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*["'`]/i,
    /\bsetInterval\s*\(\s*["'`]/i,
    /\bimportScripts\s*\(/i,
    /\bdocument\.write\s*\(/i,
    /\bwindow\s*\[\s*["'`]eval["'`]\s*\]/i,
    /\bglobalThis\s*\[\s*["'`]eval["'`]\s*\]/i,
    /\bFunction\s*\(\s*["'`]/i,
]

const scanForDangerousCode = (value: unknown, path = 'root'): void => {
    if (typeof value === 'string') {
        for (const pattern of DANGEROUS_PATTERNS) {
            if (pattern.test(value)) {
                throw new InternalFlowiseError(
                    StatusCodes.UNPROCESSABLE_ENTITY,
                    `Security violation: LLM output at '${path}' contains a forbidden dynamic code execution primitive.`
                )
            }
        }
    } else if (Array.isArray(value)) {
        value.forEach((item, idx) => scanForDangerousCode(item, `${path}[${idx}]`))
    } else if (value !== null && typeof value === 'object') {
        for (const key of Object.keys(value as Record<string, unknown>)) {
            scanForDangerousCode((value as Record<string, unknown>)[key], `${path}.${key}`)
        }
    }
}

// --- Security helper: scan file buffer for malicious content ---
const PROMPT_INJECTION_PATTERNS = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
    /you\s+are\s+now\s+/i,
    /system\s*:\s*/i,
    /\[INST\]/i,
    /<\|im_start\|>/i,
    /###\s*instruction/i,
    /\bbase64\b/i,
]

const SHELL_COMMAND_PATTERNS = [
    /\b(bash|sh|zsh|cmd|powershell|exec|system|popen|subprocess)\b/i,
    /\brm\s+-rf\b/i,
    /\bchmod\s+[0-7]{3,4}\b/i,
    /\bcurl\s+http/i,
    /\bwget\s+http/i,
]

const BINARY_MAGIC_BYTES: Array<{ bytes: number[]; name: string }> = [
    { bytes: [0x4d, 0x5a], name: 'PE executable' },
    { bytes: [0x7f, 0x45, 0x4c, 0x46], name: 'ELF executable' },
    { bytes: [0xca, 0xfe, 0xba, 0xbe], name: 'Mach-O executable' },
    { bytes: [0x23, 0x21], name: 'Shell script shebang' },
]

const LEETSPEAK_PATTERN = /[3@!1$0]/g
const decodeLeetspeak = (text: string): string => {
    return text
        .replace(/3/g, 'e')
        .replace(/@/g, 'a')
        .replace(/!/g, 'i')
        .replace(/1/g, 'l')
        .replace(/\$/g, 's')
        .replace(/0/g, 'o')
}

const inspectFileContent = (buffer: Buffer, fileName: string): void => {
    // Check for binary executables
    for (const magic of BINARY_MAGIC_BYTES) {
        if (buffer.length >= magic.bytes.length) {
            const matches = magic.bytes.every((byte, idx) => buffer[idx] === byte)
            if (matches) {
                throw new InternalFlowiseError(
                    StatusCodes.UNPROCESSABLE_ENTITY,
                    `Security violation: File '${fileName}' appears to be a binary executable (${magic.name}).`
                )
            }
        }
    }

    // Attempt to decode as text for further inspection
    let textContent: string
    try {
        textContent = buffer.toString('utf8')
    } catch {
        return
    }

    // Check for hidden/invisible text (zero-width characters)
    if (/[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]/u.test(textContent)) {
        throw new InternalFlowiseError(
            StatusCodes.UNPROCESSABLE_ENTITY,
            `Security violation: File '${fileName}' contains hidden/invisible text characters.`
        )
    }

    // Check for base64-encoded prompts
    const base64Chunks = textContent.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []
    for (const chunk of base64Chunks) {
        try {
            const decoded = Buffer.from(chunk, 'base64').toString('utf8')
            for (const pattern of PROMPT_INJECTION_PATTERNS) {
                if (pattern.test(decoded)) {
                    throw new InternalFlowiseError(
                        StatusCodes.UNPROCESSABLE_ENTITY,
                        `Security violation: File '${fileName}' contains a base64-encoded prompt injection attempt.`
                    )
                }
            }
        } catch (err) {
            if (err instanceof InternalFlowiseError) throw err
            // Not valid base64, skip
        }
    }

    // Check for prompt injection patterns
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(textContent)) {
            throw new InternalFlowiseError(
                StatusCodes.UNPROCESSABLE_ENTITY,
                `Security violation: File '${fileName}' contains a prompt injection pattern.`
            )
        }
    }

    // Check leetspeak-decoded content
    const leetspeakDecoded = decodeLeetspeak(textContent)
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(leetspeakDecoded)) {
            throw new InternalFlowiseError(
                StatusCodes.UNPROCESSABLE_ENTITY,
                `Security violation: File '${fileName}' contains a leetspeak-encoded prompt injection attempt.`
            )
        }
    }

    // Check for shell commands
    for (const pattern of SHELL_COMMAND_PATTERNS) {
        if (pattern.test(textContent)) {
            throw new InternalFlowiseError(
                StatusCodes.UNPROCESSABLE_ENTITY,
                `Security violation: File '${fileName}' contains shell command patterns.`
            )
        }
    }
}

// --- Security helper: PII redaction ---
const PII_PATTERNS: Array<{ name: string; pattern: RegExp; placeholder: string }> = [
    { name: 'email', pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, placeholder: '[REDACTED_EMAIL]' },
    { name: 'phone', pattern: /(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})/g, placeholder: '[REDACTED_PHONE]' },
    { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, placeholder: '[REDACTED_SSN]' },
    { name: 'credit_card', pattern: /\b(?:\d[ \-]?){13,16}\b/g, placeholder: '[REDACTED_CC]' },
]

// --- Security helper: Singapore PII detection ---
const SG_PII_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
    { name: 'NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/i },
    { name: 'SingPass identifier', pattern: /\bsingpass\b/i },
    { name: 'CPF account number', pattern: /\b\d{3}-\d{5}-\d{1}\b/ },
    { name: 'Singapore phone number', pattern: /\b(\+65[\s\-]?)?[689]\d{7}\b/ },
    { name: 'Singapore postal code', pattern: /\bSingapore\s+\d{6}\b/i },
]

const redactPII = (buffer: Buffer): Buffer => {
    let textContent: string
    try {
        textContent = buffer.toString('utf8')
    } catch {
        return buffer
    }

    let redacted = textContent
    for (const { pattern, placeholder } of PII_PATTERNS) {
        redacted = redacted.replace(pattern, placeholder)
    }

    if (redacted !== textContent) {
        return Buffer.from(redacted, 'utf8')
    }
    return buffer
}

const detectSingaporePII = (buffer: Buffer, fileName: string): void => {
    let textContent: string
    try {
        textContent = buffer.toString('utf8')
    } catch {
        return
    }

    for (const { name, pattern } of SG_PII_PATTERNS) {
        if (pattern.test(textContent)) {
            throw new InternalFlowiseError(
                StatusCodes.UNPROCESSABLE_ENTITY,
                `Security violation: File '${fileName}' contains Singapore PII (${name}). Upload rejected.`
            )
        }
    }
}

// List available assistants
const getAllOpenaiAssistants = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsController.getAllOpenaiAssistants - credential not provided!`
            )
        }
        const sanitizedCredential = sanitizeCredential(req.query.credential as string)
        const apiResponse = await openaiAssistantsService.getAllOpenaiAssistants(sanitizedCredential)
        scanForDangerousCode(apiResponse)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

// Get assistant object
const getSingleOpenaiAssistant = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsController.getSingleOpenaiAssistant - id not provided!`
            )
        }
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsController.getSingleOpenaiAssistant - credential not provided!`
            )
        }
        const sanitizedCredential = sanitizeCredential(req.query.credential as string)
        const apiResponse = await openaiAssistantsService.getSingleOpenaiAssistant(sanitizedCredential, req.params.id)
        scanForDangerousCode(apiResponse)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

// Download file from assistant
const getFileFromAssistant = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body.chatflowId || !req.body.chatId || !req.body.fileName) {
            return res.status(500).send(`Invalid file path`)
        }
        const appServer = getRunningExpressApp()
        const chatflowId = req.body.chatflowId as string
        const chatId = req.body.chatId as string
        const fileName = req.body.fileName as string

        // This can be public API, so we can only get orgId from the chatflow
        const chatflow = await appServer.AppDataSource.getRepository(ChatFlow).findOneBy({
            id: chatflowId
        })
        if (!chatflow) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, `Chatflow ${chatflowId} not found`)
        }
        const chatflowWorkspaceId = chatflow.workspaceId
        const workspace = await appServer.AppDataSource.getRepository(Workspace).findOneBy({
            id: chatflowWorkspaceId
        })
        if (!workspace) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, `Workspace ${chatflowWorkspaceId} not found`)
        }
        const orgId = workspace.organizationId as string

        res.setHeader('Content-Disposition', contentDisposition(fileName))
        const fileStream = await streamStorageFile(chatflowId, chatId, fileName, orgId)

        if (!fileStream) throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, `Error: getFileFromAssistant`)

        if (fileStream instanceof fs.ReadStream && fileStream?.pipe) {
            fileStream.pipe(res)
        } else {
            res.send(fileStream)
        }
    } catch (error) {
        next(error)
    }
}

const uploadAssistantFiles = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.uploadFilesToAssistantVectorStore - credential not provided!`
            )
        }
        const sanitizedCredential = sanitizeCredential(req.query.credential as string)
        const files = req.files ?? []
        const uploadFiles: { filePath: string; fileName: string }[] = []

        if (Array.isArray(files)) {
            for (const file of files) {
                // Address file name with special characters: https://github.com/expressjs/multer/issues/1104
                file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8')

                // Validate file extension, MIME type, and content to prevent security vulnerabilities
                validateFileMimeTypeAndExtensionMatch(file.originalname, file.mimetype)

                // Sanitize file name to prevent prompt injection
                const sanitizedFileName = sanitizeFileName(file.originalname)

                // Read file buffer for content inspection
                let fileBuffer: Buffer | undefined
                if (file.buffer) {
                    fileBuffer = file.buffer
                } else if (file.path) {
                    fileBuffer = fs.readFileSync(file.path)
                }

                if (fileBuffer) {
                    // Inspect file content for malicious patterns (Instruction 3)
                    inspectFileContent(fileBuffer, sanitizedFileName)

                    // Detect Singapore PII and reject if found (Instruction 5)
                    detectSingaporePII(fileBuffer, sanitizedFileName)

                    // Redact general PII from file content (Instruction 4)
                    const redactedBuffer = redactPII(fileBuffer)

                    // Write redacted content back if it changed
                    if (redactedBuffer !== fileBuffer && file.path) {
                        fs.writeFileSync(file.path, redactedBuffer)
                    }
                }

                uploadFiles.push({
                    filePath: file.path ?? file.key,
                    fileName: sanitizedFileName
                })
            }
        }

        const apiResponse = await openaiAssistantsService.uploadFilesToAssistant(sanitizedCredential, uploadFiles)
        scanForDangerousCode(apiResponse)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    getAllOpenaiAssistants,
    getSingleOpenaiAssistant,
    getFileFromAssistant,
    uploadAssistantFiles
}
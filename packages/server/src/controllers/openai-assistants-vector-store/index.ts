import { Request, Response, NextFunction } from 'express'
import { StatusCodes } from 'http-status-codes'
import * as fs from 'fs'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import openAIAssistantVectorStoreService from '../../services/openai-assistants-vector-store'
import { validateFileMimeTypeAndExtensionMatch } from '../../utils/fileValidation'

// Sanitization helper: extract only known safe fields and validate types
const sanitizeVectorStoreBody = (body: any): Record<string, any> => {
    const sanitized: Record<string, any> = {}

    if (body.name !== undefined) {
        if (typeof body.name !== 'string') {
            throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, 'Invalid type for field: name')
        }
        sanitized.name = body.name.trim()
    }

    if (body.expires_after !== undefined) {
        if (typeof body.expires_after !== 'object' || body.expires_after === null) {
            throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, 'Invalid type for field: expires_after')
        }
        sanitized.expires_after = body.expires_after
    }

    if (body.metadata !== undefined) {
        if (typeof body.metadata !== 'object' || body.metadata === null || Array.isArray(body.metadata)) {
            throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, 'Invalid type for field: metadata')
        }
        sanitized.metadata = body.metadata
    }

    if (body.file_ids !== undefined) {
        if (!Array.isArray(body.file_ids) || !body.file_ids.every((id: any) => typeof id === 'string')) {
            throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, 'Invalid type for field: file_ids')
        }
        sanitized.file_ids = body.file_ids
    }

    if (body.chunking_strategy !== undefined) {
        if (typeof body.chunking_strategy !== 'object' || body.chunking_strategy === null) {
            throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, 'Invalid type for field: chunking_strategy')
        }
        sanitized.chunking_strategy = body.chunking_strategy
    }

    return sanitized
}

// Content scanning for malicious content in uploaded files
const scanFileForMaliciousContent = (buffer: Buffer, fileName: string): void => {
    const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1024 * 1024))

    // Check for hidden/invisible text patterns (zero-width characters)
    const zeroWidthPattern = /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD]/g
    if (zeroWidthPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains hidden/invisible text patterns and cannot be uploaded.`
        )
    }

    // Check for white-on-white CSS patterns
    const hiddenCSSPattern = /color\s*:\s*white|color\s*:\s*#fff|color\s*:\s*#ffffff|visibility\s*:\s*hidden|display\s*:\s*none/gi
    if (hiddenCSSPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains hidden text CSS patterns and cannot be uploaded.`
        )
    }

    // Check for base64-encoded prompt injections
    const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/g
    const base64Matches = content.match(base64Pattern)
    if (base64Matches) {
        for (const match of base64Matches) {
            try {
                const decoded = Buffer.from(match, 'base64').toString('utf8')
                const injectionKeywords = /ignore\s+previous|disregard\s+instructions|you\s+are\s+now|act\s+as|system\s+prompt/gi
                if (injectionKeywords.test(decoded)) {
                    throw new InternalFlowiseError(
                        StatusCodes.BAD_REQUEST,
                        `File "${fileName}" contains base64-encoded prompt injection content and cannot be uploaded.`
                    )
                }
            } catch (e) {
                if (e instanceof InternalFlowiseError) throw e
                // Not valid base64, skip
            }
        }
    }

    // Check for leetspeak prompt patterns
    const leetspeakPattern = /1gn0r3|d1sr3g4rd|y0u\s+4r3|4ct\s+4s/gi
    if (leetspeakPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains leetspeak prompt injection patterns and cannot be uploaded.`
        )
    }

    // Check for shell commands / binary executable signatures
    const shellCommandPattern = /(\$\(|`[^`]*`|;\s*rm\s+-|;\s*wget\s+|;\s*curl\s+|&&\s*rm\s+|&&\s*wget\s+|&&\s*curl\s+)/gi
    if (shellCommandPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains shell command patterns and cannot be uploaded.`
        )
    }

    // Check for binary executable signatures (ELF, PE, Mach-O)
    if (buffer.length >= 4) {
        const magic = buffer.slice(0, 4)
        const elfMagic = Buffer.from([0x7f, 0x45, 0x4c, 0x46])
        const peMagic = Buffer.from([0x4d, 0x5a])
        const machOMagic1 = Buffer.from([0xfe, 0xed, 0xfa, 0xce])
        const machOMagic2 = Buffer.from([0xfe, 0xed, 0xfa, 0xcf])
        if (
            magic.slice(0, 4).equals(elfMagic) ||
            magic.slice(0, 2).equals(peMagic) ||
            magic.equals(machOMagic1) ||
            magic.equals(machOMagic2)
        ) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `File "${fileName}" appears to be a binary executable and cannot be uploaded.`
            )
        }
    }

    // Check for suspicious AI-instruction keywords
    const aiInjectionPattern = /ignore\s+previous\s+instructions|disregard\s+(all\s+)?instructions|you\s+are\s+now\s+a|act\s+as\s+(a\s+)?|forget\s+(all\s+)?previous|new\s+instructions:|system\s+prompt:/gi
    if (aiInjectionPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains suspicious AI instruction patterns and cannot be uploaded.`
        )
    }
}

// PII redaction helper
const redactPIIFromBuffer = (buffer: Buffer): Buffer => {
    let content = buffer.toString('utf8')

    // Redact email addresses
    content = content.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')

    // Redact phone numbers (various formats)
    content = content.replace(/(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})/g, '[REDACTED_PHONE]')

    // Redact SSNs (US format: XXX-XX-XXXX)
    content = content.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')

    // Redact credit card numbers
    content = content.replace(/\b(?:\d{4}[\s\-]?){3}\d{4}\b/g, '[REDACTED_CC]')

    // Redact Singapore NRIC/FIN numbers (S/T/F/G followed by 7 digits and a letter)
    content = content.replace(/\b[STFG]\d{7}[A-Z]\b/gi, '[REDACTED_NRIC]')

    // Redact Singapore CPF account numbers (8 digits)
    content = content.replace(/\bCPF[:\s#]*\d{8}\b/gi, '[REDACTED_CPF]')

    // Redact SingPass identifiers
    content = content.replace(/\bSingPass[:\s#]*[A-Za-z0-9@._\-]+/gi, '[REDACTED_SINGPASS]')

    return Buffer.from(content, 'utf8')
}

// Singapore-specific PII scanner
const scanFileForSingaporePII = (buffer: Buffer, fileName: string): void => {
    const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1024 * 1024))

    // Check for NRIC/FIN numbers
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/gi
    if (nricPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains Singapore NRIC/FIN numbers (PII) and cannot be uploaded.`
        )
    }

    // Check for SingPass identifiers
    const singpassPattern = /\bSingPass[:\s#]*[A-Za-z0-9@._\-]+/gi
    if (singpassPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains SingPass identifiers (PII) and cannot be uploaded.`
        )
    }

    // Check for CPF account numbers
    const cpfPattern = /\bCPF[:\s#]*\d{8}\b/gi
    if (cpfPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains CPF account numbers (PII) and cannot be uploaded.`
        )
    }

    // Check for Singapore phone numbers (+65 XXXX XXXX)
    const sgPhonePattern = /(\+65|65)[\s\-]?\d{4}[\s\-]?\d{4}/g
    if (sgPhonePattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains Singapore phone numbers (PII) and cannot be uploaded.`
        )
    }

    // Check for Singapore postal codes (6 digits)
    const sgPostalPattern = /\bS\(\d{6}\)|\bSingapore\s+\d{6}\b/gi
    if (sgPostalPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `File "${fileName}" contains Singapore postal codes (PII) and cannot be uploaded.`
        )
    }
}

const getAssistantVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.getAssistantVectorStore - id not provided!`
            )
        }
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.getAssistantVectorStore - credential not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: openaiAssistantsVectorStoreController.getAssistantVectorStore - workspace not found!`
            )
        }
        const apiResponse = await openAIAssistantVectorStoreService.getAssistantVectorStore(
            req.query.credential as string,
            req.params.id,
            workspaceId
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const listAssistantVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.listAssistantVectorStore - credential not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: openaiAssistantsVectorStoreController.listAssistantVectorStore - workspace not found!`
            )
        }
        const apiResponse = await openAIAssistantVectorStoreService.listAssistantVectorStore(req.query.credential as string, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const createAssistantVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.createAssistantVectorStore - body not provided!`
            )
        }
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.createAssistantVectorStore - credential not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: openaiAssistantsVectorStoreController.createAssistantVectorStore - workspace not found!`
            )
        }
        const sanitizedBody = sanitizeVectorStoreBody(req.body)
        const apiResponse = await openAIAssistantVectorStoreService.createAssistantVectorStore(
            req.query.credential as string,
            sanitizedBody,
            workspaceId
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const updateAssistantVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.updateAssistantVectorStore - id not provided!`
            )
        }
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.updateAssistantVectorStore - credential not provided!`
            )
        }
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.updateAssistantVectorStore - body not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: openaiAssistantsVectorStoreController.updateAssistantVectorStore - workspace not found!`
            )
        }
        const sanitizedBody = sanitizeVectorStoreBody(req.body)
        const apiResponse = await openAIAssistantVectorStoreService.updateAssistantVectorStore(
            req.query.credential as string,
            req.params.id,
            sanitizedBody,
            workspaceId
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteAssistantVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.deleteAssistantVectorStore - id not provided!`
            )
        }
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.updateAssistantVectorStore - credential not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: openaiAssistantsVectorStoreController.deleteAssistantVectorStore - workspace not found!`
            )
        }
        const apiResponse = await openAIAssistantVectorStoreService.deleteAssistantVectorStore(
            req.query.credential as string,
            req.params.id as string,
            workspaceId
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const uploadFilesToAssistantVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.uploadFilesToAssistantVectorStore - body not provided!`
            )
        }
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.uploadFilesToAssistantVectorStore - id not provided!`
            )
        }
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.uploadFilesToAssistantVectorStore - credential not provided!`
            )
        }
        const files = req.files ?? []
        const uploadFiles: { filePath: string; fileName: string }[] = []

        if (Array.isArray(files)) {
            for (const file of files) {
                // Address file name with special characters: https://github.com/expressjs/multer/issues/1104
                file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf8')

                // Validate file extension, MIME type, and content to prevent security vulnerabilities
                validateFileMimeTypeAndExtensionMatch(file.originalname, file.mimetype)

                // Read file buffer for scanning
                const filePath = file.path ?? file.key
                let fileBuffer: Buffer
                try {
                    fileBuffer = fs.readFileSync(filePath)
                } catch (readErr) {
                    // If we can't read the file buffer (e.g. cloud storage), skip buffer-based checks
                    fileBuffer = file.buffer ?? Buffer.alloc(0)
                }

                // Scan for malicious content (prompt injection, shell commands, etc.)
                scanFileForMaliciousContent(fileBuffer, file.originalname)

                // Scan for Singapore-specific PII
                scanFileForSingaporePII(fileBuffer, file.originalname)

                // Redact PII from file content and write back
                const redactedBuffer = redactPIIFromBuffer(fileBuffer)
                try {
                    fs.writeFileSync(filePath, redactedBuffer)
                } catch (writeErr) {
                    // If we can't write back (e.g. cloud storage), continue with original
                }

                uploadFiles.push({
                    filePath: filePath,
                    fileName: file.originalname
                })
            }
        }

        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: openaiAssistantsVectorStoreController.uploadFilesToAssistantVectorStore - workspace not found!`
            )
        }
        const apiResponse = await openAIAssistantVectorStoreService.uploadFilesToAssistantVectorStore(
            req.query.credential as string,
            req.params.id as string,
            uploadFiles,
            workspaceId
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteFilesFromAssistantVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.deleteFilesFromAssistantVectorStore - body not provided!`
            )
        }
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.deleteFilesFromAssistantVectorStore - id not provided!`
            )
        }
        if (typeof req.query === 'undefined' || !req.query.credential) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: openaiAssistantsVectorStoreController.deleteFilesFromAssistantVectorStore - credential not provided!`
            )
        }

        // Validate that file_ids is a non-empty array of strings
        const fileIds = req.body.file_ids
        if (!Array.isArray(fileIds) || fileIds.length === 0 || !fileIds.every((id: any) => typeof id === 'string')) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: openaiAssistantsVectorStoreController.deleteFilesFromAssistantVectorStore - file_ids must be a non-empty array of strings!`
            )
        }

        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: openaiAssistantsVectorStoreController.deleteFilesFromAssistantVectorStore - workspace not found!`
            )
        }
        const apiResponse = await openAIAssistantVectorStoreService.deleteFilesFromAssistantVectorStore(
            req.query.credential as string,
            req.params.id as string,
            fileIds,
            workspaceId
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    getAssistantVectorStore,
    listAssistantVectorStore,
    createAssistantVectorStore,
    updateAssistantVectorStore,
    deleteAssistantVectorStore,
    uploadFilesToAssistantVectorStore,
    deleteFilesFromAssistantVectorStore
}
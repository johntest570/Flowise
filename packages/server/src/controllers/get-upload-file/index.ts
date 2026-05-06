import { Request, Response, NextFunction } from 'express'
import fs from 'fs'
import path from 'path'
import contentDisposition from 'content-disposition'
import { isUnsafeFilePath, isValidUUID, streamStorageFile } from 'flowise-components'
import { StatusCodes } from 'http-status-codes'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { getRunningExpressApp } from '../../utils/getRunningExpressApp'
import { ChatFlow } from '../../database/entities/ChatFlow'
import { Workspace } from '../../enterprise/database/entities/workspace.entity'

// Binary file extensions that should be streamed as-is without text processing
const BINARY_EXTENSIONS = new Set([
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.tiff',
    '.mp3', '.mp4', '.wav', '.ogg', '.avi', '.mov', '.mkv', '.flv',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.exe', '.dll', '.so', '.bin', '.dat'
])

function isBinaryFile(fileName: string): boolean {
    const ext = path.extname(fileName).toLowerCase()
    return BINARY_EXTENSIONS.has(ext)
}

// --- Malicious content / prompt injection detection ---
function containsMaliciousContent(content: string): boolean {
    // Check for binary executable signatures (ELF, PE, etc.)
    if (/^\x7fELF/.test(content) || /^MZ/.test(content)) return true

    // Check for shell commands
    if (/(?:^|\s)(bash|sh|cmd|powershell|exec|eval|system|passthru|popen)\s*[\(\[]/im.test(content)) return true

    // Check for base64-encoded prompt injections (decode and check)
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g
    const base64Matches = content.match(base64Pattern) || []
    for (const match of base64Matches) {
        try {
            const decoded = Buffer.from(match, 'base64').toString('utf8')
            if (containsPromptInjectionKeywords(decoded)) return true
        } catch {
            // ignore decode errors
        }
    }

    // Check for leetspeak prompt patterns
    const leetspeakNormalized = content
        .replace(/4/g, 'a').replace(/3/g, 'e').replace(/1/g, 'i')
        .replace(/0/g, 'o').replace(/5/g, 's').replace(/7/g, 't')
        .replace(/@/g, 'a').replace(/\$/g, 's')
    if (containsPromptInjectionKeywords(leetspeakNormalized)) return true

    // Check for zero-width / invisible characters used for hidden prompts
    if (/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/.test(content)) return true

    // Check for common prompt injection keywords directly
    if (containsPromptInjectionKeywords(content)) return true

    return false
}

function containsPromptInjectionKeywords(text: string): boolean {
    const lower = text.toLowerCase()
    const patterns = [
        /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
        /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
        /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
        /you\s+are\s+now\s+(a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted)/i,
        /act\s+as\s+(a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted|jailbreak)/i,
        /pretend\s+(you\s+are|to\s+be)\s+/i,
        /new\s+instructions?:/i,
        /system\s*prompt:/i,
        /\[system\]/i,
        /override\s+(safety|instructions?|guidelines?|rules?)/i,
        /jailbreak/i,
        /prompt\s+injection/i,
        /do\s+anything\s+now/i,
        /dan\s+mode/i,
        /developer\s+mode/i,
        /sudo\s+mode/i,
        /unrestricted\s+mode/i,
        /<\s*script[^>]*>/i,
        /eval\s*\(/i,
        /exec\s*\(/i
    ]
    return patterns.some((p) => p.test(text)) || lower.includes('ignore previous instructions')
}

// --- PII redaction (general) ---
function redactPII(content: string): string {
    // SSN (US): 123-45-6789 or 123 45 6789
    content = content.replace(/\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/g, '[REDACTED-SSN]')

    // Email addresses
    content = content.replace(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, '[REDACTED-EMAIL]')

    // Credit card numbers (Visa, MC, Amex, etc.) - 13-19 digits with optional separators
    content = content.replace(/\b(?:\d[ \-]?){13,19}\b/g, (match) => {
        const digits = match.replace(/[\s\-]/g, '')
        if (digits.length >= 13 && digits.length <= 19 && /^\d+$/.test(digits)) {
            return '[REDACTED-CC]'
        }
        return match
    })

    // Passport numbers (generic: letter(s) followed by digits)
    content = content.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, '[REDACTED-PASSPORT]')

    // Phone numbers (various formats)
    content = content.replace(/\b(?:\+?\d{1,3}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b/g, '[REDACTED-PHONE]')

    // Dates of birth (common formats: MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD)
    content = content.replace(/\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b/g, '[REDACTED-DOB]')

    return content
}

// --- Singapore PII detection ---
function containsSingaporePII(content: string): boolean {
    // NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    if (/\b[STFG]\d{7}[A-Z]\b/i.test(content)) return true

    // SingPass identifiers (common patterns)
    if (/singpass/i.test(content)) return true

    // Full name combined with NRIC/FIN or identifier patterns
    if (/\b(?:name|full\s+name)\s*[:=]\s*[A-Za-z\s]+.*\b[STFG]\d{7}[A-Z]\b/i.test(content)) return true
    if (/\b[STFG]\d{7}[A-Z]\b.*\b(?:name|full\s+name)\s*[:=]\s*[A-Za-z\s]+/i.test(content)) return true

    // Dates of birth in common formats (DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD)
    if (/\b(?:dob|date\s+of\s+birth|birth\s+date)\s*[:=]\s*\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b/i.test(content)) return true

    return false
}

async function streamToBuffer(stream: fs.ReadStream): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = []
        stream.on('data', (chunk: Buffer | string) => {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
        })
        stream.on('end', () => resolve(Buffer.concat(chunks)))
        stream.on('error', reject)
    })
}

const streamUploadedFile = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.query.chatflowId || !req.query.chatId || !req.query.fileName) {
            return res.status(500).send(`Invalid file path`)
        }
        const chatflowId = req.query.chatflowId as string
        const chatId = req.query.chatId as string
        const fileName = req.query.fileName as string
        const download = req.query.download === 'true' // Check if download parameter is set

        // Validate input formats to prevent path traversal attacks
        if (!chatflowId || !isValidUUID(chatflowId)) {
            return res.status(400).send(`Invalid chatflowId format`)
        }

        if (!chatId) {
            return res.status(400).send(`chatId is missing`)
        }

        // Check for path traversal and unsafe characters in fileName
        if (isUnsafeFilePath(fileName)) {
            return res.status(400).send(`Invalid path characters detected in filename`)
        }

        const appServer = getRunningExpressApp()

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

        // Set Content-Disposition header - force attachment for download
        if (download) {
            res.setHeader('Content-Disposition', contentDisposition(fileName, { type: 'attachment' }))
        } else {
            res.setHeader('Content-Disposition', contentDisposition(fileName))
        }
        const fileStream = await streamStorageFile(chatflowId, chatId, fileName, orgId)

        if (!fileStream) throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, `Error: streamStorageFile`)

        const binary = isBinaryFile(fileName)

        if (fileStream instanceof fs.ReadStream && fileStream?.pipe) {
            if (binary) {
                // For binary files: buffer and check for malicious content via byte patterns only, then stream as-is
                const buffer = await streamToBuffer(fileStream)
                const rawContent = buffer.toString('binary')

                // Check for malicious content (binary signatures)
                if (containsMaliciousContent(rawContent)) {
                    return res.status(400).send(`File contains potentially malicious content`)
                }

                // Singapore PII check - skip for binary
                // PII redaction - skip for binary

                res.send(buffer)
            } else {
                // Text file: buffer, inspect, redact, then send
                const buffer = await streamToBuffer(fileStream)
                let textContent = buffer.toString('utf8')

                // Check for malicious/prompt injection content
                if (containsMaliciousContent(textContent)) {
                    return res.status(400).send(`File contains potentially malicious content`)
                }

                // Check for Singapore PII - reject with 403
                if (containsSingaporePII(textContent)) {
                    return res.status(403).send(`File contains Singapore PII and cannot be served`)
                }

                // Redact general PII before sending
                textContent = redactPII(textContent)

                res.send(textContent)
            }
        } else {
            if (binary || typeof fileStream !== 'string' && !Buffer.isBuffer(fileStream)) {
                // Non-ReadStream binary-like content
                res.send(fileStream)
            } else {
                let textContent: string
                if (Buffer.isBuffer(fileStream)) {
                    textContent = fileStream.toString('utf8')
                } else {
                    textContent = String(fileStream)
                }

                // Check for malicious/prompt injection content
                if (containsMaliciousContent(textContent)) {
                    return res.status(400).send(`File contains potentially malicious content`)
                }

                // Check for Singapore PII - reject with 403
                if (containsSingaporePII(textContent)) {
                    return res.status(403).send(`File contains Singapore PII and cannot be served`)
                }

                // Redact general PII before sending
                textContent = redactPII(textContent)

                res.send(textContent)
            }
        }
    } catch (error) {
        next(error)
    }
}

export default {
    streamUploadedFile
}
import { Request, Response, NextFunction } from 'express'
import attachmentsService from '../../services/attachments'

// Helper: redact PII from text content
const redactPII = (text: string): string => {
    // Redact email addresses
    text = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
    // Redact phone numbers (general)
    text = text.replace(/(\+?\d[\d\s\-().]{7,}\d)/g, '[REDACTED_PHONE]')
    // Redact SSNs (US format)
    text = text.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    // Redact credit card numbers
    text = text.replace(/\b(?:\d[ -]?){13,16}\b/g, '[REDACTED_CC]')
    // Redact Singapore NRIC/FIN numbers (e.g. S1234567A, T1234567B, F1234567C, G1234567D)
    text = text.replace(/\b[STFG]\d{7}[A-Z]\b/gi, '[REDACTED_NRIC]')
    // Redact SingPass identifiers
    text = text.replace(/\bSingPass\s*[:\-]?\s*\S+/gi, '[REDACTED_SINGPASS]')
    return text
}

// Helper: detect malicious prompt injection patterns
const detectMaliciousContent = (text: string): boolean => {
    // Detect hidden/invisible prompts (zero-width characters)
    if (/[\u200B-\u200D\uFEFF\u00AD]/.test(text)) return true
    // Detect base64-encoded prompts (long base64 strings)
    if (/(?:[A-Za-z0-9+/]{40,}={0,2})/.test(text)) return true
    // Detect leetspeak patterns
    if (/\b(?:1gnor3|1nstruct|sy5tem|pr0mpt|4dmin|h4ck)\b/i.test(text)) return true
    // Detect suspicious AI instruction keywords
    if (/\b(ignore previous instructions|disregard|system prompt|you are now|act as|jailbreak|bypass|override instructions|forget your instructions|new instructions|pretend you|roleplay as)\b/i.test(text)) return true
    // Detect binary executables or shell commands
    if (/(\x7fELF|MZ\x90|#!/.test(text)) return true
    if (/\b(bash|sh|cmd|powershell|exec|eval|system|passthru|shell_exec)\s*[\(\[]/i.test(text)) return true
    return false
}

// Helper: detect Singapore-specific PII
const detectSingaporePII = (text: string): boolean => {
    // Singapore NRIC/FIN numbers
    if (/\b[STFG]\d{7}[A-Z]\b/i.test(text)) return true
    // SingPass identifiers
    if (/\bSingPass\s*[:\-]?\s*\S+/i.test(text)) return true
    // Singapore phone numbers (+65 XXXX XXXX or 8/9 XXXXXXX)
    if (/(\+65[\s\-]?\d{4}[\s\-]?\d{4}|\b[89]\d{7}\b)/.test(text)) return true
    return false
}

const createAttachment = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Extract and validate known fields from request
        const chatflowId = typeof req.params?.chatflowId === 'string' ? req.params.chatflowId.trim() : undefined
        const chatId = typeof req.params?.chatId === 'string' ? req.params.chatId.trim() : undefined

        if (!chatflowId || !chatId) {
            return res.status(400).json({ error: 'Missing required parameters: chatflowId and chatId' })
        }

        // Validate and sanitize uploaded files
        const files: Express.Multer.File[] = []
        if (req.files && Array.isArray(req.files)) {
            for (const file of req.files as Express.Multer.File[]) {
                if (!file.originalname || !file.mimetype || !file.buffer) {
                    return res.status(400).json({ error: 'Invalid file upload: missing required file metadata' })
                }

                // Inspect text-based file contents
                const isTextBased = file.mimetype.startsWith('text/') ||
                    file.mimetype === 'application/json' ||
                    file.mimetype === 'application/xml' ||
                    file.mimetype === 'application/javascript'

                if (isTextBased) {
                    const textContent = file.buffer.toString('utf8')

                    // Check for malicious prompt injection
                    if (detectMaliciousContent(textContent)) {
                        return res.status(400).json({ error: 'Uploaded file contains potentially malicious content' })
                    }

                    // Check for Singapore PII
                    if (detectSingaporePII(textContent)) {
                        return res.status(400).json({ error: 'Uploaded file contains Singapore PII which is not allowed' })
                    }

                    // Redact general PII from file content
                    const redactedContent = redactPII(textContent)
                    const redactedBuffer = Buffer.from(redactedContent, 'utf8')
                    files.push({
                        ...file,
                        buffer: redactedBuffer,
                        size: redactedBuffer.length
                    })
                } else {
                    // For binary files, check for executable signatures
                    const bufferHex = file.buffer.slice(0, 4).toString('hex')
                    // ELF magic: 7f454c46, MZ magic: 4d5a
                    if (bufferHex.startsWith('7f454c46') || bufferHex.startsWith('4d5a')) {
                        return res.status(400).json({ error: 'Uploaded file appears to be a binary executable which is not allowed' })
                    }
                    files.push(file)
                }
            }
        } else if (req.file) {
            const file = req.file
            if (!file.originalname || !file.mimetype || !file.buffer) {
                return res.status(400).json({ error: 'Invalid file upload: missing required file metadata' })
            }

            const isTextBased = file.mimetype.startsWith('text/') ||
                file.mimetype === 'application/json' ||
                file.mimetype === 'application/xml' ||
                file.mimetype === 'application/javascript'

            if (isTextBased) {
                const textContent = file.buffer.toString('utf8')

                if (detectMaliciousContent(textContent)) {
                    return res.status(400).json({ error: 'Uploaded file contains potentially malicious content' })
                }

                if (detectSingaporePII(textContent)) {
                    return res.status(400).json({ error: 'Uploaded file contains Singapore PII which is not allowed' })
                }

                const redactedContent = redactPII(textContent)
                const redactedBuffer = Buffer.from(redactedContent, 'utf8')
                req.file = {
                    ...file,
                    buffer: redactedBuffer,
                    size: redactedBuffer.length
                }
            } else {
                const bufferHex = file.buffer.slice(0, 4).toString('hex')
                if (bufferHex.startsWith('7f454c46') || bufferHex.startsWith('4d5a')) {
                    return res.status(400).json({ error: 'Uploaded file appears to be a binary executable which is not allowed' })
                }
            }
        }

        // Build sanitized request context to pass to service
        const sanitizedReq = Object.assign(Object.create(Object.getPrototypeOf(req)), req, {
            params: { chatflowId, chatId },
            files: files.length > 0 ? files : req.files,
        })

        const apiResponse = await attachmentsService.createAttachment(sanitizedReq)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    createAttachment
}
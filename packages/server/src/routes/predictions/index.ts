import express from 'express'
import { Request, Response, NextFunction } from 'express'
import predictionsController from '../../controllers/predictions'
import { getMulterStorage } from '../../utils'

const router = express.Router()

const ALLOWED_MIME_TYPES = [
    'text/plain',
    'text/csv',
    'text/html',
    'text/markdown',
    'application/pdf',
    'application/json',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'audio/mpeg',
    'audio/wav',
    'audio/ogg',
    'video/mp4',
    'video/webm'
]

const MAX_FILE_SIZE = 50 * 1024 * 1024 // 50MB

const ALLOWED_BODY_KEYS = [
    'question',
    'history',
    'overrideConfig',
    'socketIOClientId',
    'chatId',
    'memoryId',
    'sessionId',
    'action',
    'uploads',
    'leadEmail',
    'followUpPrompts'
]

// PII patterns
const PII_PATTERNS = [
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // email
    /\b(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})\b/g, // phone
    /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, // SSN
    /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g // credit card
]

// Singapore PII patterns
const SG_PII_PATTERNS = [
    /\b[STFGM]\d{7}[A-Z]\b/gi, // NRIC/FIN
    /\bSingPass\b/gi, // SingPass identifier
    /\b[STFGM]\d{7}[A-Z]\b/gi // FIN numbers
]

// Dangerous prompt patterns
const DANGEROUS_PROMPT_PATTERNS = [
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/gi,
    /system\s*prompt/gi,
    /\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0b|\x0c|\x0e|\x0f/g, // control chars
    /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g, // invisible unicode
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/m, // base64 blocks
    /(\b[i1]gn[o0]r[e3]\b|\b[s5]y[s5]t[e3]m\b)/gi, // leetspeak
    /\b(exec|eval|system|passthru|shell_exec|popen|proc_open)\s*\(/gi, // shell commands
    /^(#!\/|MZ|ELF|\x7fELF)/m // binary executables / shebangs
]

function sanitizeString(str: string): string {
    return str
        .replace(/<[^>]*>/g, '') // strip HTML tags
        .replace(/[<>"'`]/g, '') // strip dangerous chars
        .trim()
}

function redactPII(content: string): string {
    let redacted = content
    PII_PATTERNS.forEach((pattern) => {
        redacted = redacted.replace(pattern, '[REDACTED]')
    })
    return redacted
}

function checkForMaliciousContent(buffer: Buffer): boolean {
    const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1024 * 1024))
    for (const pattern of DANGEROUS_PROMPT_PATTERNS) {
        pattern.lastIndex = 0
        if (pattern.test(content)) {
            return true
        }
    }
    return false
}

function checkForSingaporePII(content: string): boolean {
    for (const pattern of SG_PII_PATTERNS) {
        pattern.lastIndex = 0
        if (pattern.test(content)) {
            return true
        }
    }
    return false
}

// Middleware: validate and sanitize inputs
const validateAndSanitizeMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    // 1. Sanitize route param `id`
    if (req.params && req.params.id !== undefined) {
        if (!/^[a-zA-Z0-9_-]*$/.test(req.params.id)) {
            res.status(400).json({ error: 'Invalid id parameter' })
            return
        }
    }

    // 2. Strip unexpected/dangerous keys from req.body
    if (req.body && typeof req.body === 'object') {
        const sanitizedBody: Record<string, any> = {}
        for (const key of ALLOWED_BODY_KEYS) {
            if (Object.prototype.hasOwnProperty.call(req.body, key)) {
                const val = req.body[key]
                if (typeof val === 'string') {
                    sanitizedBody[key] = sanitizeString(val)
                } else {
                    sanitizedBody[key] = val
                }
            }
        }
        req.body = sanitizedBody
    }

    // 3. Validate uploaded files MIME types and sizes
    if (req.files && Array.isArray(req.files)) {
        for (const file of req.files as Express.Multer.File[]) {
            if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
                res.status(400).json({ error: `File type not allowed: ${file.mimetype}` })
                return
            }
            if (file.size > MAX_FILE_SIZE) {
                res.status(400).json({ error: `File too large: ${file.originalname}` })
                return
            }
        }
    }

    next()
}

// Middleware: scan for malicious content in uploaded files
const maliciousContentScanMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    if (req.files && Array.isArray(req.files)) {
        for (const file of req.files as Express.Multer.File[]) {
            if (file.buffer && checkForMaliciousContent(file.buffer)) {
                res.status(400).json({ error: `File contains potentially malicious content: ${file.originalname}` })
                return
            }
        }
    }
    next()
}

// Middleware: redact PII from uploaded file buffers
const piiRedactionMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    if (req.files && Array.isArray(req.files)) {
        for (const file of req.files as Express.Multer.File[]) {
            if (file.buffer) {
                try {
                    const content = file.buffer.toString('utf8')
                    const redacted = redactPII(content)
                    file.buffer = Buffer.from(redacted, 'utf8')
                } catch {
                    // If buffer can't be decoded as utf8, skip redaction for binary files
                }
            }
        }
    }
    next()
}

// Middleware: Singapore PII detection
const singaporePIIMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    if (req.files && Array.isArray(req.files)) {
        for (const file of req.files as Express.Multer.File[]) {
            if (file.buffer) {
                try {
                    const content = file.buffer.toString('utf8')
                    if (checkForSingaporePII(content)) {
                        res.status(400).json({ error: `File contains Singapore PII data: ${file.originalname}` })
                        return
                    }
                } catch {
                    // If buffer can't be decoded as utf8, skip check for binary files
                }
            }
        }
    }
    next()
}

// NOTE: extractChatflowId function in XSS.ts extracts the chatflow ID from the prediction URL.
// It assumes the URL format is /prediction/{chatflowId}. Make sure to update the function if the URL format changes.
// CREATE
router.post(
    ['/', '/:id'],
    getMulterStorage().array('files'),
    maliciousContentScanMiddleware,
    validateAndSanitizeMiddleware,
    piiRedactionMiddleware,
    singaporePIIMiddleware,
    predictionsController.getRateLimiterMiddleware,
    predictionsController.createPrediction
)

export default router
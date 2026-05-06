import express, { Request, Response, NextFunction } from 'express'
import openaiAssistantsVectorStoreController from '../../controllers/openai-assistants-vector-store'
import { getMulterStorage } from '../../utils'
import { checkPermission, checkAnyPermission } from '../../enterprise/rbac/PermissionCheck'

const router = express.Router()

// Allowed MIME types for uploaded files
const ALLOWED_MIME_TYPES = [
    'text/plain',
    'text/csv',
    'text/html',
    'text/xml',
    'application/pdf',
    'application/json',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp'
]

// Maximum file size: 512 MB
const MAX_FILE_SIZE = 512 * 1024 * 1024

// Middleware: validate MIME type and file size
const validateFilesMimeAndSize = (req: Request, res: Response, next: NextFunction): void => {
    const files = req.files as Express.Multer.File[]
    if (!files || files.length === 0) {
        next()
        return
    }
    for (const file of files) {
        if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
            res.status(400).json({ error: `File type not allowed: ${file.mimetype}` })
            return
        }
        if (file.size > MAX_FILE_SIZE) {
            res.status(400).json({ error: `File too large: ${file.originalname}` })
            return
        }
    }
    next()
}

// Middleware: detect malicious prompt injection content in uploaded files
const detectMaliciousContent = (req: Request, res: Response, next: NextFunction): void => {
    const files = req.files as Express.Multer.File[]
    if (!files || files.length === 0) {
        next()
        return
    }

    // Patterns for hidden prompts, AI-instruction patterns, suspicious content
    const suspiciousPatterns = [
        // Invisible Unicode characters
        /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/,
        // AI instruction patterns
        /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
        /you\s+are\s+now\s+(a\s+)?(different|new|another|an?\s+)?(\w+\s+)?(ai|assistant|bot|model|gpt|llm)/i,
        /system\s*:\s*(you|your|ignore|forget|disregard)/i,
        /\[system\]/i,
        /\[assistant\]/i,
        /\[user\]/i,
        /<\s*system\s*>/i,
        /###\s*(instruction|system|prompt|context)/i,
        /act\s+as\s+(if\s+you\s+are\s+|a\s+)?(\w+\s+)?(ai|assistant|bot|model|gpt|llm|jailbreak)/i,
        /jailbreak/i,
        /prompt\s+injection/i,
        /forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|training|context|rules)/i,
        /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|training|context|rules)/i,
        // Base64-encoded prompt patterns (decode and check)
        // Shell command patterns
        /(\$\(|\`)[^)]*(\)|\`)/,
        /\b(eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\(/i,
        /\b(bash|sh|cmd|powershell|python|perl|ruby|node)\s+-[ce]/i,
        // Binary/null bytes
        /\x00/
    ]

    // Leetspeak patterns for common injection phrases
    const leetspeakPatterns = [
        /1gn0r3|1gnor3|igno[r3][e3]/i,
        /[s5]y[s5][t7][e3]m/i,
        /[a4][s5][s5][i1][s5][t7][a4]n[t7]/i,
        /[j][a4][i1][l1]br[e3][a4]k/i
    ]

    for (const file of files) {
        if (!file.buffer) continue
        const content = file.buffer.toString('utf8')

        // Check for null bytes / binary content
        if (file.buffer.includes(0x00)) {
            res.status(400).json({ error: `File contains binary or null-byte content: ${file.originalname}` })
            return
        }

        // Check suspicious patterns
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(content)) {
                res.status(400).json({ error: `File contains potentially malicious content: ${file.originalname}` })
                return
            }
        }

        // Check leetspeak patterns
        for (const pattern of leetspeakPatterns) {
            if (pattern.test(content)) {
                res.status(400).json({ error: `File contains potentially malicious content: ${file.originalname}` })
                return
            }
        }

        // Check for base64-encoded suspicious content
        const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g
        const base64Matches = content.match(base64Pattern)
        if (base64Matches) {
            for (const match of base64Matches) {
                try {
                    const decoded = Buffer.from(match, 'base64').toString('utf8')
                    for (const pattern of suspiciousPatterns) {
                        if (pattern.test(decoded)) {
                            res.status(400).json({ error: `File contains base64-encoded malicious content: ${file.originalname}` })
                            return
                        }
                    }
                } catch {
                    // Not valid base64, skip
                }
            }
        }
    }

    next()
}

// Middleware: redact PII from uploaded file buffers
const redactPII = (req: Request, res: Response, next: NextFunction): void => {
    const files = req.files as Express.Multer.File[]
    if (!files || files.length === 0) {
        next()
        return
    }

    const piiPatterns: Array<{ pattern: RegExp; replacement: string }> = [
        // Email addresses
        { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: '[REDACTED_EMAIL]' },
        // US phone numbers
        { pattern: /(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, replacement: '[REDACTED_PHONE]' },
        // SSNs
        { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
        // Credit card numbers
        { pattern: /\b(?:\d[ -]?){13,16}\b/g, replacement: '[REDACTED_CC]' }
    ]

    for (const file of files) {
        if (!file.buffer) continue
        let content = file.buffer.toString('utf8')
        for (const { pattern, replacement } of piiPatterns) {
            content = content.replace(pattern, replacement)
        }
        file.buffer = Buffer.from(content, 'utf8')
    }

    next()
}

// Middleware: detect Singapore-specific PII patterns
const detectSingaporePII = (req: Request, res: Response, next: NextFunction): void => {
    const files = req.files as Express.Multer.File[]
    if (!files || files.length === 0) {
        next()
        return
    }

    const singaporePIIPatterns = [
        // NRIC/FIN: S/T/F/G followed by 7 digits and a letter
        /\b[STFG]\d{7}[A-Z]\b/i,
        // SingPass identifier pattern (SingPass ID typically follows NRIC format but also includes login IDs)
        /singpass\s*id\s*[:\-]?\s*[A-Z0-9]+/i,
        // CPF account number: 8-digit number (common format)
        /\bcpf\s*(account|no|number|#)?\s*[:\-]?\s*\d{8}\b/i,
        // Singapore phone numbers: +65 followed by 8 digits
        /\+65[-.\s]?\d{4}[-.\s]?\d{4}/
    ]

    for (const file of files) {
        if (!file.buffer) continue
        const content = file.buffer.toString('utf8')
        for (const pattern of singaporePIIPatterns) {
            if (pattern.test(content)) {
                // Remove files from memory
                ;(req.files as Express.Multer.File[]).forEach((f) => {
                    if (f.buffer) {
                        f.buffer = Buffer.alloc(0)
                    }
                })
                res.status(400).json({ error: `File contains Singapore PII data and cannot be processed: ${file.originalname}` })
                return
            }
        }
    }

    next()
}

// CREATE
router.post('/', checkPermission('assistants:create'), openaiAssistantsVectorStoreController.createAssistantVectorStore)

// READ
router.get('/:id', checkPermission('assistants:view'), openaiAssistantsVectorStoreController.getAssistantVectorStore)

// LIST
router.get('/', checkPermission('assistants:view'), openaiAssistantsVectorStoreController.listAssistantVectorStore)

// UPDATE
router.put(
    ['/', '/:id'],
    checkAnyPermission('assistants:create,assistants:update'),
    openaiAssistantsVectorStoreController.updateAssistantVectorStore
)

// DELETE
router.delete(['/', '/:id'], checkPermission('assistants:delete'), openaiAssistantsVectorStoreController.deleteAssistantVectorStore)

// UPLOAD FILES — permission check must precede multer to reject unauthorized requests before file parsing
router.post(
    '/:id',
    checkAnyPermission('assistants:create,assistants:update'),
    getMulterStorage().array('files'),
    validateFilesMimeAndSize,
    detectMaliciousContent,
    detectSingaporePII,
    redactPII,
    openaiAssistantsVectorStoreController.uploadFilesToAssistantVectorStore
)

// DELETE FILES
router.patch(['/', '/:id'], checkPermission('assistants:update'), openaiAssistantsVectorStoreController.deleteFilesFromAssistantVectorStore)

export default router
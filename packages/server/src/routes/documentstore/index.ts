import express, { Request, Response, NextFunction } from 'express'
import { checkPermission, checkAnyPermission } from '../../enterprise/rbac/PermissionCheck'
import documentStoreController from '../../controllers/documentstore'
import { getMulterStorage } from '../../utils'

const router = express.Router()

// Allowed MIME types and extensions for uploaded files
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
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation'
]

const ALLOWED_EXTENSIONS = [
    '.txt', '.csv', '.html', '.htm', '.md', '.pdf', '.json',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
]

const MAX_FILE_SIZE = 50 * 1024 * 1024 // 50MB

// Binary executable signatures (magic bytes)
const BINARY_SIGNATURES = [
    Buffer.from([0x4d, 0x5a]),             // PE/EXE
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]), // ELF
    Buffer.from([0xca, 0xfe, 0xba, 0xbe]), // Mach-O
    Buffer.from([0x50, 0x4b, 0x03, 0x04])  // ZIP (but we allow docx/xlsx which are zip-based, so check carefully)
]

const EXECUTABLE_SIGNATURES = [
    Buffer.from([0x4d, 0x5a]),             // PE/EXE
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]), // ELF
    Buffer.from([0xca, 0xfe, 0xba, 0xbe])  // Mach-O
]

// Suspicious command patterns
const SUSPICIOUS_PATTERNS = [
    /ignore\s+previous\s+instructions/i,
    /ignore\s+all\s+instructions/i,
    /system\s*:\s*you\s+are/i,
    /\[INST\]/i,
    /<<SYS>>/i,
    /<\|system\|>/i,
    /\bexec\s*\(/i,
    /\beval\s*\(/i,
    /\bos\.system\s*\(/i,
    /\bsubprocess\s*\./i,
    /\bchmod\s+[0-7]{3,4}/i,
    /\brm\s+-rf\b/i,
    /\bcurl\s+https?:\/\//i,
    /\bwget\s+https?:\/\//i,
    /\bnc\s+-[a-z]*e\b/i,
    /\/bin\/(sh|bash|zsh|dash)/i,
    /cmd\.exe/i,
    /powershell/i
]

// Leetspeak pattern for prompt injection
const LEET_PATTERNS = [
    /1gn0r3\s+pr3v10us/i,
    /sy5t3m\s+pr0mpt/i
]

// Base64 suspicious content check
function containsSuspiciousBase64(text: string): boolean {
    const base64Regex = /[A-Za-z0-9+/]{40,}={0,2}/g
    const matches = text.match(base64Regex)
    if (!matches) return false
    for (const match of matches) {
        try {
            const decoded = Buffer.from(match, 'base64').toString('utf8')
            for (const pattern of SUSPICIOUS_PATTERNS) {
                if (pattern.test(decoded)) return true
            }
        } catch {
            // ignore decode errors
        }
    }
    return false
}

// Hidden/invisible character prompt injection check
function containsHiddenPrompts(text: string): boolean {
    // Check for zero-width characters and other invisible unicode used for prompt injection
    const hiddenCharPattern = /[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]/
    return hiddenCharPattern.test(text)
}

// PII patterns (general)
const PII_PATTERNS = {
    email: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    phone: /\b(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)?\d{3}[\s.\-]?\d{4}\b/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    creditCard: /\b(?:\d[ \-]?){13,16}\b/g
}

// Singapore-specific PII patterns
const SG_PII_PATTERNS = {
    nric: /\b[STFGM]\d{7}[A-Z]\b/i,
    singpass: /\bsingpass\b/i,
    sgPhone: /\b(\+65[\s\-]?)?(6|8|9)\d{7}\b/,
    sgPostal: /\bS\d{6}\b|\b\d{6}\b/
}

function redactPII(text: string): string {
    let redacted = text
    redacted = redacted.replace(PII_PATTERNS.email, '[REDACTED_EMAIL]')
    redacted = redacted.replace(PII_PATTERNS.ssn, '[REDACTED_SSN]')
    redacted = redacted.replace(PII_PATTERNS.creditCard, '[REDACTED_CC]')
    redacted = redacted.replace(PII_PATTERNS.phone, '[REDACTED_PHONE]')
    return redacted
}

function containsSingaporePII(text: string): boolean {
    if (SG_PII_PATTERNS.nric.test(text)) return true
    if (SG_PII_PATTERNS.singpass.test(text)) return true
    if (SG_PII_PATTERNS.sgPhone.test(text)) return true
    // Singapore postal code check - only flag if clearly formatted as S followed by 6 digits
    if (/\bS\d{6}\b/.test(text)) return true
    return false
}

// Allowed body fields for upsert
const ALLOWED_BODY_FIELDS = new Set([
    'docId', 'storeId', 'loaderId', 'splitterId', 'vectorStoreId',
    'embeddingId', 'recordManagerId', 'chunkOverlap', 'chunkSize',
    'metadata', 'replaceExisting', 'filterByFileId', 'id'
])

function sanitizeString(value: string): string {
    // Strip null bytes and control characters except common whitespace
    return value.replace(/\0/g, '').replace(/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
}

function sanitizeBody(body: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {}
    for (const key of Object.keys(body)) {
        if (ALLOWED_BODY_FIELDS.has(key)) {
            const value = body[key]
            if (typeof value === 'string') {
                sanitized[key] = sanitizeString(value)
            } else if (typeof value === 'number' || typeof value === 'boolean') {
                sanitized[key] = value
            } else if (typeof value === 'object' && value !== null) {
                sanitized[key] = value
            }
        }
    }
    return sanitized
}

// Middleware 1: Validate and sanitize uploaded files and request body
function validateAndSanitizeUpsert(req: Request, res: Response, next: NextFunction): void {
    const files = req.files as Express.Multer.File[] | undefined

    if (files && files.length > 0) {
        for (const file of files) {
            // Check MIME type
            if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
                res.status(400).json({ error: `File type not allowed: ${file.mimetype}` })
                return
            }

            // Check file extension
            const ext = ('.' + file.originalname.split('.').pop()!.toLowerCase())
            if (!ALLOWED_EXTENSIONS.includes(ext)) {
                res.status(400).json({ error: `File extension not allowed: ${ext}` })
                return
            }

            // Check file size
            if (file.size > MAX_FILE_SIZE) {
                res.status(400).json({ error: `File too large: ${file.originalname}` })
                return
            }
        }
    }

    // Sanitize request body
    if (req.body && typeof req.body === 'object') {
        req.body = sanitizeBody(req.body)
    }

    next()
}

// Middleware 2: Detect malicious content in uploaded files
function detectMaliciousContent(req: Request, res: Response, next: NextFunction): void {
    const files = req.files as Express.Multer.File[] | undefined

    if (files && files.length > 0) {
        for (const file of files) {
            const buffer = file.buffer

            if (!buffer) {
                next()
                return
            }

            // Check for binary executable signatures
            for (const sig of EXECUTABLE_SIGNATURES) {
                if (buffer.length >= sig.length && buffer.slice(0, sig.length).equals(sig)) {
                    res.status(400).json({ error: 'Uploaded file contains executable content and is not allowed.' })
                    return
                }
            }

            // Convert buffer to text for pattern analysis (best-effort for text files)
            const text = buffer.toString('utf8')

            // Check for hidden/invisible prompt injection characters
            if (containsHiddenPrompts(text)) {
                res.status(400).json({ error: 'Uploaded file contains hidden or invisible characters that may indicate prompt injection.' })
                return
            }

            // Check for suspicious command/prompt injection patterns
            for (const pattern of SUSPICIOUS_PATTERNS) {
                if (pattern.test(text)) {
                    res.status(400).json({ error: 'Uploaded file contains suspicious content that is not allowed.' })
                    return
                }
            }

            // Check for leetspeak prompt injection
            for (const pattern of LEET_PATTERNS) {
                if (pattern.test(text)) {
                    res.status(400).json({ error: 'Uploaded file contains suspicious leetspeak content that is not allowed.' })
                    return
                }
            }

            // Check for base64-encoded suspicious content
            if (containsSuspiciousBase64(text)) {
                res.status(400).json({ error: 'Uploaded file contains suspicious base64-encoded content.' })
                return
            }
        }
    }

    next()
}

// Middleware 3: Redact PII from uploaded file buffers
function redactPIIFromFiles(req: Request, res: Response, next: NextFunction): void {
    const files = req.files as Express.Multer.File[] | undefined

    if (files && files.length > 0) {
        for (const file of files) {
            if (file.buffer) {
                const text = file.buffer.toString('utf8')
                const redacted = redactPII(text)
                file.buffer = Buffer.from(redacted, 'utf8')
            }
        }
    }

    next()
}

// Middleware 4: Detect Singapore-specific PII in uploaded files
function detectSingaporePII(req: Request, res: Response, next: NextFunction): void {
    const files = req.files as Express.Multer.File[] | undefined

    if (files && files.length > 0) {
        for (const file of files) {
            if (file.buffer) {
                const text = file.buffer.toString('utf8')
                if (containsSingaporePII(text)) {
                    res.status(400).json({ error: 'Uploaded file contains Singapore-specific PII and cannot be processed.' })
                    return
                }
            }
        }
    }

    next()
}

router.post(
    ['/upsert/', '/upsert/:id'],
    getMulterStorage().array('files'),
    validateAndSanitizeUpsert,
    detectMaliciousContent,
    detectSingaporePII,
    redactPIIFromFiles,
    documentStoreController.upsertDocStoreMiddleware
)

router.post(['/refresh/', '/refresh/:id'], documentStoreController.refreshDocStoreMiddleware)

/** Document Store Routes */
// Create document store
router.post('/store', checkPermission('documentStores:create'), documentStoreController.createDocumentStore)
// List all stores
router.get('/store', checkPermission('documentStores:view'), documentStoreController.getAllDocumentStores)
// Get specific store
router.get(
    '/store/:id',
    checkAnyPermission('documentStores:view,documentStores:update,documentStores:delete'),
    documentStoreController.getDocumentStoreById
)
// Update documentStore
router.put('/store/:id', checkAnyPermission('documentStores:create,documentStores:update'), documentStoreController.updateDocumentStore)
// Delete documentStore
router.delete('/store/:id', checkPermission('documentStores:delete'), documentStoreController.deleteDocumentStore)
// Get document store configs
router.get('/store-configs/:id/:loaderId', checkAnyPermission('documentStores:view'), documentStoreController.getDocStoreConfigs)

/** Component Nodes = Document Store - Loaders */
// Get all loaders
router.get('/components/loaders', checkPermission('documentStores:add-loader'), documentStoreController.getDocumentLoaders)

// delete loader from document store
router.delete(
    '/loader/:id/:loaderId',
    checkPermission('documentStores:delete-loader'),
    documentStoreController.deleteLoaderFromDocumentStore
)
// chunking preview
router.post('/loader/preview', checkPermission('documentStores:preview-process'), documentStoreController.previewFileChunks)
// saving process
router.post('/loader/save', checkPermission('documentStores:preview-process'), documentStoreController.saveProcessingLoader)
// chunking process
router.post('/loader/process/:loaderId', checkPermission('documentStores:preview-process'), documentStoreController.processLoader)

/** Document Store - Loaders - Chunks */
// delete specific file chunk from the store
router.delete(
    '/chunks/:storeId/:loaderId/:chunkId',
    checkAnyPermission('documentStores:update,documentStores:delete'),
    documentStoreController.deleteDocumentStoreFileChunk
)
// edit specific file chunk from the store
router.put(
    '/chunks/:storeId/:loaderId/:chunkId',
    checkPermission('documentStores:update'),
    documentStoreController.editDocumentStoreFileChunk
)
// Get all file chunks from the store
router.get('/chunks/:storeId/:fileId/:pageNo', checkPermission('documentStores:view'), documentStoreController.getDocumentStoreFileChunks)

// add chunks to the selected vector store
router.post('/vectorstore/insert', checkPermission('documentStores:upsert-config'), documentStoreController.insertIntoVectorStore)
// save the selected vector store
router.post('/vectorstore/save', checkPermission('documentStores:upsert-config'), documentStoreController.saveVectorStoreConfig)
// delete data from the selected vector store
router.delete('/vectorstore/:storeId', checkPermission('documentStores:upsert-config'), documentStoreController.deleteVectorStoreFromStore)
// query the vector store
router.post('/vectorstore/query', checkPermission('documentStores:view'), documentStoreController.queryVectorStore)
// Get all embedding providers
router.get('/components/embeddings', checkPermission('documentStores:upsert-config'), documentStoreController.getEmbeddingProviders)
// Get all vector store providers
router.get('/components/vectorstore', checkPermission('documentStores:upsert-config'), documentStoreController.getVectorStoreProviders)
// Get all Record Manager providers
router.get('/components/recordmanager', checkPermission('documentStores:upsert-config'), documentStoreController.getRecordManagerProviders)

// update the selected vector store from the playground
router.post('/vectorstore/update', checkPermission('documentStores:upsert-config'), documentStoreController.updateVectorStoreConfigOnly)

// generate docstore tool description
router.post('/generate-tool-desc/:id', checkPermission('documentStores:view'), documentStoreController.generateDocStoreToolDesc)

export default router
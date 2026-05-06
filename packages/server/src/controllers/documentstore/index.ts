import { NextFunction, Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import documentStoreService from '../../services/documentstore'
import { DocumentStore } from '../../database/entities/DocumentStore'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { DocumentStoreDTO } from '../../Interface'
import { getRunningExpressApp } from '../../utils/getRunningExpressApp'
import { FLOWISE_COUNTER_STATUS, FLOWISE_METRIC_COUNTERS } from '../../Interface.Metrics'
import { getPageAndLimitParams } from '../../utils/pagination'

// --- Sanitization helper ---
const sanitizeParam = (value: string): string => {
    if (typeof value !== 'string') return ''
    // Allow alphanumeric, hyphens, underscores, dots, spaces, colons, @, +, =, /
    return value.replace(/[^a-zA-Z0-9\-_.:\s@+=\/]/g, '')
}

// --- Body field sanitization helper ---
const sanitizeBodyField = (value: unknown): unknown => {
    if (typeof value === 'string') {
        return value.replace(/[<>]/g, '')
    }
    return value
}

const sanitizeBodyObject = (body: Record<string, unknown>): Record<string, unknown> => {
    const sanitized: Record<string, unknown> = {}
    for (const key of Object.keys(body)) {
        sanitized[key] = sanitizeBodyField(body[key])
    }
    return sanitized
}

// --- Dynamic code execution primitive detection ---
const DANGEROUS_CODE_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /new\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*["'`]/i,
    /\bsetInterval\s*\(\s*["'`]/i,
    /\bimportScripts\s*\(/i,
    /\brequire\s*\(\s*["'`]/i,
    /\bprocess\.binding\s*\(/i,
    /\bchild_process/i,
    /\bspawn\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bexecFile\s*\(/i,
]

const containsDangerousCode = (value: unknown): boolean => {
    if (typeof value === 'string') {
        return DANGEROUS_CODE_PATTERNS.some((pattern) => pattern.test(value))
    }
    if (typeof value === 'object' && value !== null) {
        return Object.values(value as Record<string, unknown>).some(containsDangerousCode)
    }
    return false
}

const validateLLMResponse = (apiResponse: unknown): void => {
    if (containsDangerousCode(apiResponse)) {
        throw new InternalFlowiseError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            'Error: Response contains potentially dangerous code execution primitives and has been blocked.'
        )
    }
}

// --- Malicious content scanner for uploaded file content ---
const MALICIOUS_PATTERNS = [
    // Hidden/invisible text (zero-width characters)
    /[\u200B-\u200D\uFEFF\u00AD]/,
    // Base64-encoded prompts (long base64 strings)
    /(?:[A-Za-z0-9+/]{40,}={0,2})/,
    // Leetspeak prompt injection patterns
    /\b(?:1gnor3|1gnore|d1sreg4rd|disreg4rd|overr1de)\b/i,
    // Suspicious AI instruction patterns
    /\b(?:ignore\s+(?:previous|above|all)\s+instructions?|disregard\s+(?:previous|above|all)|you\s+are\s+now|act\s+as\s+(?:a|an)|pretend\s+(?:you\s+are|to\s+be)|system\s*:\s*you|<\s*system\s*>|<\s*\/\s*system\s*>|assistant\s*:\s*|human\s*:\s*)\b/i,
    // Shell command payloads
    /(?:\/bin\/(?:sh|bash|zsh|dash)|cmd\.exe|powershell|wget\s+http|curl\s+http|nc\s+-|ncat\s+-|\|\s*bash|\|\s*sh\b)/i,
    // Binary/null bytes
    /\x00/,
]

const scanForMaliciousContent = (content: unknown): void => {
    const checkString = (str: string): boolean => {
        return MALICIOUS_PATTERNS.some((pattern) => pattern.test(str))
    }

    const scanValue = (value: unknown): boolean => {
        if (typeof value === 'string') {
            return checkString(value)
        }
        if (typeof value === 'object' && value !== null) {
            return Object.values(value as Record<string, unknown>).some(scanValue)
        }
        return false
    }

    if (scanValue(content)) {
        throw new InternalFlowiseError(
            StatusCodes.UNPROCESSABLE_ENTITY,
            'Error: Uploaded content contains potentially malicious patterns and has been rejected.'
        )
    }
}

// --- PII redaction helper ---
const PII_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[REDACTED_EMAIL]' },
    { pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, replacement: '[REDACTED_PHONE]' },
    { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
    { pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g, replacement: '[REDACTED_CC]' },
    { pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, replacement: '[REDACTED_IP]' },
]

const redactPII = (value: string): string => {
    let redacted = value
    for (const { pattern, replacement } of PII_PATTERNS) {
        redacted = redacted.replace(pattern, replacement)
    }
    return redacted
}

const redactPIIFromBody = (body: Record<string, unknown>): Record<string, unknown> => {
    const redacted: Record<string, unknown> = {}
    for (const key of Object.keys(body)) {
        const val = body[key]
        if (typeof val === 'string') {
            redacted[key] = redactPII(val)
        } else {
            redacted[key] = val
        }
    }
    return redacted
}

// --- Singapore PII detection helper ---
const SINGAPORE_PII_PATTERNS = [
    // NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    /\b[STFG]\d{7}[A-Z]\b/i,
    // Singapore phone numbers: +65 followed by 8 digits
    /\b(?:\+65[-.\s]?)?\d{4}[-.\s]?\d{4}\b/,
    // Singapore passport: E followed by 7 digits
    /\bE\d{7}\b/i,
    // Singapore postal code: 6 digits
    /\b\d{6}\b/,
    // Singapore bank account patterns (simplified)
    /\b\d{3}-\d{5}-\d{1}\b/,
]

const detectSingaporePII = (content: unknown): boolean => {
    const checkString = (str: string): boolean => {
        return SINGAPORE_PII_PATTERNS.some((pattern) => pattern.test(str))
    }

    const scanValue = (value: unknown): boolean => {
        if (typeof value === 'string') {
            return checkString(value)
        }
        if (typeof value === 'object' && value !== null) {
            return Object.values(value as Record<string, unknown>).some(scanValue)
        }
        return false
    }

    return scanValue(content)
}

const rejectIfSingaporePII = (content: unknown): void => {
    if (detectSingaporePII(content)) {
        throw new InternalFlowiseError(
            StatusCodes.UNPROCESSABLE_ENTITY,
            'Error: Uploaded content contains Singapore PII and has been rejected per data protection policy.'
        )
    }
}

const createDocumentStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - body not provided!`
            )
        }

        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - organizationId not provided!`
            )
        }

        const rawBody = req.body
        const sanitizedBody = sanitizeBodyObject(rawBody)
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - workspaceId not provided!`
            )
        }
        const docStore = DocumentStoreDTO.toEntity(sanitizedBody)
        docStore.workspaceId = workspaceId
        const apiResponse = await documentStoreService.createDocumentStore(docStore, orgId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getAllDocumentStores = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { page, limit } = getPageAndLimitParams(req)

        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.getAllDocumentStores - workspaceId not provided!`
            )
        }
        const apiResponse: any = await documentStoreService.getAllDocumentStores(workspaceId, page, limit)
        if (apiResponse?.total >= 0) {
            return res.json({
                total: apiResponse.total,
                data: DocumentStoreDTO.fromEntities(apiResponse.data)
            })
        } else {
            return res.json(DocumentStoreDTO.fromEntities(apiResponse))
        }
    } catch (error) {
        next(error)
    }
}

const deleteLoaderFromDocumentStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const storeId = sanitizeParam(req.params.id)
        const loaderId = sanitizeParam(req.params.loaderId)

        if (!storeId || !loaderId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.deleteLoaderFromDocumentStore - missing storeId or loaderId.`
            )
        }

        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - organizationId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - workspaceId not provided!`
            )
        }

        const apiResponse = await documentStoreService.deleteLoaderFromDocumentStore(
            storeId,
            loaderId,
            orgId,
            workspaceId,
            getRunningExpressApp().usageCacheManager
        )
        return res.json(DocumentStoreDTO.fromEntity(apiResponse))
    } catch (error) {
        next(error)
    }
}

const getDocumentStoreById = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.id === 'undefined' || req.params.id === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.getDocumentStoreById - id not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.getDocumentStoreById - workspaceId not provided!`
            )
        }
        const sanitizedId = sanitizeParam(req.params.id)
        const apiResponse = await documentStoreService.getDocumentStoreById(sanitizedId, workspaceId)
        if (apiResponse && apiResponse.whereUsed) {
            apiResponse.whereUsed = JSON.stringify(await documentStoreService.getUsedChatflowNames(apiResponse, workspaceId))
        }
        return res.json(DocumentStoreDTO.fromEntity(apiResponse))
    } catch (error) {
        next(error)
    }
}

const getDocumentStoreFileChunks = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.storeId === 'undefined' || req.params.storeId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.getDocumentStoreFileChunks - storeId not provided!`
            )
        }
        if (typeof req.params.fileId === 'undefined' || req.params.fileId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.getDocumentStoreFileChunks - fileId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.getDocumentStoreFileChunks - workspaceId not provided!`
            )
        }
        const appDataSource = getRunningExpressApp().AppDataSource
        const page = req.params.pageNo ? parseInt(req.params.pageNo) : 1
        const sanitizedStoreId = sanitizeParam(req.params.storeId)
        const sanitizedFileId = sanitizeParam(req.params.fileId)
        const apiResponse = await documentStoreService.getDocumentStoreFileChunks(
            appDataSource,
            sanitizedStoreId,
            sanitizedFileId,
            workspaceId,
            page
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteDocumentStoreFileChunk = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.storeId === 'undefined' || req.params.storeId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.deleteDocumentStoreFileChunk - storeId not provided!`
            )
        }
        if (typeof req.params.loaderId === 'undefined' || req.params.loaderId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.deleteDocumentStoreFileChunk - loaderId not provided!`
            )
        }
        if (typeof req.params.chunkId === 'undefined' || req.params.chunkId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.deleteDocumentStoreFileChunk - chunkId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.deleteDocumentStoreFileChunk - workspaceId not provided!`
            )
        }
        const sanitizedStoreId = sanitizeParam(req.params.storeId)
        const sanitizedLoaderId = sanitizeParam(req.params.loaderId)
        const sanitizedChunkId = sanitizeParam(req.params.chunkId)
        const apiResponse = await documentStoreService.deleteDocumentStoreFileChunk(
            sanitizedStoreId,
            sanitizedLoaderId,
            sanitizedChunkId,
            workspaceId
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const editDocumentStoreFileChunk = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.storeId === 'undefined' || req.params.storeId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.editDocumentStoreFileChunk - storeId not provided!`
            )
        }
        if (typeof req.params.loaderId === 'undefined' || req.params.loaderId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.editDocumentStoreFileChunk - loaderId not provided!`
            )
        }
        if (typeof req.params.chunkId === 'undefined' || req.params.chunkId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.editDocumentStoreFileChunk - chunkId not provided!`
            )
        }
        const body = req.body
        if (typeof body === 'undefined') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.editDocumentStoreFileChunk - body not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.editDocumentStoreFileChunk - workspaceId not provided!`
            )
        }
        const sanitizedStoreId = sanitizeParam(req.params.storeId)
        const sanitizedLoaderId = sanitizeParam(req.params.loaderId)
        const sanitizedChunkId = sanitizeParam(req.params.chunkId)
        const apiResponse = await documentStoreService.editDocumentStoreFileChunk(
            sanitizedStoreId,
            sanitizedLoaderId,
            sanitizedChunkId,
            body.pageContent,
            body.metadata,
            workspaceId
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const saveProcessingLoader = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const appServer = getRunningExpressApp()
        if (typeof req.body === 'undefined') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.saveProcessingLoader - body not provided!`
            )
        }
        const body = req.body
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.saveProcessingLoader - workspaceId not provided!`
            )
        }
        // Scan for malicious content in uploaded file body
        scanForMaliciousContent(body)
        // Reject if Singapore PII detected
        rejectIfSingaporePII(body)
        const apiResponse = await documentStoreService.saveProcessingLoader(appServer.AppDataSource, body, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const processLoader = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.loaderId === 'undefined' || req.params.loaderId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.processLoader - loaderId not provided!`
            )
        }
        if (typeof req.body === 'undefined') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.processLoader - body not provided!`
            )
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - organizationId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - workspaceId not provided!`
            )
        }
        const subscriptionId = req.user?.activeOrganizationSubscriptionId || ''
        const sanitizedLoaderId = sanitizeParam(req.params.loaderId)
        const body = req.body
        // Scan for malicious content in uploaded file body
        scanForMaliciousContent(body)
        // Reject if Singapore PII detected
        rejectIfSingaporePII(body)
        const isInternalRequest = req.headers['x-request-from'] === 'internal'
        const apiResponse = await documentStoreService.processLoaderMiddleware(
            body,
            sanitizedLoaderId,
            orgId,
            workspaceId,
            subscriptionId,
            getRunningExpressApp().usageCacheManager,
            isInternalRequest
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const updateDocumentStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.id === 'undefined' || req.params.id === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.updateDocumentStore - storeId not provided!`
            )
        }
        if (typeof req.body === 'undefined') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.updateDocumentStore - body not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.updateDocumentStore - workspaceId not provided!`
            )
        }
        const sanitizedId = sanitizeParam(req.params.id)
        const store = await documentStoreService.getDocumentStoreById(sanitizedId, workspaceId)
        if (!store) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: documentStoreController.updateDocumentStore - DocumentStore ${sanitizedId} not found in the database`
            )
        }
        const body = req.body
        const updateDocStore = new DocumentStore()
        // Explicit allowlist — id/workspaceId/timestamps must not be overrideable by client
        if (body.name !== undefined) updateDocStore.name = body.name
        if (body.description !== undefined) updateDocStore.description = body.description
        if (body.vectorStoreConfig !== undefined) updateDocStore.vectorStoreConfig = body.vectorStoreConfig
        if (body.embeddingConfig !== undefined) updateDocStore.embeddingConfig = body.embeddingConfig
        if (body.recordManagerConfig !== undefined) updateDocStore.recordManagerConfig = body.recordManagerConfig
        if (body.loaders !== undefined) updateDocStore.loaders = body.loaders
        if (body.whereUsed !== undefined) updateDocStore.whereUsed = body.whereUsed
        const apiResponse = await documentStoreService.updateDocumentStore(store, updateDocStore)
        return res.json(DocumentStoreDTO.fromEntity(apiResponse))
    } catch (error) {
        next(error)
    }
}

const deleteDocumentStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.id === 'undefined' || req.params.id === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.deleteDocumentStore - storeId not provided!`
            )
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - organizationId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - workspaceId not provided!`
            )
        }
        const sanitizedId = sanitizeParam(req.params.id)
        const apiResponse = await documentStoreService.deleteDocumentStore(
            sanitizedId,
            orgId,
            workspaceId,
            getRunningExpressApp().usageCacheManager
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const previewFileChunks = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.previewFileChunks - body not provided!`
            )
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - organizationId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - workspaceId not provided!`
            )
        }
        const subscriptionId = req.user?.activeOrganizationSubscriptionId || ''
        let body = req.body
        // Scan for malicious content
        scanForMaliciousContent(body)
        // Reject if Singapore PII detected
        rejectIfSingaporePII(body)
        // Redact PII from body before passing to service
        body = redactPIIFromBody(body)
        if (body.storeId) {
            const sanitizedStoreId = sanitizeParam(body.storeId as string)
            const store = await documentStoreService.getDocumentStoreById(sanitizedStoreId, workspaceId)
            if (!store) {
                throw new InternalFlowiseError(StatusCodes.NOT_FOUND, 'Document store not found')
            }
            body.storeId = sanitizedStoreId
        }
        body.preview = true
        const apiResponse = await documentStoreService.previewChunksMiddleware(
            body,
            orgId,
            workspaceId,
            subscriptionId,
            getRunningExpressApp().usageCacheManager
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getDocumentLoaders = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const apiResponse = await documentStoreService.getDocumentLoaders()
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const insertIntoVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined') {
            throw new Error('Error: documentStoreController.insertIntoVectorStore - body not provided!')
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - organizationId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - workspaceId not provided!`
            )
        }
        const subscriptionId = req.user?.activeOrganizationSubscriptionId || ''
        const body = req.body
        const isStrictSave = body.isStrictSave ?? false
        const apiResponse = await documentStoreService.insertIntoVectorStoreMiddleware(
            body,
            isStrictSave,
            orgId,
            workspaceId,
            subscriptionId,
            getRunningExpressApp().usageCacheManager
        )
        validateLLMResponse(apiResponse)
        getRunningExpressApp().metricsProvider?.incrementCounter(FLOWISE_METRIC_COUNTERS.VECTORSTORE_UPSERT, {
            status: FLOWISE_COUNTER_STATUS.SUCCESS
        })
        return res.json(DocumentStoreDTO.fromEntity(apiResponse))
    } catch (error) {
        getRunningExpressApp().metricsProvider?.incrementCounter(FLOWISE_METRIC_COUNTERS.VECTORSTORE_UPSERT, {
            status: FLOWISE_COUNTER_STATUS.FAILURE
        })
        next(error)
    }
}

const queryVectorStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined') {
            throw new Error('Error: documentStoreController.queryVectorStore - body not provided!')
        }
        const body = req.body
        const apiResponse = await documentStoreService.queryVectorStore(body)
        validateLLMResponse(apiResponse)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteVectorStoreFromStore = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.storeId === 'undefined' || req.params.storeId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.deleteVectorStoreFromStore - storeId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.deleteVectorStoreFromStore - workspaceId not provided!`
            )
        }
        const sanitizedStoreId = sanitizeParam(req.params.storeId)
        const apiResponse = await documentStoreService.deleteVectorStoreFromStore(
            sanitizedStoreId,
            workspaceId,
            (req.query.docId as string) || undefined
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const saveVectorStoreConfig = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined') {
            throw new Error('Error: documentStoreController.saveVectorStoreConfig - body not provided!')
        }
        const body = req.body
        const appDataSource = getRunningExpressApp().AppDataSource
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.saveVectorStoreConfig - workspaceId not provided!`
            )
        }
        const apiResponse = await documentStoreService.saveVectorStoreConfig(appDataSource, body, true, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const updateVectorStoreConfigOnly = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined') {
            throw new Error('Error: documentStoreController.updateVectorStoreConfigOnly - body not provided!')
        }
        const body = req.body
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.updateVectorStoreConfigOnly - workspaceId not provided!`
            )
        }
        const apiResponse = await documentStoreService.updateVectorStoreConfigOnly(body, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getEmbeddingProviders = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const apiResponse = await documentStoreService.getEmbeddingProviders()
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getVectorStoreProviders = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const apiResponse = await documentStoreService.getVectorStoreProviders()
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getRecordManagerProviders = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const apiResponse = await documentStoreService.getRecordManagerProviders()
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const upsertDocStoreMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.id === 'undefined' || req.params.id === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.upsertDocStoreMiddleware - storeId not provided!`
            )
        }
        if (typeof req.body === 'undefined') {
            throw new Error('Error: documentStoreController.upsertDocStoreMiddleware - body not provided!')
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - organizationId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - workspaceId not provided!`
            )
        }
        const subscriptionId = req.user?.activeOrganizationSubscriptionId || ''
        const sanitizedId = sanitizeParam(req.params.id)
        const body = req.body
        // Reject if Singapore PII detected in body or files
        rejectIfSingaporePII(body)
        const files = (req.files as Express.Multer.File[]) || []
        // Check file buffers for Singapore PII
        for (const file of files) {
            if (file.buffer) {
                const fileContent = file.buffer.toString('utf8')
                rejectIfSingaporePII(fileContent)
            }
        }
        const apiResponse = await documentStoreService.upsertDocStoreMiddleware(
            sanitizedId,
            body,
            files,
            orgId,
            workspaceId,
            subscriptionId,
            getRunningExpressApp().usageCacheManager
        )
        validateLLMResponse(apiResponse)
        getRunningExpressApp().metricsProvider?.incrementCounter(FLOWISE_METRIC_COUNTERS.VECTORSTORE_UPSERT, {
            status: FLOWISE_COUNTER_STATUS.SUCCESS
        })
        return res.json(apiResponse)
    } catch (error) {
        getRunningExpressApp().metricsProvider?.incrementCounter(FLOWISE_METRIC_COUNTERS.VECTORSTORE_UPSERT, {
            status: FLOWISE_COUNTER_STATUS.FAILURE
        })
        next(error)
    }
}

const refreshDocStoreMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.id === 'undefined' || req.params.id === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.refreshDocStoreMiddleware - storeId not provided!`
            )
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - organizationId not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.createDocumentStore - workspaceId not provided!`
            )
        }
        const subscriptionId = req.user?.activeOrganizationSubscriptionId || ''
        const sanitizedId = sanitizeParam(req.params.id)
        const body = req.body
        const apiResponse = await documentStoreService.refreshDocStoreMiddleware(
            sanitizedId,
            body,
            orgId,
            workspaceId,
            subscriptionId,
            getRunningExpressApp().usageCacheManager
        )
        validateLLMResponse(apiResponse)
        getRunningExpressApp().metricsProvider?.incrementCounter(FLOWISE_METRIC_COUNTERS.VECTORSTORE_UPSERT, {
            status: FLOWISE_COUNTER_STATUS.SUCCESS
        })
        return res.json(apiResponse)
    } catch (error) {
        getRunningExpressApp().metricsProvider?.incrementCounter(FLOWISE_METRIC_COUNTERS.VECTORSTORE_UPSERT, {
            status: FLOWISE_COUNTER_STATUS.FAILURE
        })
        next(error)
    }
}

const generateDocStoreToolDesc = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.id === 'undefined' || req.params.id === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.generateDocStoreToolDesc - storeId not provided!`
            )
        }
        if (typeof req.body === 'undefined') {
            throw new Error('Error: documentStoreController.generateDocStoreToolDesc - body not provided!')
        }
        // Validate and sanitize selectedChatModel
        const rawModel = req.body.selectedChatModel
        if (typeof rawModel !== 'string' || rawModel.trim().length === 0) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.generateDocStoreToolDesc - selectedChatModel must be a non-empty string!`
            )
        }
        const trimmedModel = rawModel.trim()
        if (trimmedModel.length > 256) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.generateDocStoreToolDesc - selectedChatModel exceeds maximum allowed length!`
            )
        }
        // Only allow alphanumeric, hyphens, underscores, dots, colons, and spaces
        if (!/^[a-zA-Z0-9\-_.:\ ]+$/.test(trimmedModel)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.generateDocStoreToolDesc - selectedChatModel contains invalid characters!`
            )
        }
        const sanitizedId = sanitizeParam(req.params.id)
        const apiResponse = await documentStoreService.generateDocStoreToolDesc(sanitizedId, trimmedModel)
        validateLLMResponse(apiResponse)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getDocStoreConfigs = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.id === 'undefined' || req.params.id === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.getDocStoreConfigs - storeId not provided!`
            )
        }
        if (typeof req.params.loaderId === 'undefined' || req.params.loaderId === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: documentStoreController.getDocStoreConfigs - doc loader Id not provided!`
            )
        }
        const sanitizedId = sanitizeParam(req.params.id)
        const sanitizedLoaderId = sanitizeParam(req.params.loaderId)
        const apiResponse = await documentStoreService.findDocStoreAvailableConfigs(sanitizedId, sanitizedLoaderId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    deleteDocumentStore,
    createDocumentStore,
    getAllDocumentStores,
    deleteLoaderFromDocumentStore,
    getDocumentStoreById,
    getDocumentStoreFileChunks,
    updateDocumentStore,
    processLoader,
    previewFileChunks,
    getDocumentLoaders,
    deleteDocumentStoreFileChunk,
    editDocumentStoreFileChunk,
    insertIntoVectorStore,
    getEmbeddingProviders,
    getVectorStoreProviders,
    getRecordManagerProviders,
    saveVectorStoreConfig,
    queryVectorStore,
    deleteVectorStoreFromStore,
    updateVectorStoreConfigOnly,
    upsertDocStoreMiddleware,
    refreshDocStoreMiddleware,
    saveProcessingLoader,
    generateDocStoreToolDesc,
    getDocStoreConfigs
}
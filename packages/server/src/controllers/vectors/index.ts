import { Request, Response, NextFunction } from 'express'
import vectorsService from '../../services/vectors'
import { RateLimiterManager } from '../../utils/rateLimit'

const SUSPICIOUS_PATTERNS = [
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /system\s*prompt/i,
    /you\s+are\s+now/i,
    /act\s+as\s+(a\s+)?(?:different|new|another)/i,
    /disregard\s+(all\s+)?(previous|prior|above)/i,
    /forget\s+(all\s+)?(previous|prior|above|your)/i,
    /new\s+instructions?\s*:/i,
    /override\s+(previous|prior|all|system)/i,
    /\[system\]/i,
    /\[assistant\]/i,
    /\[user\]/i,
    /<\s*system\s*>/i,
    /###\s*instruction/i,
    /prompt\s*injection/i,
    /jailbreak/i,
]

const INVISIBLE_CHAR_PATTERN = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/

const BASE64_PROMPT_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

const SHELL_COMMAND_PATTERN = /(\b(rm|chmod|chown|wget|curl|bash|sh|exec|eval|system|passthru|popen)\b\s*[\(\-\/])/i

const BINARY_CONTENT_PATTERN = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/

function isBase64EncodedPrompt(value: string): boolean {
    if (value.length > 20 && BASE64_PROMPT_PATTERN.test(value.trim())) {
        try {
            const decoded = Buffer.from(value.trim(), 'base64').toString('utf8')
            return SUSPICIOUS_PATTERNS.some((p) => p.test(decoded))
        } catch {
            return false
        }
    }
    return false
}

function containsMaliciousContent(value: string): boolean {
    if (INVISIBLE_CHAR_PATTERN.test(value)) return true
    if (BINARY_CONTENT_PATTERN.test(value)) return true
    if (SHELL_COMMAND_PATTERN.test(value)) return true
    if (SUSPICIOUS_PATTERNS.some((p) => p.test(value))) return true
    if (isBase64EncodedPrompt(value)) return true
    // leetspeak check: replace common substitutions and re-test
    const normalized = value
        .replace(/0/g, 'o')
        .replace(/1/g, 'i')
        .replace(/3/g, 'e')
        .replace(/4/g, 'a')
        .replace(/5/g, 's')
        .replace(/7/g, 't')
        .replace(/@/g, 'a')
        .replace(/\$/g, 's')
    if (SUSPICIOUS_PATTERNS.some((p) => p.test(normalized))) return true
    return false
}

function inspectObjectForMaliciousContent(obj: unknown, depth = 0): boolean {
    if (depth > 10) return false
    if (typeof obj === 'string') {
        return containsMaliciousContent(obj)
    }
    if (Array.isArray(obj)) {
        return obj.some((item) => inspectObjectForMaliciousContent(item, depth + 1))
    }
    if (obj && typeof obj === 'object') {
        return Object.values(obj).some((val) => inspectObjectForMaliciousContent(val, depth + 1))
    }
    return false
}

function inspectRequestForMaliciousContent(req: Request): boolean {
    const fieldsToCheck = ['text', 'content', 'documents', 'input', 'query', 'message', 'messages', 'data', 'prompt']
    if (req.body && typeof req.body === 'object') {
        for (const field of fieldsToCheck) {
            if (req.body[field] !== undefined) {
                if (inspectObjectForMaliciousContent(req.body[field])) return true
            }
        }
        // Also check the full body shallowly
        if (inspectObjectForMaliciousContent(req.body)) return true
    }
    return false
}

function sanitizeAndValidateRequest(req: Request): Partial<Request> {
    const allowedBodyFields = [
        'chatflowid',
        'chatId',
        'question',
        'overrideConfig',
        'history',
        'socketIOClientId',
        'stopNodeId',
        'uploads',
        'leadEmail',
        'action',
        'type',
        'id',
        'name',
        'description',
        'content',
        'documents',
        'text',
        'input',
        'data',
        'metadata',
        'namespace',
        'pineconeIndex',
        'pineconeNamespace',
        'pineconeEnvironment',
        'weaviateIndex',
        'weaviateScheme',
        'weaviateHost',
        'chromaCollection',
        'qdrantCollection',
        'replaceExisting',
        'returnSourceDocuments',
        'chunkSize',
        'chunkOverlap',
        'topK',
        'scoreThreshold',
    ]

    const sanitizedBody: Record<string, unknown> = {}
    if (req.body && typeof req.body === 'object') {
        for (const field of allowedBodyFields) {
            if (req.body[field] !== undefined) {
                sanitizedBody[field] = req.body[field]
            }
        }
    }

    const allowedParams = ['id', 'chatflowid', 'chatId', 'nodeId', 'type']
    const sanitizedParams: Record<string, string> = {}
    if (req.params) {
        for (const field of allowedParams) {
            if (req.params[field] !== undefined) {
                sanitizedParams[field] = String(req.params[field])
            }
        }
    }

    const allowedQuery = ['chatflowid', 'chatId', 'type', 'order', 'limit', 'offset', 'startDate', 'endDate']
    const sanitizedQuery: Record<string, unknown> = {}
    if (req.query) {
        for (const field of allowedQuery) {
            if (req.query[field] !== undefined) {
                sanitizedQuery[field] = req.query[field]
            }
        }
    }

    const allowedHeaders = ['authorization', 'content-type', 'x-request-id', 'x-api-key']
    const sanitizedHeaders: Record<string, string | string[] | undefined> = {}
    if (req.headers) {
        for (const field of allowedHeaders) {
            if (req.headers[field] !== undefined) {
                sanitizedHeaders[field] = req.headers[field]
            }
        }
    }

    return {
        ...req,
        body: sanitizedBody,
        params: sanitizedParams as Record<string, string>,
        query: sanitizedQuery as Request['query'],
        headers: sanitizedHeaders as Request['headers'],
    }
}

const getRateLimiterMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
        return RateLimiterManager.getInstance().getRateLimiter()(req, res, next)
    } catch (error) {
        next(error)
    }
}

const upsertVectorMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (inspectRequestForMaliciousContent(req)) {
            return res.status(400).json({ error: 'Request contains potentially malicious content and has been rejected.' })
        }
        const sanitizedReq = sanitizeAndValidateRequest(req)
        const apiResponse = await vectorsService.upsertVectorMiddleware(sanitizedReq as Request)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const createInternalUpsert = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (inspectRequestForMaliciousContent(req)) {
            return res.status(400).json({ error: 'Request contains potentially malicious content and has been rejected.' })
        }
        const isInternal = true
        const sanitizedReq = sanitizeAndValidateRequest(req)
        const apiResponse = await vectorsService.upsertVectorMiddleware(sanitizedReq as Request, isInternal)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    upsertVectorMiddleware,
    createInternalUpsert,
    getRateLimiterMiddleware
}
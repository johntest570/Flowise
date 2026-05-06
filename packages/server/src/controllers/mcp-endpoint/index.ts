import { NextFunction, Request, Response } from 'express'
import mcpEndpointService from '../../services/mcp-endpoint'
import { RateLimiterManager } from '../../utils/rateLimit'
import logger from '../../utils/logger'

/**
 * Validates chatflowId against a strict alphanumeric/hyphen/underscore/UUID pattern.
 */
const CHATFLOW_ID_PATTERN = /^[a-zA-Z0-9_-]{1,128}$/

function isValidChatflowId(id: string): boolean {
    return CHATFLOW_ID_PATTERN.test(id)
}

/**
 * Allowed JSON-RPC 2.0 top-level fields for request body sanitization.
 */
const ALLOWED_JSONRPC_FIELDS = new Set(['jsonrpc', 'method', 'params', 'id'])

/**
 * Dangerous prototype-polluting keys to strip from objects.
 */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/**
 * Script injection pattern for sanitizing string values.
 */
const SCRIPT_INJECTION_PATTERN = /<\s*script[\s\S]*?>[\s\S]*?<\s*\/\s*script\s*>/gi
const EVENT_HANDLER_PATTERN = /on\w+\s*=\s*["'][^"']*["']/gi
const JAVASCRIPT_PROTOCOL_PATTERN = /javascript\s*:/gi

/**
 * Maximum allowed body size in characters (1MB of JSON text).
 */
const MAX_BODY_SIZE = 1_000_000

/**
 * Recursively sanitize an object by stripping dangerous keys and script injection from strings.
 */
function sanitizeObject(obj: unknown, depth = 0): unknown {
    if (depth > 20) return obj
    if (typeof obj === 'string') {
        return obj
            .replace(SCRIPT_INJECTION_PATTERN, '')
            .replace(EVENT_HANDLER_PATTERN, '')
            .replace(JAVASCRIPT_PROTOCOL_PATTERN, '')
    }
    if (Array.isArray(obj)) {
        return obj.map((item) => sanitizeObject(item, depth + 1))
    }
    if (obj !== null && typeof obj === 'object') {
        const sanitized: Record<string, unknown> = {}
        for (const key of Object.keys(obj as Record<string, unknown>)) {
            if (DANGEROUS_KEYS.has(key)) continue
            sanitized[key] = sanitizeObject((obj as Record<string, unknown>)[key], depth + 1)
        }
        return sanitized
    }
    return obj
}

/**
 * Sanitize and validate the JSON-RPC request body, keeping only allowed fields.
 */
function sanitizeRequestBody(body: unknown): { valid: boolean; sanitized: Record<string, unknown>; error?: string } {
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
        return { valid: false, sanitized: {}, error: 'Request body must be a JSON object.' }
    }

    const raw = body as Record<string, unknown>
    const bodyStr = JSON.stringify(raw)
    if (bodyStr.length > MAX_BODY_SIZE) {
        return { valid: false, sanitized: {}, error: 'Request body exceeds maximum allowed size.' }
    }

    const sanitized: Record<string, unknown> = {}
    for (const key of Object.keys(raw)) {
        if (DANGEROUS_KEYS.has(key)) continue
        if (!ALLOWED_JSONRPC_FIELDS.has(key)) continue
        sanitized[key] = sanitizeObject(raw[key])
    }

    return { valid: true, sanitized }
}

/**
 * Sanitize MCP server response — strips dangerous keys, sanitizes strings, validates JSON-RPC 2.0 shape.
 */
function sanitizeMcpResponse(data: unknown): unknown {
    if (data === null || data === undefined) return data

    const sanitized = sanitizeObject(data)

    // Validate JSON-RPC 2.0 shape if it looks like a JSON-RPC response
    if (sanitized !== null && typeof sanitized === 'object' && !Array.isArray(sanitized)) {
        const obj = sanitized as Record<string, unknown>
        // Ensure jsonrpc field is '2.0' if present
        if ('jsonrpc' in obj && obj['jsonrpc'] !== '2.0') {
            obj['jsonrpc'] = '2.0'
        }
        // Strip any keys that are not part of JSON-RPC 2.0 response shape
        const allowedResponseKeys = new Set(['jsonrpc', 'result', 'error', 'id'])
        for (const key of Object.keys(obj)) {
            if (!allowedResponseKeys.has(key)) {
                delete obj[key]
            }
        }
    }

    return sanitized
}

/**
 * Wrap res.json and res.send to intercept and sanitize MCP server outputs before sending.
 */
function wrapResponseForSanitization(res: Response): void {
    const originalJson = res.json.bind(res)
    const originalSend = res.send.bind(res)

    res.json = function (body?: unknown): Response {
        const sanitized = sanitizeMcpResponse(body)
        return originalJson(sanitized)
    }

    res.send = function (body?: unknown): Response {
        if (typeof body === 'string') {
            try {
                const parsed = JSON.parse(body)
                const sanitized = sanitizeMcpResponse(parsed)
                return originalSend(JSON.stringify(sanitized))
            } catch {
                // Not JSON, pass through
                return originalSend(body)
            }
        }
        if (body !== null && body !== undefined && typeof body === 'object') {
            const sanitized = sanitizeMcpResponse(body)
            return originalSend(sanitized)
        }
        return originalSend(body)
    }
}

/**
 * Sanitize request headers by removing oversized or unexpected custom headers.
 */
function sanitizeHeaders(req: Request): void {
    const MAX_HEADER_VALUE_LENGTH = 8192
    for (const key of Object.keys(req.headers)) {
        const val = req.headers[key]
        if (typeof val === 'string' && val.length > MAX_HEADER_VALUE_LENGTH) {
            delete req.headers[key]
        } else if (Array.isArray(val)) {
            req.headers[key] = val.filter((v) => typeof v === 'string' && v.length <= MAX_HEADER_VALUE_LENGTH)
        }
    }
}

/**
 * Extract token from the Authorization: Bearer <token> header.
 * Returns null if not present or malformed.
 */
function extractToken(req: Request): string | null {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) return null
    const token = authHeader.slice(7).trim()
    return token.length > 0 ? token : null
}

/**
 * Authentication middleware — validates Bearer token and attaches it to res.locals.
 */
const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
    const token = extractToken(req)
    if (!token) {
        res.status(401).json({
            jsonrpc: '2.0',
            error: { code: -32001, message: 'Unauthorized: missing or invalid Authorization header. Use Bearer <token>.' },
            id: null
        })
        return
    }
    res.locals.token = token
    next()
}

/**
 * Rate limiter middleware for MCP endpoint — reuses per-chatflow rate limiters.
 */
const getRateLimiterMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
        return RateLimiterManager.getInstance().getRateLimiter()(req, res, next)
    } catch (error) {
        next(error)
    }
}

/**
 * Handle POST /api/v1/mcp/:chatflowId — MCP JSON-RPC messages
 * Auth: token must be in Authorization: Bearer <token> header
 */
const handlePost = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { chatflowId } = req.params

        // Validate chatflowId
        if (!chatflowId || !isValidChatflowId(chatflowId)) {
            res.status(400).json({
                jsonrpc: '2.0',
                error: { code: -32600, message: 'Invalid chatflowId: must be alphanumeric, hyphens, or underscores only.' },
                id: null
            })
            return
        }

        // Sanitize headers
        sanitizeHeaders(req)

        // Sanitize and validate request body
        const { valid, sanitized, error: bodyError } = sanitizeRequestBody(req.body)
        if (!valid) {
            res.status(400).json({
                jsonrpc: '2.0',
                error: { code: -32600, message: bodyError || 'Invalid request body.' },
                id: null
            })
            return
        }
        req.body = sanitized

        const token = res.locals.token as string

        logger.debug(`[MCP] POST request for chatflow: ${chatflowId}`)

        // Wrap response to sanitize MCP server output
        wrapResponseForSanitization(res)

        await mcpEndpointService.handleMcpRequest(chatflowId, token, req, res)

        logger.debug(`[MCP] POST response sent for chatflow: ${chatflowId}`)
    } catch (error) {
        next(error)
    }
}

/**
 * Handle DELETE /api/v1/mcp/:chatflowId — Session termination
 */
const handleDelete = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { chatflowId } = req.params

        // Validate chatflowId
        if (!chatflowId || !isValidChatflowId(chatflowId)) {
            res.status(400).json({
                jsonrpc: '2.0',
                error: { code: -32600, message: 'Invalid chatflowId: must be alphanumeric, hyphens, or underscores only.' },
                id: null
            })
            return
        }

        // Sanitize headers
        sanitizeHeaders(req)

        logger.debug(`[MCP] DELETE request for chatflow: ${chatflowId}`)

        // Wrap response to sanitize MCP server output
        wrapResponseForSanitization(res)

        await mcpEndpointService.handleMcpDeleteRequest(chatflowId, req, res)

        logger.debug(`[MCP] DELETE response sent for chatflow: ${chatflowId}`)
    } catch (error) {
        next(error)
    }
}

export default {
    authenticateToken,
    handlePost,
    handleDelete,
    getRateLimiterMiddleware
}
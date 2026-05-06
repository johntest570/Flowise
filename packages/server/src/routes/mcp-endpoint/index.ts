import express from 'express'
import cors from 'cors'
import crypto from 'crypto'
import mcpEndpointController from '../../controllers/mcp-endpoint'

const router = express.Router()

// Body size limit: 1MB max for MCP JSON-RPC payloads (overrides the global 50mb limit)
router.use(express.json({ limit: '1mb', type: 'application/json' }))

// CORS: Use MCP_CORS_ORIGINS if set, otherwise allow only non-browser (no Origin header) requests.
// MCP desktop clients (Claude Desktop, Cursor, etc.) don't send an Origin header, so they pass through.
// Browser-based clients are restricted to the configured origins.
const mcpCorsOrigins = process.env.MCP_CORS_ORIGINS
const mcpCorsOptions: cors.CorsOptions = {
    origin: mcpCorsOrigins
        ? mcpCorsOrigins === '*'
            ? true
            : mcpCorsOrigins.split(',').map((o) => o.trim())
        : (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
              // No origin header (desktop/server-to-server) → allow
              // Browser origin → deny (no allowed list configured)
              callback(null, !origin)
          },
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400
}
router.use(cors(mcpCorsOptions))
// Handle preflight for all MCP routes
router.options('/:chatflowId', cors(mcpCorsOptions))

// Middleware: Enforce HTTPS and set HSTS headers (skip in development/test)
const enforceHttps = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    const env = process.env.NODE_ENV
    if (env === 'development' || env === 'test') {
        return next()
    }
    const isHttps =
        req.secure ||
        req.headers['x-forwarded-proto'] === 'https' ||
        (Array.isArray(req.headers['x-forwarded-proto']) && req.headers['x-forwarded-proto'][0] === 'https')
    if (!isHttps) {
        res.status(403).json({ error: 'HTTPS is required for MCP endpoint access.' })
        return
    }
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
    next()
}

// Middleware: Expose server identity token derived from configured secret
const serverIdentitySecret = process.env.MCP_SERVER_IDENTITY_SECRET || ''
const attachServerIdentity = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    if (serverIdentitySecret) {
        const identityToken = crypto
            .createHmac('sha256', serverIdentitySecret)
            .update('mcp-server-identity')
            .digest('hex')
        res.setHeader('X-MCP-Server-Identity', identityToken)
    }
    next()
}

// Middleware: Validate ':chatflowId' route parameter (UUID format)
const validateChatflowId = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    const { chatflowId } = req.params
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    if (!chatflowId || !uuidRegex.test(chatflowId)) {
        res.status(400).json({ error: 'Invalid chatflowId: must be a valid UUID.' })
        return
    }
    next()
}

// Middleware: Validate JSON-RPC POST body (schema validation for required fields)
const validateJsonRpcBody = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    const body = req.body
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        res.status(400).json({ error: 'Invalid JSON-RPC request: body must be a non-null object.' })
        return
    }
    if (body.jsonrpc !== '2.0') {
        res.status(400).json({ error: 'Invalid JSON-RPC request: jsonrpc must be exactly "2.0".' })
        return
    }
    if (!body.method || typeof body.method !== 'string' || body.method.trim() === '') {
        res.status(400).json({ error: 'Invalid JSON-RPC request: method must be a non-empty string.' })
        return
    }
    next()
}

// Middleware: Sanitize and validate JSON-RPC payload for AI model input
const MAX_PARAMS_DEPTH = 5
const MAX_PARAMS_SIZE = 65536 // 64KB serialized limit for params

const sanitizeString = (value: string): string => {
    // Remove null bytes and control characters (except tab, newline, carriage return)
    return value.replace(/\x00/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
}

const sanitizeValue = (value: unknown, depth: number): unknown => {
    if (depth > MAX_PARAMS_DEPTH) {
        return null
    }
    if (typeof value === 'string') {
        return sanitizeString(value)
    }
    if (Array.isArray(value)) {
        return value.map((item) => sanitizeValue(item, depth + 1))
    }
    if (value !== null && typeof value === 'object') {
        const sanitized: Record<string, unknown> = {}
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
            sanitized[sanitizeString(k)] = sanitizeValue(v, depth + 1)
        }
        return sanitized
    }
    return value
}

const sanitizeJsonRpcPayload = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    const body = req.body
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        res.status(400).json({ error: 'Invalid JSON-RPC request: body must be a non-null object.' })
        return
    }
    if (body.jsonrpc !== '2.0') {
        res.status(400).json({ error: 'Invalid JSON-RPC request: jsonrpc must be exactly "2.0".' })
        return
    }
    if (!body.method || typeof body.method !== 'string' || body.method.trim() === '') {
        res.status(400).json({ error: 'Invalid JSON-RPC request: method must be a non-empty string.' })
        return
    }
    // Validate method contains only safe characters
    const safeMethodRegex = /^[a-zA-Z0-9_\-./]+$/
    if (!safeMethodRegex.test(body.method)) {
        res.status(400).json({ error: 'Invalid JSON-RPC request: method contains unsafe characters.' })
        return
    }
    // Strip unexpected top-level keys; only allow: jsonrpc, method, params, id
    const allowedKeys = new Set(['jsonrpc', 'method', 'params', 'id'])
    const sanitizedBody: Record<string, unknown> = {}
    for (const key of allowedKeys) {
        if (key in body) {
            sanitizedBody[key] = body[key]
        }
    }
    // Enforce max size on params
    if ('params' in sanitizedBody && sanitizedBody.params !== undefined) {
        const paramsStr = JSON.stringify(sanitizedBody.params)
        if (paramsStr.length > MAX_PARAMS_SIZE) {
            res.status(400).json({ error: 'Invalid JSON-RPC request: params exceeds maximum allowed size.' })
            return
        }
        // Recursively sanitize params
        sanitizedBody.params = sanitizeValue(sanitizedBody.params, 0)
    }
    // Sanitize method and id strings
    sanitizedBody.method = sanitizeString(sanitizedBody.method as string)
    if (typeof sanitizedBody.id === 'string') {
        sanitizedBody.id = sanitizeString(sanitizedBody.id)
    }
    req.body = sanitizedBody
    next()
}

// Apply HTTPS enforcement and server identity middleware globally
router.use(enforceHttps)
router.use(attachServerIdentity)

// MCP Streamable HTTP protocol routes (protocol version 2025-03-26)
// Auth: token must be provided via Authorization: Bearer <token> header
// POST — JSON-RPC messages (initialize, tools/list, tools/call, etc.)
router.post(
    '/:chatflowId',
    validateChatflowId,
    validateJsonRpcBody,
    mcpEndpointController.getRateLimiterMiddleware,
    mcpEndpointController.authenticateToken,
    sanitizeJsonRpcPayload,
    mcpEndpointController.handlePost
)

// DELETE — Session termination (stateless mode returns 405)
router.delete('/:chatflowId', validateChatflowId, mcpEndpointController.handleDelete)

export default router
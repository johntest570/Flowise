import express from 'express'
import customMcpServersController from '../../controllers/custom-mcp-servers'
import { checkAnyPermission, checkPermission } from '../../enterprise/rbac/PermissionCheck'
import { getLogger } from '../../utils/logger'

const logger = getLogger()
const router = express.Router()

// Logging middleware for all routes
router.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
    const user = (req as any).user ? (req as any).user.id || (req as any).user.email || 'authenticated' : 'anonymous'
    logger.info(`[MCP Interaction] method=${req.method} path=${req.path} timestamp=${new Date().toISOString()} user=${user}`)
    next()
})

// UUID/alphanumeric validator for :id params
const validateId = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const id = req.params.id
    if (id && !/^[a-zA-Z0-9_-]+$/.test(id)) {
        return res.status(400).json({ error: 'Invalid id parameter' })
    }
    next()
}

// Body sanitizer middleware
const sanitizeBody = (allowedFields: string[]) => (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.body && typeof req.body === 'object') {
        const sanitized: Record<string, any> = {}
        for (const field of allowedFields) {
            if (Object.prototype.hasOwnProperty.call(req.body, field)) {
                sanitized[field] = req.body[field]
            }
        }
        req.body = sanitized
    }
    next()
}

// MCP server identity verification middleware
const verifyMcpServerIdentity = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const mcpServerSecret = process.env.MCP_SERVER_SECRET
    const serverTokenHeader = req.headers['x-mcp-server-token'] as string | undefined
    const serverTokenBody = req.body && req.body.serverToken

    if (mcpServerSecret) {
        if (serverTokenHeader && serverTokenHeader === mcpServerSecret) {
            return next()
        }
        if (serverTokenBody && serverTokenBody === mcpServerSecret) {
            return next()
        }
        return res.status(401).json({ error: 'MCP server authentication failed: invalid or missing server token' })
    }
    next()
}

// CREATE
router.post(
    '/',
    checkPermission('tools:create'),
    sanitizeBody(['name', 'description', 'config', 'type', 'url', 'headers', 'isActive']),
    customMcpServersController.createCustomMcpServer
)

// READ
router.get('/', checkPermission('tools:view'), customMcpServersController.getAllCustomMcpServers)
router.get('/:id', validateId, checkPermission('tools:view'), customMcpServersController.getCustomMcpServerById)
router.get('/:id/tools', validateId, checkPermission('tools:view'), customMcpServersController.getDiscoveredTools)

// UPDATE
router.put(
    '/:id',
    validateId,
    checkAnyPermission('tools:update,tools:create'),
    sanitizeBody(['name', 'description', 'config', 'type', 'url', 'headers', 'isActive']),
    customMcpServersController.updateCustomMcpServer
)

// AUTHORIZE (connect to server & discover tools)
router.post(
    '/:id/authorize',
    validateId,
    checkAnyPermission('tools:update,tools:create'),
    verifyMcpServerIdentity,
    sanitizeBody(['serverToken', 'config', 'credentials']),
    customMcpServersController.authorizeCustomMcpServer
)

// DELETE
router.delete('/:id', validateId, checkPermission('tools:delete'), customMcpServersController.deleteCustomMcpServer)

export default router
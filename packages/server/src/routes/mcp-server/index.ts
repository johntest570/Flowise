import express from 'express'
import mcpServerController from '../../controllers/mcp-server'
import { checkAnyPermission } from '../../enterprise/rbac/PermissionCheck'
const router = express.Router()

const validateAndSanitize = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    const { id } = req.params
    if (id !== undefined) {
        const uuidRegex = /^[a-zA-Z0-9_-]+$/
        if (!id || !uuidRegex.test(id)) {
            res.status(400).json({ error: 'Invalid id parameter' })
            return
        }
    }

    if (req.body && typeof req.body === 'object') {
        const sanitized: Record<string, unknown> = {}
        for (const key of Object.keys(req.body)) {
            const value = req.body[key]
            sanitized[key] = typeof value === 'string' ? value.trim() : value
        }
        req.body = sanitized
    }

    if (req.query && typeof req.query === 'object') {
        const sanitizedQuery: Record<string, unknown> = {}
        for (const key of Object.keys(req.query)) {
            const value = req.query[key]
            sanitizedQuery[key] = typeof value === 'string' ? value.trim() : value
        }
        req.query = sanitizedQuery as any
    }

    next()
}

// GET    /api/v1/mcp-server/:id     → get current config
router.get('/:id', validateAndSanitize, checkAnyPermission('chatflows:config,agentflows:config'), mcpServerController.getMcpServerConfig)

// POST   /api/v1/mcp-server/:id       → enable (generates token)
router.post('/:id', validateAndSanitize, checkAnyPermission('chatflows:config,agentflows:config'), mcpServerController.createMcpServerConfig)

// PUT    /api/v1/mcp-server/:id         → update description/toolName/status
router.put('/:id', validateAndSanitize, checkAnyPermission('chatflows:config,agentflows:config'), mcpServerController.updateMcpServerConfig)

// DELETE /api/v1/mcp-server/:id         → disable (set enabled=false)
router.delete('/:id', validateAndSanitize, checkAnyPermission('chatflows:config,agentflows:config'), mcpServerController.deleteMcpServerConfig)

// POST   /api/v1/mcp-server/:id/refresh → rotate token
router.post('/:id/refresh', validateAndSanitize, checkAnyPermission('chatflows:config,agentflows:config'), mcpServerController.refreshMcpToken)

export default router
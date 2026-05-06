import express from 'express'
import toolsController from '../../controllers/tools'
import { checkAnyPermission, checkPermission } from '../../enterprise/rbac/PermissionCheck'

const router = express.Router()

const validateId = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const id = req.params.id
    if (id !== undefined) {
        if (!/^[a-zA-Z0-9-_]+$/.test(id) || id.trim() === '') {
            return res.status(400).json({ error: 'Invalid id parameter' })
        }
    }
    next()
}

const sanitizeBody = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.body && typeof req.body === 'object') {
        const sanitized: Record<string, any> = {}
        for (const key of Object.keys(req.body)) {
            const value = req.body[key]
            if (typeof value === 'string') {
                sanitized[key] = value.trim()
            } else if (typeof value === 'number' || typeof value === 'boolean' || Array.isArray(value) || (value !== null && typeof value === 'object')) {
                sanitized[key] = value
            }
        }
        req.body = sanitized
    }
    next()
}

// CREATE
router.post('/', checkPermission('tools:create'), sanitizeBody, toolsController.createTool)

// READ
router.get('/', checkPermission('tools:view'), toolsController.getAllTools)
router.get(['/', '/:id'], validateId, checkAnyPermission('tools:view'), toolsController.getToolById)

// UPDATE
router.put(['/', '/:id'], validateId, sanitizeBody, checkAnyPermission('tools:update,tools:create'), toolsController.updateTool)

// DELETE
router.delete(['/', '/:id'], validateId, checkPermission('tools:delete'), toolsController.deleteTool)

export default router
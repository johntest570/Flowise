import express, { Request, Response, NextFunction } from 'express'
import openaiRealTimeController from '../../controllers/openai-realtime'
import { authenticateUser } from '../../utils/validateKey'

const router = express.Router()

const validateId = (req: Request, res: Response, next: NextFunction): void => {
    const { id } = req.params
    if (id !== undefined) {
        const uuidRegex = /^[a-zA-Z0-9_-]+$/
        if (!uuidRegex.test(id)) {
            res.status(400).json({ error: 'Invalid id parameter' })
            return
        }
        req.params.id = id.trim()
    }
    next()
}

const sanitizeBody = (req: Request, res: Response, next: NextFunction): void => {
    if (req.body && typeof req.body === 'object') {
        const sanitize = (obj: Record<string, any>): Record<string, any> => {
            const sanitized: Record<string, any> = {}
            for (const key of Object.keys(obj)) {
                const value = obj[key]
                if (typeof value === 'string') {
                    sanitized[key] = value.trim()
                } else if (value && typeof value === 'object' && !Array.isArray(value)) {
                    sanitized[key] = sanitize(value)
                } else {
                    sanitized[key] = value
                }
            }
            return sanitized
        }
        req.body = sanitize(req.body)
    }
    next()
}

// GET
router.get(['/', '/:id'], authenticateUser, validateId, openaiRealTimeController.getAgentTools)

// EXECUTE
router.post(['/', '/:id'], authenticateUser, validateId, sanitizeBody, openaiRealTimeController.executeAgentTool)

export default router
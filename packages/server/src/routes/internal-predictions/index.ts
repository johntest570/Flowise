import express, { Request, Response, NextFunction } from 'express'
import internalPredictionsController from '../../controllers/internal-predictions'
const router = express.Router()

// Authentication middleware
const authenticateRequest = (req: Request, res: Response, next: NextFunction): void => {
    const expectedApiKey = process.env.INTERNAL_API_KEY
    if (!expectedApiKey) {
        res.status(401).json({ error: 'Unauthorized: server not configured with INTERNAL_API_KEY' })
        return
    }
    const apiKeyHeader = req.headers['x-api-key']
    const authHeader = req.headers['authorization']
    let providedKey: string | undefined
    if (apiKeyHeader) {
        providedKey = Array.isArray(apiKeyHeader) ? apiKeyHeader[0] : apiKeyHeader
    } else if (authHeader) {
        const parts = authHeader.split(' ')
        if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
            providedKey = parts[1]
        } else {
            providedKey = authHeader
        }
    }
    if (!providedKey || providedKey !== expectedApiKey) {
        res.status(401).json({ error: 'Unauthorized: invalid or missing API key' })
        return
    }
    next()
}

// Validation and sanitization middleware
const validateAndSanitize = (req: Request, res: Response, next: NextFunction): void => {
    // Validate route parameter id if present
    if (req.params && req.params.id !== undefined) {
        const id = req.params.id
        if (!id || !/^[a-zA-Z0-9_-]+$/.test(id)) {
            res.status(400).json({ error: 'Invalid id parameter' })
            return
        }
    }

    // Sanitize and validate request body
    if (req.body !== undefined && req.body !== null) {
        if (typeof req.body !== 'object' || Array.isArray(req.body)) {
            res.status(400).json({ error: 'Invalid request body' })
            return
        }

        const allowedFields = ['question', 'chatId', 'chatType', 'memoryType', 'sessionId', 'overrideConfig', 'history', 'socketIOClientId', 'uploads', 'leadEmail', 'action']
        const sanitizedBody: Record<string, unknown> = {}

        for (const key of allowedFields) {
            if (Object.prototype.hasOwnProperty.call(req.body, key)) {
                const value = req.body[key]
                // Trim string values and check for prompt injection patterns
                if (typeof value === 'string') {
                    const trimmed = value.trim()
                    const injectionPattern = /(\bignore\s+previous\s+instructions?\b|\bsystem\s*:\s*|\bprompt\s+injection\b)/i
                    if (injectionPattern.test(trimmed)) {
                        res.status(400).json({ error: 'Invalid input detected' })
                        return
                    }
                    sanitizedBody[key] = trimmed
                } else {
                    sanitizedBody[key] = value
                }
            }
        }

        req.body = sanitizedBody
    }

    next()
}

// CREATE
router.post(['/', '/:id'], authenticateRequest, validateAndSanitize, internalPredictionsController.createInternalPrediction)

export default router
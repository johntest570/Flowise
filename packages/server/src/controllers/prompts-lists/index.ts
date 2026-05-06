import { Request, Response, NextFunction } from 'express'
import promptsListsService from '../../services/prompts-lists'

const sanitizeString = (value: string): string => {
    return value.trim().replace(/[<>]/g, '')
}

const sanitizeBody = (body: Record<string, any>): Record<string, any> => {
    const sanitized: Record<string, any> = {}
    for (const key of Object.keys(body)) {
        const value = body[key]
        if (typeof value === 'string') {
            sanitized[key] = sanitizeString(value)
        } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
            sanitized[key] = sanitizeBody(value)
        } else {
            sanitized[key] = value
        }
    }
    return sanitized
}

// Prompt from Hub
const createPromptsList = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Authentication check
        const expectedApiKey = process.env.MCP_API_KEY
        if (expectedApiKey) {
            const authHeader = req.headers['authorization']
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Unauthorized: Missing or invalid Authorization header' })
            }
            const token = authHeader.slice(7)
            if (token !== expectedApiKey) {
                return res.status(401).json({ error: 'Unauthorized: Invalid API key' })
            }
        }

        // Input validation and sanitization
        if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
            return res.status(400).json({ error: 'Invalid request body: must be a plain object' })
        }

        const sanitizedBody = sanitizeBody(req.body)

        const apiResponse = await promptsListsService.createPromptsList(sanitizedBody)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    createPromptsList
}
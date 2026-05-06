import express, { Request, Response, NextFunction } from 'express'
import loadPromptsController from '../../controllers/load-prompts'
const router = express.Router()

const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    if (!token) {
        res.status(401).json({ error: 'Unauthorized: Missing token' })
        return
    }
    const validToken = process.env.AUTH_TOKEN
    if (!validToken || token !== validToken) {
        res.status(401).json({ error: 'Unauthorized: Invalid token' })
        return
    }
    next()
}

const validateAndSanitizePrompt = (req: Request, res: Response, next: NextFunction): void => {
    const MAX_LENGTH = 4096
    const DANGEROUS_CHARS = /[<>]/g

    const { prompt } = req.body

    if (prompt === undefined || prompt === null) {
        res.status(400).json({ error: 'Bad Request: Missing required field "prompt"' })
        return
    }

    if (typeof prompt !== 'string') {
        res.status(400).json({ error: 'Bad Request: Field "prompt" must be a string' })
        return
    }

    const sanitized = prompt.trim().replace(DANGEROUS_CHARS, '').slice(0, MAX_LENGTH)
    req.body.prompt = sanitized

    next()
}

// CREATE
router.post('/', authenticateToken, validateAndSanitizePrompt, loadPromptsController.createPrompt)

export default router
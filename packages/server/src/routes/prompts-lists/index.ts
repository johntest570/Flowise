import express from 'express'
import promptsListController from '../../controllers/prompts-lists'
const router = express.Router()

// Inline token-based authentication middleware
const authenticateToken = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null
    const serverSecret = process.env.FLOWISE_SECRET_KEY || ''
    if (!token || token !== serverSecret) {
        res.status(401).json({ error: 'Unauthorized' })
        return
    }
    next()
}

// CREATE
router.post('/', authenticateToken, promptsListController.createPromptsList)

export default router
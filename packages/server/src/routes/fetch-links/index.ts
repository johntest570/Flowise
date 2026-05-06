import express from 'express'
import fetchLinksController from '../../controllers/fetch-links'
const router = express.Router()

const authenticateMiddleware = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    const authHeader = req.headers['authorization']
    if (!authHeader) {
        res.status(401).json({ error: 'Unauthorized' })
        return
    }
    next()
}

// READ
router.get('/', authenticateMiddleware, fetchLinksController.getAllLinks)

export default router
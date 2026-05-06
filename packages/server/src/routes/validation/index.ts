import express from 'express'
import validationController from '../../controllers/validation'
import authenticateMiddleware from '../../middlewares/authentication'

const router = express.Router()

// READ
router.get(
    '/:id',
    authenticateMiddleware,
    (req, res, next) => {
        const { id } = req.params
        if (!id || !/^[a-zA-Z0-9_-]+$/.test(id)) {
            return res.status(400).json({ error: 'Invalid id parameter' })
        }
        next()
    },
    validationController.checkFlowValidation
)

export default router
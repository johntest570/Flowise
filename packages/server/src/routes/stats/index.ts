import express from 'express'
import statsController from '../../controllers/stats'
import { authenticateUser } from '../../utils/validateKey'

const router = express.Router()

// READ
router.get(['/', '/:id'], authenticateUser, statsController.getChatflowStats)

export default router
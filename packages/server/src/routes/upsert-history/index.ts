import express from 'express'
import upsertHistoryController from '../../controllers/upsert-history'
import { authenticateUser } from '../../utils/authMiddleware'
const router = express.Router()

// CREATE

// READ
router.get(['/', '/:id'], authenticateUser, upsertHistoryController.getAllUpsertHistory)

// PATCH
router.patch('/', authenticateUser, upsertHistoryController.patchDeleteUpsertHistory)

// DELETE

export default router
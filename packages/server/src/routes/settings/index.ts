import express from 'express'
import settingsController from '../../controllers/settings'
import { authenticateUser } from '../../utils/validateKey'
const router = express.Router()

// CREATE
router.get('/', authenticateUser, settingsController.getSettingsList)

export default router
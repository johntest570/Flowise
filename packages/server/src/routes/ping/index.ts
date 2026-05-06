import express from 'express'
import pingController from '../../controllers/ping'
import { authenticateUser } from '../../utils/validateKey'
const router = express.Router()

// GET
router.get('/', authenticateUser, pingController.getPing)

export default router
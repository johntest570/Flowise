import express from 'express'
import nodeConfigsController from '../../controllers/node-configs'
import { authenticateUser } from '../../utils/validateKey'
const router = express.Router()

// CREATE
router.post('/', authenticateUser, nodeConfigsController.getAllNodeConfigs)

export default router
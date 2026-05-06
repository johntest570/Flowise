import express from 'express'
import componentsCredentialsController from '../../controllers/components-credentials'
import { authenticateUser } from '../../utils/validateKey'
const router = express.Router()

// READ
router.get('/', authenticateUser, componentsCredentialsController.getAllComponentsCredentials)
router.get(['/', '/:name'], authenticateUser, componentsCredentialsController.getComponentByName)

export default router
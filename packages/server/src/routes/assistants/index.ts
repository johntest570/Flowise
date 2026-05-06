import express from 'express'
import { Request, Response, NextFunction } from 'express'
import assistantsController from '../../controllers/assistants'
import { checkPermission, checkAnyPermission } from '../../enterprise/rbac/PermissionCheck'

const router = express.Router()

// Inline sanitization and validation middleware for generate instruction route
const validateGenerateInstruction = (req: Request, res: Response, next: NextFunction): void => {
    const body = req.body

    if (!body || typeof body !== 'object') {
        res.status(400).json({ message: 'Invalid request body' })
        return
    }

    // Check for a non-empty prompt or instruction field
    const promptField = body.prompt !== undefined ? 'prompt' : body.instruction !== undefined ? 'instruction' : null

    if (!promptField) {
        res.status(400).json({ message: 'Request body must contain a prompt or instruction field' })
        return
    }

    const fieldValue = body[promptField]

    if (typeof fieldValue !== 'string' || fieldValue.trim().length === 0) {
        res.status(400).json({ message: `The ${promptField} field must be a non-empty string` })
        return
    }

    // Strip or escape potentially dangerous characters
    const sanitized = fieldValue
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // remove control characters
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')

    if (sanitized.trim().length === 0) {
        res.status(400).json({ message: `The ${promptField} field contains only invalid characters` })
        return
    }

    req.body[promptField] = sanitized

    next()
}

// CREATE
router.post('/', checkPermission('assistants:create'), assistantsController.createAssistant)

// READ
router.get('/', checkPermission('assistants:view'), assistantsController.getAllAssistants)
router.get(['/', '/:id'], checkPermission('assistants:view'), assistantsController.getAssistantById)

// UPDATE
router.put(['/', '/:id'], checkAnyPermission('assistants:create,assistants:update'), assistantsController.updateAssistant)

// DELETE
router.delete(['/', '/:id'], checkPermission('assistants:delete'), assistantsController.deleteAssistant)

router.get('/components/chatmodels', assistantsController.getChatModels)
router.get('/components/docstores', assistantsController.getDocumentStores)
router.get('/components/tools', assistantsController.getTools)

// Generate Assistant Instruction
router.post('/generate/instruction', validateGenerateInstruction, assistantsController.generateAssistantInstruction)

export default router
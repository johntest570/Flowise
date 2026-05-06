import { NextFunction, Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { AssistantType } from '../../Interface'
import assistantsService from '../../services/assistants'
import { getRunningExpressApp } from '../../utils/getRunningExpressApp'
import { checkUsageLimit } from '../../utils/quotaUsage'

const DANGEROUS_CODE_PRIMITIVES = /\b(eval|exec|execSync|spawn|spawnSync|fork|Function|setTimeout|setInterval|setImmediate|require|import|process|child_process|subprocess|__import__|compile|execfile|execfile)\s*\(/i

const sanitizeString = (value: unknown): string => {
    if (typeof value !== 'string') return ''
    return value.trim().replace(/[<>"'`\\]/g, '')
}

const sanitizeBody = (body: Record<string, unknown>): Record<string, unknown> => {
    const sanitized: Record<string, unknown> = {}
    for (const key of Object.keys(body)) {
        const value = body[key]
        if (typeof value === 'string') {
            sanitized[key] = sanitizeString(value)
        } else if (typeof value === 'number' || typeof value === 'boolean') {
            sanitized[key] = value
        } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
            sanitized[key] = sanitizeBody(value as Record<string, unknown>)
        } else if (Array.isArray(value)) {
            sanitized[key] = value
        } else {
            sanitized[key] = value
        }
    }
    return sanitized
}

const containsDangerousCodePrimitives = (value: unknown): boolean => {
    if (typeof value === 'string') {
        return DANGEROUS_CODE_PRIMITIVES.test(value)
    }
    if (value !== null && typeof value === 'object') {
        return Object.values(value).some(containsDangerousCodePrimitives)
    }
    return false
}

const createAssistant = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.createAssistant - body not provided!`
            )
        }
        const body = sanitizeBody(req.body)
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: assistantsController.createAssistant - organization ${orgId} not found!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: assistantsController.createAssistant - workspace ${workspaceId} not found!`
            )
        }
        const subscriptionId = req.user?.activeOrganizationSubscriptionId || ''

        const existingAssistantCount = await assistantsService.getAssistantsCountByOrganization(body.type as string, orgId)
        const newAssistantCount = 1
        await checkUsageLimit('flows', subscriptionId, getRunningExpressApp().usageCacheManager, existingAssistantCount + newAssistantCount)

        const apiResponse = await assistantsService.createAssistant(body, orgId, workspaceId)

        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteAssistant = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.deleteAssistant - id not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: assistantsController.deleteAssistant - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await assistantsService.deleteAssistant(req.params.id, req.query.isDeleteBoth, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getAllAssistants = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const type = req.query.type as AssistantType
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: assistantsController.getAllAssistants - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await assistantsService.getAllAssistants(workspaceId, type)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getAssistantById = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.getAssistantById - id not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: assistantsController.getAssistantById - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await assistantsService.getAssistantById(req.params.id, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const updateAssistant = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.updateAssistant - id not provided!`
            )
        }
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.updateAssistant - body not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: assistantsController.updateAssistant - workspace ${workspaceId} not found!`
            )
        }
        const sanitizedBody = sanitizeBody(req.body)
        const apiResponse = await assistantsService.updateAssistant(req.params.id, sanitizedBody, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getChatModels = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const apiResponse = await assistantsService.getChatModels()
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getDocumentStores = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: assistantsController.getDocumentStores - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await assistantsService.getDocumentStores(workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getTools = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const apiResponse = await assistantsService.getTools()
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const generateAssistantInstruction = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.generateAssistantInstruction - body not provided!`
            )
        }
        const rawTask = req.body.task
        const rawSelectedChatModel = req.body.selectedChatModel

        if (!rawTask || typeof rawTask !== 'string' || rawTask.trim() === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.generateAssistantInstruction - task must be a non-empty string!`
            )
        }
        if (!rawSelectedChatModel || typeof rawSelectedChatModel !== 'string' || rawSelectedChatModel.trim() === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.generateAssistantInstruction - selectedChatModel must be a non-empty string!`
            )
        }

        const task = sanitizeString(rawTask)
        const selectedChatModel = sanitizeString(rawSelectedChatModel)

        if (!task) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.generateAssistantInstruction - task is invalid after sanitization!`
            )
        }
        if (!selectedChatModel) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: assistantsController.generateAssistantInstruction - selectedChatModel is invalid after sanitization!`
            )
        }

        const apiResponse = await assistantsService.generateAssistantInstruction(task, selectedChatModel)

        if (containsDangerousCodePrimitives(apiResponse)) {
            throw new InternalFlowiseError(
                StatusCodes.INTERNAL_SERVER_ERROR,
                `Error: assistantsController.generateAssistantInstruction - LLM response contains dangerous code execution primitives!`
            )
        }

        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    createAssistant,
    deleteAssistant,
    getAllAssistants,
    getAssistantById,
    updateAssistant,
    getChatModels,
    getDocumentStores,
    getTools,
    generateAssistantInstruction
}
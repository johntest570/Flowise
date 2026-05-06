import { NextFunction, Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import marketplacesService from '../../services/marketplaces'
import { stripProtectedFields } from '../../utils/stripProtectedFields'

// Get all templates for marketplaces
const getAllTemplates = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const apiResponse = await marketplacesService.getAllTemplates()
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteCustomTemplate = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: marketplacesService.deleteCustomTemplate - id not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: marketplacesController.deleteCustomTemplate - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await marketplacesService.deleteCustomTemplate(req.params.id, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getAllCustomTemplates = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const activeWorkspaceId = req.user?.activeWorkspaceId
        if (!activeWorkspaceId || typeof activeWorkspaceId !== 'string' || activeWorkspaceId.trim() === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: marketplacesController.getAllCustomTemplates - activeWorkspaceId is required and must be a non-empty string!`
            )
        }
        const apiResponse = await marketplacesService.getAllCustomTemplates(activeWorkspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const saveCustomTemplate = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if ((!req.body && !(req.body.chatflowId || req.body.tool)) || !req.body.name) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: marketplacesService.saveCustomTemplate - body not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: marketplacesController.saveCustomTemplate - workspace ${workspaceId} not found!`
            )
        }

        const { chatflowId, tool, name } = req.body

        if (typeof name !== 'string' || name.trim() === '' || name.trim().length > 255) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: marketplacesService.saveCustomTemplate - 'name' must be a non-empty string with a maximum length of 255 characters!`
            )
        }

        if (chatflowId !== undefined) {
            if (typeof chatflowId !== 'string' || chatflowId.trim() === '' || chatflowId.trim().length > 255) {
                throw new InternalFlowiseError(
                    StatusCodes.PRECONDITION_FAILED,
                    `Error: marketplacesService.saveCustomTemplate - 'chatflowId' must be a non-empty string with a maximum length of 255 characters!`
                )
            }
        }

        if (tool !== undefined) {
            if (typeof tool !== 'string' || tool.trim() === '' || tool.trim().length > 255) {
                throw new InternalFlowiseError(
                    StatusCodes.PRECONDITION_FAILED,
                    `Error: marketplacesService.saveCustomTemplate - 'tool' must be a non-empty string with a maximum length of 255 characters!`
                )
            }
        }

        const sanitizedBody = {
            ...stripProtectedFields(req.body),
            name: name.trim(),
            ...(chatflowId !== undefined && { chatflowId: chatflowId.trim() }),
            ...(tool !== undefined && { tool: tool.trim() }),
            workspaceId
        }

        const apiResponse = await marketplacesService.saveCustomTemplate(sanitizedBody)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    getAllTemplates,
    getAllCustomTemplates,
    saveCustomTemplate,
    deleteCustomTemplate
}
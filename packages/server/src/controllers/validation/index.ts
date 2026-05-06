import { Request, Response, NextFunction } from 'express'
import validationService from '../../services/validation'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'

const SAFE_ID_REGEX = /^[a-zA-Z0-9_-]+$/

const checkFlowValidation = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const rawFlowId = req.params?.id as string | undefined
        if (!rawFlowId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: validationController.checkFlowValidation - id not provided!`
            )
        }
        const flowId = rawFlowId.trim()
        if (!SAFE_ID_REGEX.test(flowId)) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: validationController.checkFlowValidation - invalid id format!`
            )
        }
        const rawWorkspaceId = req.user?.activeWorkspaceId
        let workspaceId: string | undefined
        if (rawWorkspaceId !== undefined && rawWorkspaceId !== null) {
            const trimmed = String(rawWorkspaceId).trim()
            if (!SAFE_ID_REGEX.test(trimmed)) {
                throw new InternalFlowiseError(
                    StatusCodes.BAD_REQUEST,
                    `Error: validationController.checkFlowValidation - invalid workspaceId format!`
                )
            }
            workspaceId = trimmed
        } else {
            workspaceId = rawWorkspaceId
        }
        const apiResponse = await validationService.checkFlowValidation(flowId, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    checkFlowValidation
}
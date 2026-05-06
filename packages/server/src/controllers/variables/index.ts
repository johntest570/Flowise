import { Request, Response, NextFunction } from 'express'
import variablesService from '../../services/variables'
import { Variable } from '../../database/entities/Variable'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'
import { getPageAndLimitParams } from '../../utils/pagination'

const VARIABLE_TYPE_ALLOWLIST = ['string', 'number', 'boolean', 'json', 'static', 'runtime']
const MAX_FIELD_LENGTH = 4096

const sanitizeString = (value: unknown, maxLength: number = MAX_FIELD_LENGTH): string | undefined => {
    if (value === undefined || value === null) return undefined
    if (typeof value !== 'string') return undefined
    const trimmed = value.trim()
    if (trimmed.length > maxLength) return trimmed.substring(0, maxLength)
    return trimmed
}

const sanitizeType = (value: unknown): string | undefined => {
    if (value === undefined || value === null) return undefined
    if (typeof value !== 'string') return undefined
    const trimmed = value.trim()
    if (!VARIABLE_TYPE_ALLOWLIST.includes(trimmed)) return undefined
    return trimmed
}

const createVariable = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: variablesController.createVariable - body not provided!`
            )
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, `Error: toolsController.createTool - organization ${orgId} not found!`)
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, `Error: toolsController.createTool - workspace ${workspaceId} not found!`)
        }
        const body = req.body
        // Explicit allowlist — id/workspaceId/timestamps must not be overrideable by client
        const newVariable = new Variable()
        const sanitizedName = sanitizeString(body.name)
        if (sanitizedName !== undefined) newVariable.name = sanitizedName
        const sanitizedValue = sanitizeString(body.value)
        if (sanitizedValue !== undefined) newVariable.value = sanitizedValue
        const sanitizedType = sanitizeType(body.type)
        if (sanitizedType !== undefined) newVariable.type = sanitizedType
        newVariable.workspaceId = workspaceId
        const apiResponse = await variablesService.createVariable(newVariable, orgId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteVariable = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, 'Error: variablesController.deleteVariable - id not provided!')
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: variablesController.deleteVariable - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await variablesService.deleteVariable(req.params.id, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getAllVariables = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { page, limit } = getPageAndLimitParams(req)
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: variablesController.getAllVariables - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await variablesService.getAllVariables(workspaceId, page, limit)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const updateVariable = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, 'Error: variablesController.updateVariable - id not provided!')
        }
        if (typeof req.body === 'undefined') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                'Error: variablesController.updateVariable - body not provided!'
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: variablesController.updateVariable - workspace ${workspaceId} not found!`
            )
        }
        const variable = await variablesService.getVariableById(req.params.id, workspaceId)
        if (!variable) {
            return res.status(404).send('Variable not found in the database')
        }
        const body = req.body
        // Explicit allowlist — id/workspaceId/timestamps must not be overrideable by client
        const updatedVariable = new Variable()
        const sanitizedName = sanitizeString(body.name)
        if (sanitizedName !== undefined) updatedVariable.name = sanitizedName
        const sanitizedValue = sanitizeString(body.value)
        if (sanitizedValue !== undefined) updatedVariable.value = sanitizedValue
        const sanitizedType = sanitizeType(body.type)
        if (sanitizedType !== undefined) updatedVariable.type = sanitizedType
        const apiResponse = await variablesService.updateVariable(variable, updatedVariable)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    createVariable,
    deleteVariable,
    getAllVariables,
    updateVariable
}
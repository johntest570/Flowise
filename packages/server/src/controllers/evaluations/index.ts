import { Request, Response, NextFunction } from 'express'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'
import evaluationsService from '../../services/evaluations'
import { getPageAndLimitParams } from '../../utils/pagination'

const createEvaluation = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: evaluationsService.createEvaluation - body not provided!`
            )
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.createEvaluation - organization ${orgId} not found!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.createEvaluation - workspace ${workspaceId} not found!`
            )
        }

        // Validate required fields
        const { name, evaluationType, chatflowId, datasetId, evaluators, description, evaluatorId, additionalConfig } = req.body

        if (!name || typeof name !== 'string' || name.trim() === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: evaluationsService.createEvaluation - name is required and must be a non-empty string!`
            )
        }
        if (!evaluationType || typeof evaluationType !== 'string' || evaluationType.trim() === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: evaluationsService.createEvaluation - evaluationType is required and must be a non-empty string!`
            )
        }
        if (!chatflowId || typeof chatflowId !== 'string' || chatflowId.trim() === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: evaluationsService.createEvaluation - chatflowId is required and must be a non-empty string!`
            )
        }
        if (!datasetId || typeof datasetId !== 'string' || datasetId.trim() === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: evaluationsService.createEvaluation - datasetId is required and must be a non-empty string!`
            )
        }
        if (!evaluators || !Array.isArray(evaluators)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: evaluationsService.createEvaluation - evaluators is required and must be an array!`
            )
        }

        // Build sanitized body with only known, expected fields
        const sanitizedBody: Record<string, unknown> = {
            name: name.trim(),
            evaluationType: evaluationType.trim(),
            chatflowId: chatflowId.trim(),
            datasetId: datasetId.trim(),
            evaluators,
            workspaceId
        }

        if (description !== undefined && typeof description === 'string') {
            sanitizedBody.description = description.trim()
        }
        if (evaluatorId !== undefined && typeof evaluatorId === 'string' && evaluatorId.trim() !== '') {
            sanitizedBody.evaluatorId = evaluatorId.trim()
        }
        if (additionalConfig !== undefined && typeof additionalConfig === 'object' && additionalConfig !== null && !Array.isArray(additionalConfig)) {
            sanitizedBody.additionalConfig = additionalConfig
        }

        const baseURL = `${process.env.APP_URL}`
        const apiResponse = await evaluationsService.createEvaluation(sanitizedBody, baseURL, orgId, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const runAgain = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, `Error: evaluationsService.runAgain - id not provided!`)
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, `Error: evaluationsService.runAgain - organization ${orgId} not found!`)
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.runAgain - workspace ${workspaceId} not found!`
            )
        }
        const baseURL = `${process.env.APP_URL}`
        const apiResponse = await evaluationsService.runAgain(req.params.id, baseURL, orgId, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getEvaluation = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, `Error: evaluationsService.getEvaluation - id not provided!`)
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.getEvaluation - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await evaluationsService.getEvaluation(req.params.id, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteEvaluation = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, `Error: evaluationsService.deleteEvaluation - id not provided!`)
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.deleteEvaluation - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await evaluationsService.deleteEvaluation(req.params.id, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getAllEvaluations = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { page, limit } = getPageAndLimitParams(req)
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.getAllEvaluations - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await evaluationsService.getAllEvaluations(workspaceId, page, limit)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const isOutdated = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, `Error: evaluationsService.isOutdated - id not provided!`)
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.isOutdated - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await evaluationsService.isOutdated(req.params.id, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const getVersions = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, `Error: evaluationsService.getVersions - id not provided!`)
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.getVersions - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await evaluationsService.getVersions(req.params.id, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const patchDeleteEvaluations = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const rawIds = req.body.ids
        const rawIsDeleteAllVersion = req.body.isDeleteAllVersion

        // Validate ids is an array of non-empty strings
        if (!Array.isArray(rawIds)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: evaluationsService.patchDeleteEvaluations - ids must be an array!`
            )
        }
        for (const id of rawIds) {
            if (typeof id !== 'string' || id.trim() === '') {
                throw new InternalFlowiseError(
                    StatusCodes.PRECONDITION_FAILED,
                    `Error: evaluationsService.patchDeleteEvaluations - each id must be a non-empty string!`
                )
            }
        }
        const ids: string[] = rawIds.map((id: string) => id.trim())

        // Validate isDeleteAllVersion is a boolean
        let isDeleteAllVersion: boolean = false
        if (rawIsDeleteAllVersion !== undefined) {
            if (typeof rawIsDeleteAllVersion !== 'boolean') {
                throw new InternalFlowiseError(
                    StatusCodes.PRECONDITION_FAILED,
                    `Error: evaluationsService.patchDeleteEvaluations - isDeleteAllVersion must be a boolean!`
                )
            }
            isDeleteAllVersion = rawIsDeleteAllVersion
        }

        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: evaluationsService.patchDeleteEvaluations - workspace ${workspaceId} not found!`
            )
        }
        const apiResponse = await evaluationsService.patchDeleteEvaluations(ids, workspaceId, isDeleteAllVersion)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    createEvaluation,
    getEvaluation,
    deleteEvaluation,
    getAllEvaluations,
    isOutdated,
    runAgain,
    getVersions,
    patchDeleteEvaluations
}
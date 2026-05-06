import { Request, Response, NextFunction } from 'express'
import { StatusCodes } from 'http-status-codes'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import chatflowsService from '../../services/chatflows'
import upsertHistoryService from '../../services/upsert-history'

const SORT_ORDER_ALLOWLIST = ['ASC', 'DESC']
const ISO8601_REGEX = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$/
const SAFE_ID_REGEX = /^[a-zA-Z0-9_-]+$/

const getAllUpsertHistory = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: upsertHistoryController.getAllUpsertHistory - workspace ${workspaceId} not found!`
            )
        }
        const chatflowid = req.params?.id as string | undefined
        if (!chatflowid) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                'Error: upsertHistoryController.getAllUpsertHistory - chatflow id is required!'
            )
        }
        await chatflowsService.getChatflowById(chatflowid, workspaceId)

        const rawSortOrder = req.query?.order as string | undefined
        let sortOrder: string | undefined
        if (rawSortOrder !== undefined) {
            if (!SORT_ORDER_ALLOWLIST.includes(rawSortOrder)) {
                throw new InternalFlowiseError(
                    StatusCodes.BAD_REQUEST,
                    'Error: upsertHistoryController.getAllUpsertHistory - invalid sortOrder value!'
                )
            }
            sortOrder = rawSortOrder
        }

        const rawStartDate = req.query?.startDate as string | undefined
        let startDate: string | undefined
        if (rawStartDate !== undefined) {
            const trimmed = rawStartDate.trim()
            if (!ISO8601_REGEX.test(trimmed)) {
                throw new InternalFlowiseError(
                    StatusCodes.BAD_REQUEST,
                    'Error: upsertHistoryController.getAllUpsertHistory - invalid startDate format!'
                )
            }
            startDate = trimmed
        }

        const rawEndDate = req.query?.endDate as string | undefined
        let endDate: string | undefined
        if (rawEndDate !== undefined) {
            const trimmed = rawEndDate.trim()
            if (!ISO8601_REGEX.test(trimmed)) {
                throw new InternalFlowiseError(
                    StatusCodes.BAD_REQUEST,
                    'Error: upsertHistoryController.getAllUpsertHistory - invalid endDate format!'
                )
            }
            endDate = trimmed
        }

        const apiResponse = await upsertHistoryService.getAllUpsertHistory(sortOrder, chatflowid, startDate, endDate)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const patchDeleteUpsertHistory = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: upsertHistoryController.patchDeleteUpsertHistory - workspace ${workspaceId} not found!`
            )
        }
        const rawIds = req.body.ids ?? []
        if (!Array.isArray(rawIds) || rawIds.length === 0) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                'Error: upsertHistoryController.patchDeleteUpsertHistory - ids must be a non-empty array!'
            )
        }
        for (const id of rawIds) {
            if (typeof id !== 'string' || id.trim() === '' || !SAFE_ID_REGEX.test(id)) {
                throw new InternalFlowiseError(
                    StatusCodes.BAD_REQUEST,
                    'Error: upsertHistoryController.patchDeleteUpsertHistory - invalid id value in ids array!'
                )
            }
        }
        const ids = rawIds.map((id: string) => id.trim())
        const apiResponse = await upsertHistoryService.patchDeleteUpsertHistory(ids, workspaceId)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    getAllUpsertHistory,
    patchDeleteUpsertHistory
}
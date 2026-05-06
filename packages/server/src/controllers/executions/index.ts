import { Request, Response, NextFunction } from 'express'
import executionsService from '../../services/executions'
import { ExecutionState } from '../../Interface'

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const isValidUUID = (id: string): boolean => {
    return UUID_REGEX.test(id)
}

const isValidDateString = (dateStr: string): boolean => {
    if (!dateStr || typeof dateStr !== 'string') return false
    const date = new Date(dateStr)
    return !isNaN(date.getTime())
}

const ALLOWED_UPDATE_FIELDS = ['state', 'executionData', 'stoppedDate', 'timeTaken', 'fullLogs', 'shortLogs']

const sanitizeUpdateBody = (body: any): any => {
    if (!body || typeof body !== 'object') return {}
    const sanitized: any = {}
    for (const field of ALLOWED_UPDATE_FIELDS) {
        if (Object.prototype.hasOwnProperty.call(body, field)) {
            sanitized[field] = body[field]
        }
    }
    return sanitized
}

const getExecutionById = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const executionId = req.params.id
        if (!executionId || !isValidUUID(executionId)) {
            return res.status(400).json({ success: false, message: 'Invalid execution ID format' })
        }
        const workspaceId = req.user?.activeWorkspaceId
        const execution = await executionsService.getExecutionById(executionId, workspaceId)
        return res.json(execution)
    } catch (error) {
        next(error)
    }
}

const getPublicExecutionById = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const executionId = req.params.id
        if (!executionId || !isValidUUID(executionId)) {
            return res.status(400).json({ success: false, message: 'Invalid execution ID format' })
        }
        const execution = await executionsService.getPublicExecutionById(executionId)
        return res.json(execution)
    } catch (error) {
        next(error)
    }
}

const updateExecution = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const executionId = req.params.id
        if (!executionId || !isValidUUID(executionId)) {
            return res.status(400).json({ success: false, message: 'Invalid execution ID format' })
        }
        const workspaceId = req.user?.activeWorkspaceId
        const sanitizedBody = sanitizeUpdateBody(req.body)
        const execution = await executionsService.updateExecution(executionId, sanitizedBody, workspaceId)
        return res.json(execution)
    } catch (error) {
        next(error)
    }
}

const getAllExecutions = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Extract all possible filters from query params
        const filters: any = {}

        // Add workspace ID filter
        filters.workspaceId = req.user?.activeWorkspaceId

        // ID filter
        if (req.query.id) filters.id = req.query.id as string

        // Flow and session filters
        if (req.query.agentflowId) filters.agentflowId = req.query.agentflowId as string
        if (req.query.agentflowName) filters.agentflowName = req.query.agentflowName as string
        if (req.query.sessionId) filters.sessionId = req.query.sessionId as string

        // State filter
        if (req.query.state) {
            const stateValue = req.query.state as string
            if (['INPROGRESS', 'FINISHED', 'ERROR', 'TERMINATED', 'TIMEOUT', 'STOPPED'].includes(stateValue)) {
                filters.state = stateValue as ExecutionState
            }
        }

        // Date filters
        if (req.query.startDate) {
            const startDateStr = req.query.startDate as string
            if (!isValidDateString(startDateStr)) {
                return res.status(400).json({ success: false, message: 'Invalid startDate format' })
            }
            filters.startDate = new Date(startDateStr)
        }

        if (req.query.endDate) {
            const endDateStr = req.query.endDate as string
            if (!isValidDateString(endDateStr)) {
                return res.status(400).json({ success: false, message: 'Invalid endDate format' })
            }
            filters.endDate = new Date(endDateStr)
        }

        // Pagination
        if (req.query.page) {
            filters.page = parseInt(req.query.page as string, 10)
        }

        if (req.query.limit) {
            filters.limit = parseInt(req.query.limit as string, 10)
        }

        const apiResponse = await executionsService.getAllExecutions(filters)

        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

/**
 * Delete multiple executions by their IDs
 * If a single ID is provided in the URL params, it will delete that execution
 * If an array of IDs is provided in the request body, it will delete all those executions
 */
const deleteExecutions = async (req: Request, res: Response, next: NextFunction) => {
    try {
        let executionIds: string[] = []
        const workspaceId = req.user?.activeWorkspaceId

        // Check if we're deleting a single execution from URL param
        if (req.params.id) {
            if (!isValidUUID(req.params.id)) {
                return res.status(400).json({ success: false, message: 'Invalid execution ID format' })
            }
            executionIds = [req.params.id]
        }
        // Check if we're deleting multiple executions from request body
        else if (req.body.executionIds && Array.isArray(req.body.executionIds)) {
            const ids = req.body.executionIds
            for (const id of ids) {
                if (typeof id !== 'string' || !isValidUUID(id)) {
                    return res.status(400).json({ success: false, message: `Invalid execution ID format: ${id}` })
                }
            }
            executionIds = ids
        } else {
            return res.status(400).json({ success: false, message: 'No execution IDs provided' })
        }

        const result = await executionsService.deleteExecutions(executionIds, workspaceId)
        return res.json(result)
    } catch (error) {
        next(error)
    }
}

export default {
    getAllExecutions,
    deleteExecutions,
    getExecutionById,
    getPublicExecutionById,
    updateExecution
}
import { NextFunction, Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import mcpServerService from '../../services/mcp-server'

const ALLOWED_ID_PATTERN = /^[a-zA-Z0-9_\-]+$/

const sanitizeId = (id: string): string => {
    const trimmed = (id || '').trim()
    if (!trimmed || !ALLOWED_ID_PATTERN.test(trimmed)) {
        throw new Error('Invalid id format')
    }
    return trimmed
}

const KNOWN_BODY_KEYS = ['name', 'description', 'type', 'config', 'url', 'token', 'enabled', 'settings', 'metadata']

const sanitizeBody = (body: Record<string, any>): Record<string, any> => {
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        return {}
    }
    const sanitized: Record<string, any> = {}
    for (const key of KNOWN_BODY_KEYS) {
        if (Object.prototype.hasOwnProperty.call(body, key)) {
            const val = body[key]
            if (typeof val === 'string') {
                sanitized[key] = val.trim()
            } else if (typeof val === 'boolean' || typeof val === 'number') {
                sanitized[key] = val
            } else if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
                sanitized[key] = val
            } else if (Array.isArray(val)) {
                sanitized[key] = val
            }
        }
    }
    return sanitized
}

const sanitizeResponse = (data: any): any => {
    if (data === null || data === undefined) {
        return data
    }
    if (typeof data === 'string' || typeof data === 'number' || typeof data === 'boolean') {
        return data
    }
    if (Array.isArray(data)) {
        return data.map(sanitizeResponse)
    }
    if (typeof data === 'object') {
        const plain: Record<string, any> = {}
        for (const key of Object.keys(data)) {
            const val = data[key]
            if (typeof val === 'function') continue
            plain[key] = sanitizeResponse(val)
        }
        return plain
    }
    return null
}

const getMcpServerConfig = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                'Error: mcpServerController.getMcpServerConfig - id not provided!'
            )
        }
        const sanitizedId = sanitizeId(req.params.id)
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, 'Error: mcpServerController.getMcpServerConfig - workspace not found!')
        }
        console.log(`[mcpServer] getMcpServerConfig - calling service with id: ${sanitizedId}, workspaceId: ${workspaceId}`)
        const apiResponse = await mcpServerService.getMcpServerConfig(sanitizedId, workspaceId)
        console.log(`[mcpServer] getMcpServerConfig - service call completed for id: ${sanitizedId}`)
        return res.json(sanitizeResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const createMcpServerConfig = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                'Error: mcpServerController.createMcpServerConfig - id not provided!'
            )
        }
        const sanitizedId = sanitizeId(req.params.id)
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, 'Error: mcpServerController.createMcpServerConfig - workspace not found!')
        }
        const sanitizedBody = sanitizeBody(req.body || {})
        console.log(`[mcpServer] createMcpServerConfig - calling service with id: ${sanitizedId}, workspaceId: ${workspaceId}`)
        const apiResponse = await mcpServerService.createMcpServerConfig(sanitizedId, workspaceId, sanitizedBody)
        console.log(`[mcpServer] createMcpServerConfig - service call completed for id: ${sanitizedId}`)
        return res.status(StatusCodes.CREATED).json(sanitizeResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const updateMcpServerConfig = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                'Error: mcpServerController.updateMcpServerConfig - id not provided!'
            )
        }
        const sanitizedId = sanitizeId(req.params.id)
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, 'Error: mcpServerController.updateMcpServerConfig - workspace not found!')
        }
        const sanitizedBody = sanitizeBody(req.body || {})
        console.log(`[mcpServer] updateMcpServerConfig - calling service with id: ${sanitizedId}, workspaceId: ${workspaceId}`)
        const apiResponse = await mcpServerService.updateMcpServerConfig(sanitizedId, workspaceId, sanitizedBody)
        console.log(`[mcpServer] updateMcpServerConfig - service call completed for id: ${sanitizedId}`)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const deleteMcpServerConfig = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                'Error: mcpServerController.deleteMcpServerConfig - id not provided!'
            )
        }
        const sanitizedId = sanitizeId(req.params.id)
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, 'Error: mcpServerController.deleteMcpServerConfig - workspace not found!')
        }
        console.log(`[mcpServer] deleteMcpServerConfig - calling service with id: ${sanitizedId}, workspaceId: ${workspaceId}`)
        await mcpServerService.deleteMcpServerConfig(sanitizedId, workspaceId)
        console.log(`[mcpServer] deleteMcpServerConfig - service call completed for id: ${sanitizedId}`)
        return res.json({ message: 'MCP server config disabled' })
    } catch (error) {
        next(error)
    }
}

const refreshMcpToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.params.id) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, 'Error: mcpServerController.refreshMcpToken - id not provided!')
        }
        const sanitizedId = sanitizeId(req.params.id)
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, 'Error: mcpServerController.refreshMcpToken - workspace not found!')
        }
        console.log(`[mcpServer] refreshMcpToken - calling service with id: ${sanitizedId}, workspaceId: ${workspaceId}`)
        const apiResponse = await mcpServerService.refreshMcpToken(sanitizedId, workspaceId)
        console.log(`[mcpServer] refreshMcpToken - service call completed for id: ${sanitizedId}`)
        return res.json(sanitizeResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

export default {
    getMcpServerConfig,
    createMcpServerConfig,
    updateMcpServerConfig,
    deleteMcpServerConfig,
    refreshMcpToken
}
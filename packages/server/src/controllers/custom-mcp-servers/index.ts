import { NextFunction, Request, Response } from 'express'
import { StatusCodes } from 'http-status-codes'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { CustomMcpServerAuthType } from '../../Interface'
import customMcpServersService from '../../services/custom-mcp-servers'
import { getPageAndLimitParams } from '../../utils/pagination'

const MAX_PAGE_LIMIT = 500
const DEFAULT_PAGE = 1
const DEFAULT_LIMIT = 50

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const PROTOTYPE_POLLUTION_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

const assertValidUuid = (id: unknown, endpoint: string): void => {
    if (typeof id !== 'string' || !UUID_REGEX.test(id)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `Error: customMcpServersController.${endpoint} - invalid id format "${String(id)}"`
        )
    }
}

const assertValidStringField = (value: unknown, fieldName: string, endpoint: string, maxLength = 2048): void => {
    if (value === undefined) return
    if (typeof value !== 'string') {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `Error: customMcpServersController.${endpoint} - field "${fieldName}" must be a string`
        )
    }
    if (value.length > maxLength) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `Error: customMcpServersController.${endpoint} - field "${fieldName}" exceeds maximum length of ${maxLength}`
        )
    }
}

const assertValidAuthConfig = (authConfig: unknown, endpoint: string): void => {
    if (authConfig === undefined) return
    if (typeof authConfig !== 'object' || authConfig === null || Array.isArray(authConfig)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `Error: customMcpServersController.${endpoint} - authConfig must be a plain object`
        )
    }
    for (const key of Object.keys(authConfig as object)) {
        if (PROTOTYPE_POLLUTION_KEYS.has(key)) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: customMcpServersController.${endpoint} - authConfig contains forbidden key "${key}"`
            )
        }
    }
}

const assertValidAuthType = (authType: unknown, endpoint: string): void => {
    if (authType === undefined) return
    const allowed = Object.values(CustomMcpServerAuthType) as string[]
    if (typeof authType !== 'string' || !allowed.includes(authType)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            `Error: customMcpServersController.${endpoint} - invalid authType "${String(authType)}"`
        )
    }
}

const sanitizeMcpResponse = (apiResponse: unknown): unknown => {
    if (apiResponse === null || (typeof apiResponse !== 'object' && !Array.isArray(apiResponse))) {
        throw new InternalFlowiseError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            `Error: customMcpServersController - invalid response type from service`
        )
    }

    const stripPollutionKeys = (obj: unknown): unknown => {
        if (Array.isArray(obj)) {
            return obj.map(stripPollutionKeys)
        }
        if (obj !== null && typeof obj === 'object') {
            const cleaned: Record<string, unknown> = {}
            for (const key of Object.keys(obj as object)) {
                if (!PROTOTYPE_POLLUTION_KEYS.has(key)) {
                    cleaned[key] = stripPollutionKeys((obj as Record<string, unknown>)[key])
                }
            }
            return cleaned
        }
        return obj
    }

    const stripped = stripPollutionKeys(apiResponse)

    try {
        JSON.stringify(stripped)
    } catch {
        throw new InternalFlowiseError(
            StatusCodes.INTERNAL_SERVER_ERROR,
            `Error: customMcpServersController - service response is not JSON-serializable`
        )
    }

    return stripped
}

const createCustomMcpServer = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: customMcpServersController.createCustomMcpServer - body not provided!`
            )
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.createCustomMcpServer - organization not found!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.createCustomMcpServer - workspace not found!`
            )
        }
        const body = req.body
        assertValidAuthType(body.authType, 'createCustomMcpServer')
        assertValidStringField(body.name, 'name', 'createCustomMcpServer', 512)
        assertValidStringField(body.serverUrl, 'serverUrl', 'createCustomMcpServer', 2048)
        assertValidStringField(body.iconSrc, 'iconSrc', 'createCustomMcpServer', 2048)
        assertValidStringField(body.color, 'color', 'createCustomMcpServer', 64)
        assertValidAuthConfig(body.authConfig, 'createCustomMcpServer')
        // Explicit allowlist — id/workspaceId/timestamps must not be overrideable by client
        const mcpBody: Record<string, unknown> = {}
        if (body.name !== undefined) mcpBody.name = body.name
        if (body.serverUrl !== undefined) mcpBody.serverUrl = body.serverUrl
        if (body.iconSrc !== undefined) mcpBody.iconSrc = body.iconSrc
        if (body.color !== undefined) mcpBody.color = body.color
        if (body.authType !== undefined) mcpBody.authType = body.authType
        if (body.authConfig !== undefined) mcpBody.authConfig = body.authConfig
        mcpBody.workspaceId = workspaceId

        console.log(`[customMcpServersController] createCustomMcpServer - calling service with workspaceId: ${workspaceId}, orgId: ${orgId}`)
        const apiResponse = await customMcpServersService.createCustomMcpServer(mcpBody, orgId)
        console.log(`[customMcpServersController] createCustomMcpServer - service response:`, apiResponse)
        return res.json(sanitizeMcpResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const getAllCustomMcpServers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.getAllCustomMcpServers - workspace not found!`
            )
        }
        const raw = getPageAndLimitParams(req)
        const page = raw.page > 0 ? raw.page : DEFAULT_PAGE
        const limit = raw.limit > 0 ? Math.min(raw.limit, MAX_PAGE_LIMIT) : DEFAULT_LIMIT
        console.log(`[customMcpServersController] getAllCustomMcpServers - calling service with workspaceId: ${workspaceId}, page: ${page}, limit: ${limit}`)
        const apiResponse = await customMcpServersService.getAllCustomMcpServers(workspaceId, page, limit)
        console.log(`[customMcpServersController] getAllCustomMcpServers - service response:`, apiResponse)
        return res.json(sanitizeMcpResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const getCustomMcpServerById = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: customMcpServersController.getCustomMcpServerById - id not provided!`
            )
        }
        assertValidUuid(req.params.id, 'getCustomMcpServerById')
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.getCustomMcpServerById - workspace not found!`
            )
        }
        console.log(`[customMcpServersController] getCustomMcpServerById - calling service with id: ${req.params.id}, workspaceId: ${workspaceId}`)
        const apiResponse = await customMcpServersService.getCustomMcpServerById(req.params.id, workspaceId)
        console.log(`[customMcpServersController] getCustomMcpServerById - service response:`, apiResponse)
        return res.json(sanitizeMcpResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const updateCustomMcpServer = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: customMcpServersController.updateCustomMcpServer - id not provided!`
            )
        }
        assertValidUuid(req.params.id, 'updateCustomMcpServer')
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: customMcpServersController.updateCustomMcpServer - body not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.updateCustomMcpServer - workspace not found!`
            )
        }
        const body = req.body
        assertValidAuthType(body.authType, 'updateCustomMcpServer')
        assertValidStringField(body.name, 'name', 'updateCustomMcpServer', 512)
        assertValidStringField(body.serverUrl, 'serverUrl', 'updateCustomMcpServer', 2048)
        assertValidStringField(body.iconSrc, 'iconSrc', 'updateCustomMcpServer', 2048)
        assertValidStringField(body.color, 'color', 'updateCustomMcpServer', 64)
        assertValidAuthConfig(body.authConfig, 'updateCustomMcpServer')
        // Explicit allowlist
        const mcpBody: Record<string, unknown> = {}
        if (body.name !== undefined) mcpBody.name = body.name
        if (body.serverUrl !== undefined) mcpBody.serverUrl = body.serverUrl
        if (body.iconSrc !== undefined) mcpBody.iconSrc = body.iconSrc
        if (body.color !== undefined) mcpBody.color = body.color
        if (body.authType !== undefined) mcpBody.authType = body.authType
        if (body.authConfig !== undefined) mcpBody.authConfig = body.authConfig

        console.log(`[customMcpServersController] updateCustomMcpServer - calling service with id: ${req.params.id}, workspaceId: ${workspaceId}`)
        const apiResponse = await customMcpServersService.updateCustomMcpServer(req.params.id, mcpBody, workspaceId)
        console.log(`[customMcpServersController] updateCustomMcpServer - service response:`, apiResponse)
        return res.json(sanitizeMcpResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const deleteCustomMcpServer = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: customMcpServersController.deleteCustomMcpServer - id not provided!`
            )
        }
        assertValidUuid(req.params.id, 'deleteCustomMcpServer')
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.deleteCustomMcpServer - workspace not found!`
            )
        }
        console.log(`[customMcpServersController] deleteCustomMcpServer - calling service with id: ${req.params.id}, workspaceId: ${workspaceId}`)
        const apiResponse = await customMcpServersService.deleteCustomMcpServer(req.params.id, workspaceId)
        console.log(`[customMcpServersController] deleteCustomMcpServer - service response:`, apiResponse)
        return res.json(sanitizeMcpResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const authorizeCustomMcpServer = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: customMcpServersController.authorizeCustomMcpServer - id not provided!`
            )
        }
        assertValidUuid(req.params.id, 'authorizeCustomMcpServer')
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.authorizeCustomMcpServer - workspace not found!`
            )
        }
        console.log(`[customMcpServersController] authorizeCustomMcpServer - calling service with id: ${req.params.id}, workspaceId: ${workspaceId}`)
        const apiResponse = await customMcpServersService.authorizeCustomMcpServer(req.params.id, workspaceId)
        console.log(`[customMcpServersController] authorizeCustomMcpServer - service response:`, apiResponse)
        return res.json(sanitizeMcpResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const getDiscoveredTools = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: customMcpServersController.getDiscoveredTools - id not provided!`
            )
        }
        assertValidUuid(req.params.id, 'getDiscoveredTools')
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.getDiscoveredTools - workspace not found!`
            )
        }

        // Fetch the MCP server configuration and verify authentication before connecting
        const serverConfig = await customMcpServersService.getCustomMcpServerById(req.params.id, workspaceId)
        if (!serverConfig) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: customMcpServersController.getDiscoveredTools - MCP server not found!`
            )
        }
        const configObj = serverConfig as Record<string, unknown>
        if (!configObj.authType || !configObj.authConfig) {
            throw new InternalFlowiseError(
                StatusCodes.UNAUTHORIZED,
                `Error: customMcpServersController.getDiscoveredTools - MCP server does not have valid authentication credentials (authType and authConfig are required)`
            )
        }
        if (!configObj.isAuthorized && configObj.authType !== CustomMcpServerAuthType.None) {
            throw new InternalFlowiseError(
                StatusCodes.UNAUTHORIZED,
                `Error: customMcpServersController.getDiscoveredTools - MCP server has not been authorized`
            )
        }

        console.log(`[customMcpServersController] getDiscoveredTools - calling service with id: ${req.params.id}, workspaceId: ${workspaceId}`)
        const apiResponse = await customMcpServersService.getDiscoveredTools(req.params.id, workspaceId)
        console.log(`[customMcpServersController] getDiscoveredTools - service response:`, apiResponse)
        return res.json(sanitizeMcpResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

export default {
    createCustomMcpServer,
    getAllCustomMcpServers,
    getCustomMcpServerById,
    updateCustomMcpServer,
    deleteCustomMcpServer,
    authorizeCustomMcpServer,
    getDiscoveredTools
}
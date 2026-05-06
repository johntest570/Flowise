import client from './client'

// Input validation helpers
const isNonEmptyAlphanumeric = (id) => {
    return typeof id === 'string' && /^[a-zA-Z0-9_-]+$/.test(id) && id.trim().length > 0
}

const isPlainObject = (obj) => {
    return obj !== null && typeof obj === 'object' && !Array.isArray(obj) && Object.getPrototypeOf(obj) === Object.prototype
}

const isValidParams = (params) => {
    if (!isPlainObject(params)) return false
    return Object.values(params).every((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')
}

const sanitizeString = (str) => {
    if (typeof str !== 'string') return str
    return str.replace(/[<>"'`;]/g, '')
}

const sanitizeObject = (obj) => {
    if (typeof obj === 'string') return sanitizeString(obj)
    if (obj === null || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(sanitizeObject)
    const sanitized = {}
    for (const key of Object.keys(obj)) {
        sanitized[key] = sanitizeObject(obj[key])
    }
    return sanitized
}

const sanitizeParams = (params) => {
    if (!params) return params
    const sanitized = {}
    for (const key of Object.keys(params)) {
        const val = params[key]
        sanitized[key] = typeof val === 'string' ? sanitizeString(val) : val
    }
    return sanitized
}

// Output validation/sanitization helper
const validateAndSanitizeResponse = (response) => {
    if (response === null || response === undefined) return response
    if (typeof response === 'string') return sanitizeString(response)
    if (typeof response !== 'object') return response
    return sanitizeObject(response)
}

// Logging helper
const logInteraction = async (operation, params, fn) => {
    console.log(`[MCP] Request: ${operation}`, params)
    try {
        const result = await fn()
        console.log(`[MCP] Response: ${operation}`, result)
        return result
    } catch (error) {
        console.error(`[MCP] Error: ${operation}`, error)
        throw error
    }
}

const getAllCustomMcpServers = (params) => {
    if (params !== undefined && params !== null) {
        if (!isValidParams(params)) {
            throw new Error('Invalid params: must be a plain object with string/number/boolean values')
        }
    }
    const sanitizedParams = sanitizeParams(params)
    return logInteraction('getAllCustomMcpServers', { params: sanitizedParams }, async () => {
        const response = await client.get('/custom-mcp-servers', { params: sanitizedParams })
        return validateAndSanitizeResponse(response)
    })
}

const getCustomMcpServer = (id) => {
    return logInteraction('getCustomMcpServer', { id }, async () => {
        const response = await client.get(`/custom-mcp-servers/${id}`)
        return validateAndSanitizeResponse(response)
    })
}

const createCustomMcpServer = (body) => {
    if (!isPlainObject(body)) {
        throw new Error('Invalid body: must be a plain object')
    }
    const sanitizedBody = sanitizeObject(body)
    return logInteraction('createCustomMcpServer', { body: sanitizedBody }, async () => {
        const response = await client.post(`/custom-mcp-servers`, sanitizedBody)
        return validateAndSanitizeResponse(response)
    })
}

const updateCustomMcpServer = (id, body) => {
    if (!isPlainObject(body)) {
        throw new Error('Invalid body: must be a plain object')
    }
    const sanitizedBody = sanitizeObject(body)
    return logInteraction('updateCustomMcpServer', { id, body: sanitizedBody }, async () => {
        const response = await client.put(`/custom-mcp-servers/${id}`, sanitizedBody)
        return validateAndSanitizeResponse(response)
    })
}

const deleteCustomMcpServer = (id) => {
    return logInteraction('deleteCustomMcpServer', { id }, async () => {
        const response = await client.delete(`/custom-mcp-servers/${id}`)
        return validateAndSanitizeResponse(response)
    })
}

const authorizeCustomMcpServer = (id) => {
    if (!isNonEmptyAlphanumeric(id)) {
        throw new Error('Invalid id: must be a non-empty alphanumeric string')
    }
    return logInteraction('authorizeCustomMcpServer', { id }, async () => {
        const response = await client.post(`/custom-mcp-servers/${id}/authorize`)
        return validateAndSanitizeResponse(response)
    })
}

const getCustomMcpServerTools = (id) => {
    return logInteraction('getCustomMcpServerTools', { id }, async () => {
        const response = await client.get(`/custom-mcp-servers/${id}/tools`)
        return validateAndSanitizeResponse(response)
    })
}

export default {
    getAllCustomMcpServers,
    getCustomMcpServer,
    createCustomMcpServer,
    updateCustomMcpServer,
    deleteCustomMcpServer,
    authorizeCustomMcpServer,
    getCustomMcpServerTools
}
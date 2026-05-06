import client from './client'

// Validation and sanitization helpers
const SAFE_ID_PATTERN = /^[a-zA-Z0-9_-]+$/

const validateId = (id) => {
    if (id === null || id === undefined || String(id).trim() === '') {
        throw new Error('Invalid id: id must be a non-empty string or number')
    }
    const idStr = String(id)
    if (!SAFE_ID_PATTERN.test(idStr)) {
        throw new Error('Invalid id: id contains unsafe characters')
    }
    return idStr
}

const sanitizeBody = (body) => {
    if (body === null || body === undefined) {
        return body
    }
    if (typeof body !== 'object' || Array.isArray(body)) {
        throw new Error('Invalid body: body must be a plain object')
    }
    if (Object.getPrototypeOf(body) !== Object.prototype && Object.getPrototypeOf(body) !== null) {
        throw new Error('Invalid body: body must be a plain object without prototype pollution')
    }
    const sanitized = {}
    for (const key of Object.keys(body)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue
        }
        sanitized[key] = body[key]
    }
    return sanitized
}

const sanitizeResponse = (response) => {
    if (response === null || response === undefined) {
        throw new Error('Invalid response: response is null or undefined')
    }
    if (typeof response !== 'object') {
        return response
    }
    const sanitizeStringFields = (obj) => {
        if (obj === null || obj === undefined) return obj
        if (typeof obj === 'string') {
            return obj.replace(/</g, '&lt;').replace(/>/g, '&gt;')
        }
        if (Array.isArray(obj)) {
            return obj.map(sanitizeStringFields)
        }
        if (typeof obj === 'object') {
            const result = {}
            for (const key of Object.keys(obj)) {
                result[key] = sanitizeStringFields(obj[key])
            }
            return result
        }
        return obj
    }
    return sanitizeStringFields(response)
}

const getMcpServerConfig = async (id) => {
    const validatedId = validateId(id)
    console.log('[mcpserver] getMcpServerConfig called', { id: validatedId })
    try {
        const response = await client.get(`/mcp-server/${validatedId}`)
        const sanitized = sanitizeResponse(response)
        console.log('[mcpserver] getMcpServerConfig response', { id: validatedId, response: sanitized })
        return sanitized
    } catch (error) {
        console.log('[mcpserver] getMcpServerConfig error', { id: validatedId, error })
        throw error
    }
}

const createMcpServerConfig = async (id, body) => {
    const validatedId = validateId(id)
    const sanitizedBody = sanitizeBody(body)
    console.log('[mcpserver] createMcpServerConfig called', { id: validatedId, body: sanitizedBody })
    try {
        const response = await client.post(`/mcp-server/${validatedId}`, sanitizedBody)
        const sanitized = sanitizeResponse(response)
        console.log('[mcpserver] createMcpServerConfig response', { id: validatedId, response: sanitized })
        return sanitized
    } catch (error) {
        console.log('[mcpserver] createMcpServerConfig error', { id: validatedId, error })
        throw error
    }
}

const updateMcpServerConfig = async (id, body) => {
    const validatedId = validateId(id)
    const sanitizedBody = sanitizeBody(body)
    console.log('[mcpserver] updateMcpServerConfig called', { id: validatedId, body: sanitizedBody })
    try {
        const response = await client.put(`/mcp-server/${validatedId}`, sanitizedBody)
        const sanitized = sanitizeResponse(response)
        console.log('[mcpserver] updateMcpServerConfig response', { id: validatedId, response: sanitized })
        return sanitized
    } catch (error) {
        console.log('[mcpserver] updateMcpServerConfig error', { id: validatedId, error })
        throw error
    }
}

const deleteMcpServerConfig = async (id) => {
    const validatedId = validateId(id)
    console.log('[mcpserver] deleteMcpServerConfig called', { id: validatedId })
    try {
        const response = await client.delete(`/mcp-server/${validatedId}`)
        const sanitized = sanitizeResponse(response)
        console.log('[mcpserver] deleteMcpServerConfig response', { id: validatedId, response: sanitized })
        return sanitized
    } catch (error) {
        console.log('[mcpserver] deleteMcpServerConfig error', { id: validatedId, error })
        throw error
    }
}

const refreshMcpToken = async (id) => {
    const validatedId = validateId(id)
    console.log('[mcpserver] refreshMcpToken called', { id: validatedId })
    try {
        const response = await client.post(`/mcp-server/${validatedId}/refresh`)
        const sanitized = sanitizeResponse(response)
        console.log('[mcpserver] refreshMcpToken response', { id: validatedId, response: sanitized })
        return sanitized
    } catch (error) {
        console.log('[mcpserver] refreshMcpToken error', { id: validatedId, error })
        throw error
    }
}

export default {
    getMcpServerConfig,
    createMcpServerConfig,
    updateMcpServerConfig,
    deleteMcpServerConfig,
    refreshMcpToken
}
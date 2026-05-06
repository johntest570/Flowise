import client from './client'

const sanitizeBody = (body) => {
    if (body === null || body === undefined) {
        throw new Error('Invalid input: body cannot be null or undefined')
    }
    if (typeof body !== 'object' || Array.isArray(body) || body.constructor !== Object) {
        throw new Error('Invalid input: body must be a plain object')
    }
    const sanitized = {}
    for (const key of Object.keys(body)) {
        const value = body[key]
        if (typeof value === 'string') {
            sanitized[key] = value.trim().replace(/[<>]/g, '')
        } else {
            sanitized[key] = value
        }
    }
    return sanitized
}

const getAvailablePrompts = (body) => client.post(`/prompts-list`, sanitizeBody(body))
const getPrompt = (body) => client.post(`/load-prompt`, sanitizeBody(body))

export default {
    getAvailablePrompts,
    getPrompt
}
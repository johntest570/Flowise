import client from './client'

const MAX_INPUT_LENGTH = 100000

const sanitizeAndValidateInput = (input) => {
    if (input === null || input === undefined) {
        throw new Error('Input cannot be null or undefined')
    }

    if (typeof input === 'string') {
        if (input.trim().length === 0) {
            throw new Error('Input cannot be an empty string')
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new Error(`Input exceeds maximum allowed length of ${MAX_INPUT_LENGTH} characters`)
        }
        const sanitized = input
            .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
            .replace(/<[^>]+>/g, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+\s*=/gi, '')
        return sanitized
    }

    if (typeof input === 'object' && !Array.isArray(input)) {
        const serialized = JSON.stringify(input)
        if (serialized.length > MAX_INPUT_LENGTH) {
            throw new Error(`Input exceeds maximum allowed length of ${MAX_INPUT_LENGTH} characters`)
        }
        return input
    }

    throw new Error('Input must be a non-empty string or a plain object')
}

const sendMessageAndGetPrediction = (id, input) => {
    const sanitizedInput = sanitizeAndValidateInput(input)
    return client.post(`/internal-prediction/${id}`, sanitizedInput)
}

const sendMessageAndStreamPrediction = (id, input) => {
    const sanitizedInput = sanitizeAndValidateInput(input)
    return client.post(`/internal-prediction/stream/${id}`, sanitizedInput)
}

const sendMessageAndGetPredictionPublic = (id, input) => {
    const sanitizedInput = sanitizeAndValidateInput(input)
    return client.post(`/prediction/${id}`, sanitizedInput)
}

export default {
    sendMessageAndGetPrediction,
    sendMessageAndStreamPrediction,
    sendMessageAndGetPredictionPublic
}
import { Request, Response, NextFunction } from 'express'
import { RateLimiterManager } from '../../utils/rateLimit'
import chatflowsService from '../../services/chatflows'
import logger from '../../utils/logger'
import predictionsServices from '../../services/predictions'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'
import { getRunningExpressApp } from '../../utils/getRunningExpressApp'
import { v4 as uuidv4 } from 'uuid'
import { getErrorMessage } from '../../errors/utils'
import { MODE } from '../../Interface'

// Sanitization helper: strips special characters and validates types for ID fields
const sanitizeId = (id: any): string => {
    if (typeof id !== 'string') return ''
    // Allow only alphanumeric characters, hyphens, and underscores
    return id.replace(/[^a-zA-Z0-9\-_]/g, '').slice(0, 256)
}

// Sanitization helper: strips dangerous characters and enforces length limits on string fields
const sanitizeString = (value: any, maxLength: number = 10000): string => {
    if (typeof value !== 'string') return ''
    // Remove null bytes and control characters except common whitespace
    return value.replace(/\0/g, '').slice(0, maxLength)
}

// Sanitization helper: validates streaming field
const sanitizeStreaming = (value: any): boolean | string => {
    if (value === 'true' || value === true) return true
    if (value === 'false' || value === false) return false
    return false
}

// Sanitization helper: sanitizes overrideConfig object
const sanitizeOverrideConfig = (config: any): any => {
    if (config === null || config === undefined) return config
    if (typeof config !== 'object' || Array.isArray(config)) return {}
    const sanitized: Record<string, any> = {}
    for (const key of Object.keys(config)) {
        const sanitizedKey = sanitizeString(key, 256)
        const val = config[key]
        if (typeof val === 'string') {
            sanitized[sanitizedKey] = sanitizeString(val, 10000)
        } else if (typeof val === 'number' || typeof val === 'boolean') {
            sanitized[sanitizedKey] = val
        } else if (typeof val === 'object' && val !== null) {
            sanitized[sanitizedKey] = sanitizeOverrideConfig(val)
        } else {
            sanitized[sanitizedKey] = val
        }
    }
    return sanitized
}

// Sanitization helper: sanitizes uploads array
const sanitizeUploads = (uploads: any): any[] => {
    if (!Array.isArray(uploads)) return []
    return uploads.slice(0, 100).map((upload: any) => {
        if (typeof upload !== 'object' || upload === null) return upload
        const sanitized: Record<string, any> = {}
        for (const key of Object.keys(upload)) {
            const val = upload[key]
            if (typeof val === 'string') {
                sanitized[key] = sanitizeString(val, 10000)
            } else {
                sanitized[key] = val
            }
        }
        return sanitized
    })
}

// Sanitization helper: sanitizes history array
const sanitizeHistory = (history: any): any[] => {
    if (!Array.isArray(history)) return []
    return history.slice(0, 1000).map((item: any) => {
        if (typeof item !== 'object' || item === null) return item
        const sanitized: Record<string, any> = {}
        for (const key of Object.keys(item)) {
            const val = item[key]
            if (typeof val === 'string') {
                sanitized[key] = sanitizeString(val, 10000)
            } else {
                sanitized[key] = val
            }
        }
        return sanitized
    })
}

// Dynamic code execution primitives to check in LLM output
const DANGEROUS_CODE_PATTERNS = [
    /\beval\s*\(/gi,
    /\bexec\s*\(/gi,
    /\bsubprocess\b/gi,
    /\bFunction\s*\(/gi,
    /\bnew\s+Function\b/gi,
    /\bsetTimeout\s*\(\s*["'`]/gi,
    /\bsetInterval\s*\(\s*["'`]/gi,
    /\bexecSync\s*\(/gi,
    /\bspawnSync\s*\(/gi,
    /\bspawn\s*\(/gi,
    /\bexecFile\s*\(/gi,
    /\brequire\s*\(\s*["'`]child_process/gi,
    /\bimport\s*\(\s*["'`]child_process/gi,
    /\b__import__\s*\(/gi,
    /\bos\.system\s*\(/gi,
    /\bos\.popen\s*\(/gi,
]

// Sanitize/validate LLM output for dangerous code execution primitives
const sanitizeLLMOutput = (response: any): any => {
    if (response === null || response === undefined) return response
    if (typeof response === 'string') {
        for (const pattern of DANGEROUS_CODE_PATTERNS) {
            if (pattern.test(response)) {
                logger.warn(`[server]: Dangerous code execution primitive detected in LLM output, sanitizing response.`)
                return response.replace(pattern, '[REDACTED]')
            }
        }
        return response
    }
    if (Array.isArray(response)) {
        return response.map(sanitizeLLMOutput)
    }
    if (typeof response === 'object') {
        const sanitized: Record<string, any> = {}
        for (const key of Object.keys(response)) {
            sanitized[key] = sanitizeLLMOutput(response[key])
        }
        return sanitized
    }
    return response
}

// Send input message and get prediction result (External)
const createPrediction = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: predictionsController.createPrediction - id not provided!`
            )
        }
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: predictionsController.createPrediction - body not provided!`
            )
        }

        // Sanitize req.params.id before use
        const sanitizedId = sanitizeId(req.params.id)
        if (!sanitizedId) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: predictionsController.createPrediction - invalid id provided!`
            )
        }
        req.params.id = sanitizedId

        // Sanitize req.body fields before use
        if (req.body.chatId !== undefined) {
            req.body.chatId = sanitizeId(req.body.chatId)
        }
        if (req.body.streaming !== undefined) {
            req.body.streaming = sanitizeStreaming(req.body.streaming)
        }
        if (req.body.overrideConfig !== undefined) {
            req.body.overrideConfig = sanitizeOverrideConfig(req.body.overrideConfig)
        }
        if (req.body.question !== undefined) {
            req.body.question = sanitizeString(req.body.question, 10000)
        }
        if (req.body.uploads !== undefined) {
            req.body.uploads = sanitizeUploads(req.body.uploads)
        }
        if (req.body.history !== undefined) {
            req.body.history = sanitizeHistory(req.body.history)
        }

        const workspaceId = req.user?.activeWorkspaceId

        const chatflow = await chatflowsService.getChatflowById(req.params.id, workspaceId)
        if (!chatflow) {
            throw new InternalFlowiseError(StatusCodes.NOT_FOUND, `Chatflow ${req.params.id} not found`)
        }
        let isDomainAllowed = true
        let unauthorizedOriginError = 'This site is not allowed to access this chatbot'
        logger.info(`[server]: Request originated from ${req.headers.origin || 'UNKNOWN ORIGIN'}`)
        if (chatflow.chatbotConfig) {
            const parsedConfig = JSON.parse(chatflow.chatbotConfig)
            // check whether the first one is not empty. if it is empty that means the user set a value and then removed it.
            const isValidAllowedOrigins = parsedConfig.allowedOrigins?.length && parsedConfig.allowedOrigins[0] !== ''
            unauthorizedOriginError = parsedConfig.allowedOriginsError || 'This site is not allowed to access this chatbot'
            if (isValidAllowedOrigins && req.headers.origin) {
                const originHeader = req.headers.origin
                const origin = new URL(originHeader).host
                isDomainAllowed =
                    parsedConfig.allowedOrigins.filter((domain: string) => {
                        try {
                            const allowedOrigin = new URL(domain).host
                            return origin === allowedOrigin
                        } catch (e) {
                            return false
                        }
                    }).length > 0
            }
        }
        if (isDomainAllowed) {
            const streamable = await chatflowsService.checkIfChatflowIsValidForStreaming(req.params.id)
            const isStreamingRequested = req.body.streaming === 'true' || req.body.streaming === true
            if (streamable?.isStreaming && isStreamingRequested) {
                const sseStreamer = getRunningExpressApp().sseStreamer

                let chatId = req.body.chatId
                if (!req.body.chatId) {
                    chatId = req.body.chatId ?? req.body.overrideConfig?.sessionId ?? uuidv4()
                    chatId = sanitizeId(chatId)
                    req.body.chatId = chatId
                }
                const isQueueMode = process.env.MODE === MODE.QUEUE
                try {
                    sseStreamer.addExternalClient(chatId, res)
                    res.setHeader('Content-Type', 'text/event-stream')
                    res.setHeader('Cache-Control', 'no-cache')
                    res.setHeader('Connection', 'keep-alive')
                    res.setHeader('X-Accel-Buffering', 'no') //nginx config: https://serverfault.com/a/801629
                    res.flushHeaders()

                    if (isQueueMode) {
                        await getRunningExpressApp().redisSubscriber.subscribe(chatId)
                    }

                    const apiResponse = await predictionsServices.buildChatflow(req)
                    const sanitizedApiResponse = sanitizeLLMOutput(apiResponse)
                    sseStreamer.streamMetadataEvent(sanitizedApiResponse.chatId, sanitizedApiResponse)
                } catch (error) {
                    if (chatId) {
                        sseStreamer.streamErrorEvent(chatId, getErrorMessage(error))
                    }
                    next(error)
                } finally {
                    if (isQueueMode && chatId) {
                        await getRunningExpressApp().redisSubscriber.unsubscribe(chatId)
                    }
                    sseStreamer.removeClient(chatId)
                }
            } else {
                const apiResponse = await predictionsServices.buildChatflow(req)
                const sanitizedApiResponse = sanitizeLLMOutput(apiResponse)
                return res.json(sanitizedApiResponse)
            }
        } else {
            const isStreamingRequested = req.body.streaming === 'true' || req.body.streaming === true
            if (isStreamingRequested) {
                return res.status(StatusCodes.FORBIDDEN).send(unauthorizedOriginError)
            }
            throw new InternalFlowiseError(StatusCodes.FORBIDDEN, unauthorizedOriginError)
        }
    } catch (error) {
        next(error)
    }
}

const getRateLimiterMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    try {
        return RateLimiterManager.getInstance().getRateLimiter()(req, res, next)
    } catch (error) {
        next(error)
    }
}

export default {
    createPrediction,
    getRateLimiterMiddleware
}
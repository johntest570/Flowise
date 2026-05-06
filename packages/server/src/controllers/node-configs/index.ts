import { Request, Response, NextFunction } from 'express'
import nodeConfigsService from '../../services/node-configs'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'

const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype']

const sanitizeString = (value: string): string => {
    return value.trim().replace(/[<>]/g, '')
}

const sanitizeObject = (obj: Record<string, any>): Record<string, any> => {
    const sanitized: Record<string, any> = {}
    for (const key of Object.keys(obj)) {
        if (DANGEROUS_KEYS.includes(key)) continue
        const value = obj[key]
        if (typeof value === 'string') {
            sanitized[key] = sanitizeString(value)
        } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
            sanitized[key] = sanitizeObject(value)
        } else {
            sanitized[key] = value
        }
    }
    return sanitized
}

const validateAndSanitizeBody = (body: any): Record<string, any> => {
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, 'Invalid request body: must be a plain object')
    }
    for (const key of Object.keys(body)) {
        if (DANGEROUS_KEYS.includes(key)) {
            throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, `Invalid request body: disallowed key "${key}"`)
        }
    }
    return sanitizeObject(body)
}

const getAllNodeConfigs = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: nodeConfigsController.getAllNodeConfigs - body not provided!`
            )
        }
        const sanitizedBody = validateAndSanitizeBody(req.body)
        const apiResponse = await nodeConfigsService.getAllNodeConfigs(sanitizedBody)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    getAllNodeConfigs
}
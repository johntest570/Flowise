import { Request, Response, NextFunction } from 'express'
import componentsCredentialsService from '../../services/components-credentials'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'

const MAX_NAME_LENGTH = 100
const VALID_NAME_REGEX = /^[a-zA-Z0-9_-]+$/

const sanitizeName = (name: string): string => {
    const truncated = name.substring(0, MAX_NAME_LENGTH)
    return truncated.replace(/[^a-zA-Z0-9_-]/g, '')
}

const isValidName = (name: string): boolean => {
    return VALID_NAME_REGEX.test(name) && name.length <= MAX_NAME_LENGTH
}

// Get all component credentials
const getAllComponentsCredentials = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const apiResponse = await componentsCredentialsService.getAllComponentsCredentials()
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

// Get component credential via name
const getComponentByName = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.name) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: componentsCredentialsController.getComponentByName - name not provided!`
            )
        }
        const sanitized = sanitizeName(req.params.name)
        if (!sanitized || !isValidName(sanitized)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: componentsCredentialsController.getComponentByName - invalid name format!`
            )
        }
        const apiResponse = await componentsCredentialsService.getComponentByName(sanitized)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

// Returns specific component credential icon via name
const getSingleComponentsCredentialIcon = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.name) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: componentsCredentialsController.getSingleComponentsCredentialIcon - name not provided!`
            )
        }
        const sanitized = sanitizeName(req.params.name)
        if (!sanitized || !isValidName(sanitized)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: componentsCredentialsController.getSingleComponentsCredentialIcon - invalid name format!`
            )
        }
        const apiResponse = await componentsCredentialsService.getSingleComponentsCredentialIcon(sanitized)
        return res.sendFile(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    getAllComponentsCredentials,
    getComponentByName,
    getSingleComponentsCredentialIcon
}
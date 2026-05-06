import { Request, Response, NextFunction } from 'express'
import loadPromptsService from '../../services/load-prompts'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'

const MAX_PROMPT_NAME_LENGTH = 100

const createPrompt = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined' || !req.body.promptName) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: loadPromptsController.createPrompt - promptName not provided!`
            )
        }
        if (typeof req.body.promptName !== 'string') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: loadPromptsController.createPrompt - promptName must be a string!`
            )
        }
        let sanitizedPromptName = req.body.promptName.trim()
        if (sanitizedPromptName.length > MAX_PROMPT_NAME_LENGTH) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: loadPromptsController.createPrompt - promptName exceeds maximum length of ${MAX_PROMPT_NAME_LENGTH}!`
            )
        }
        sanitizedPromptName = sanitizedPromptName.replace(/[^a-zA-Z0-9 \-_]/g, '')
        if (!sanitizedPromptName) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: loadPromptsController.createPrompt - promptName contains invalid characters!`
            )
        }
        const apiResponse = await loadPromptsService.createPrompt(sanitizedPromptName)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    createPrompt
}
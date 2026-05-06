import { Request, Response, NextFunction } from 'express'
import fetchLinksService from '../../services/fetch-links'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'

const ALLOWED_RELATIVE_LINKS_METHODS = ['web-crawl', 'html-only', 'all-links']
const MIN_LIMIT = 1
const MAX_LIMIT = 1000

const isValidHttpUrl = (value: string): boolean => {
    try {
        const parsed = new URL(value)
        return parsed.protocol === 'http:' || parsed.protocol === 'https:'
    } catch {
        return false
    }
}

const getAllLinks = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.query === 'undefined' || !req.query.url) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, `Error: fetchLinksController.getAllLinks - url not provided!`)
        }
        if (typeof req.query === 'undefined' || !req.query.relativeLinksMethod) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: fetchLinksController.getAllLinks - relativeLinksMethod not provided!`
            )
        }
        if (typeof req.query === 'undefined' || !req.query.limit) {
            throw new InternalFlowiseError(StatusCodes.PRECONDITION_FAILED, `Error: fetchLinksController.getAllLinks - limit not provided!`)
        }

        const rawUrl = req.query.url as string
        if (!isValidHttpUrl(rawUrl)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: fetchLinksController.getAllLinks - url must be a well-formed HTTP or HTTPS URL!`
            )
        }

        const rawRelativeLinksMethod = req.query.relativeLinksMethod as string
        if (!ALLOWED_RELATIVE_LINKS_METHODS.includes(rawRelativeLinksMethod)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: fetchLinksController.getAllLinks - relativeLinksMethod must be one of: ${ALLOWED_RELATIVE_LINKS_METHODS.join(', ')}!`
            )
        }

        const rawLimit = req.query.limit as string
        if (!/^\d+$/.test(rawLimit)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: fetchLinksController.getAllLinks - limit must be a valid integer!`
            )
        }
        const limitNumber = parseInt(rawLimit, 10)
        if (isNaN(limitNumber) || limitNumber < MIN_LIMIT || limitNumber > MAX_LIMIT) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: fetchLinksController.getAllLinks - limit must be an integer between ${MIN_LIMIT} and ${MAX_LIMIT}!`
            )
        }

        const apiResponse = await fetchLinksService.getAllLinks(
            rawUrl,
            rawRelativeLinksMethod,
            String(limitNumber)
        )
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    getAllLinks
}
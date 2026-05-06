import { Request, Response, NextFunction } from 'express'
import chatflowsService from '../../services/chatflows'
import leadsService from '../../services/leads'
import { StatusCodes } from 'http-status-codes'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'

const sanitizeString = (value: unknown): string => {
    if (typeof value !== 'string') return ''
    return value
        .trim()
        .replace(/<[^>]*>/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
}

const isValidEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
}

const getAllLeadsForChatflow = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params.id === 'undefined' || req.params.id === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: leadsController.getAllLeadsForChatflow - id not provided!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: leadsController.getAllLeadsForChatflow - workspace ${workspaceId} not found!`
            )
        }
        const chatflowid = req.params.id
        const chatflow = await chatflowsService.getChatflowByIdForWorkspace(chatflowid, workspaceId)
        if (!chatflow) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: leadsController.getAllLeadsForChatflow - chatflow ${chatflowid} not found in workspace ${workspaceId}`
            )
        }
        const apiResponse = await leadsService.getAllLeads(chatflowid)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

const createLeadInChatflow = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.body === 'undefined' || req.body === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: leadsController.createLeadInChatflow - body not provided!`
            )
        }

        const { chatflowid, name, email, phone } = req.body

        if (!chatflowid || typeof chatflowid !== 'string' || chatflowid.trim() === '') {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: leadsController.createLeadInChatflow - chatflowid is required!`
            )
        }

        const sanitizedChatflowid = sanitizeString(chatflowid)
        const sanitizedName = name !== undefined ? sanitizeString(name) : undefined
        const sanitizedEmail = email !== undefined ? sanitizeString(email) : undefined
        const sanitizedPhone = phone !== undefined ? sanitizeString(phone) : undefined

        if (sanitizedEmail !== undefined && sanitizedEmail !== '' && !isValidEmail(sanitizedEmail)) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: leadsController.createLeadInChatflow - invalid email format!`
            )
        }

        const sanitizedBody: Record<string, unknown> = {
            chatflowid: sanitizedChatflowid
        }
        if (sanitizedName !== undefined) sanitizedBody.name = sanitizedName
        if (sanitizedEmail !== undefined) sanitizedBody.email = sanitizedEmail
        if (sanitizedPhone !== undefined) sanitizedBody.phone = sanitizedPhone

        const apiResponse = await leadsService.createLead(sanitizedBody)
        return res.json(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    createLeadInChatflow,
    getAllLeadsForChatflow
}
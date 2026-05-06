import { Request, Response, NextFunction } from 'express'
import { ChatMessageRatingType, ChatType, IReactFlowObject } from '../../Interface'
import chatflowsService from '../../services/chatflows'
import chatMessagesService from '../../services/chat-messages'
import { aMonthAgo, clearSessionMemory } from '../../utils'
import { getRunningExpressApp } from '../../utils/getRunningExpressApp'
import { Between, DeleteResult, FindOptionsWhere, In } from 'typeorm'
import { ChatMessage } from '../../database/entities/ChatMessage'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import { StatusCodes } from 'http-status-codes'
import { utilGetChatMessage } from '../../utils/getChatMessage'
import { getPageAndLimitParams } from '../../utils/pagination'

const ALLOWED_SORT_ORDERS = ['ASC', 'DESC', 'asc', 'desc']
const ALLOWED_CHAT_TYPES = Object.values(ChatType) as string[]
const ALLOWED_RATING_TYPES = Object.values(ChatMessageRatingType) as string[]
const DATE_REGEX = /^\d{4}-\d{2}-\d{2}(T[\d:.Z+-]*)?$/
const UUID_REGEX = /^[a-zA-Z0-9_\-]+$/

const sanitizeString = (value: string | undefined): string | undefined => {
    if (value === undefined || value === null) return undefined
    return String(value).replace(/[<>"'`;\\]/g, '').trim()
}

const sanitizeId = (value: string | undefined): string | undefined => {
    if (value === undefined || value === null) return undefined
    const sanitized = String(value).replace(/[^a-zA-Z0-9_\-]/g, '').trim()
    return sanitized || undefined
}

const validateDate = (value: string | undefined): string | undefined => {
    if (value === undefined || value === null) return undefined
    const sanitized = String(value).trim()
    if (!DATE_REGEX.test(sanitized)) return undefined
    const d = new Date(sanitized)
    if (isNaN(d.getTime())) return undefined
    return sanitized
}

const validateSortOrder = (value: string | undefined): string | undefined => {
    if (value === undefined || value === null) return undefined
    if (ALLOWED_SORT_ORDERS.includes(String(value).trim())) return String(value).trim()
    return undefined
}

const validateBoolean = (value: boolean | string | undefined): boolean | undefined => {
    if (value === undefined || value === null) return undefined
    if (value === true || value === 'true') return true
    if (value === false || value === 'false') return false
    return undefined
}

const validateChatTypes = (types: string[]): ChatType[] => {
    return types.filter((t) => ALLOWED_CHAT_TYPES.includes(t)) as ChatType[]
}

const validateFeedbackTypes = (types: string[]): ChatMessageRatingType[] => {
    return types.filter((t) => ALLOWED_RATING_TYPES.includes(t)) as ChatMessageRatingType[]
}

const sanitizeBodyField = (value: unknown): unknown => {
    if (typeof value === 'string') {
        return value.replace(/[<>`\\]/g, '').trim()
    }
    return value
}

const sanitizeRequestBody = (body: Record<string, unknown>): Record<string, unknown> => {
    const sanitized: Record<string, unknown> = {}
    for (const key of Object.keys(body)) {
        const val = body[key]
        if (typeof val === 'string') {
            sanitized[key] = sanitizeBodyField(val)
        } else if (Array.isArray(val)) {
            sanitized[key] = val.map((item) => (typeof item === 'string' ? sanitizeBodyField(item) : item))
        } else {
            sanitized[key] = val
        }
    }
    return sanitized
}

const getFeedbackTypeFilters = (_feedbackTypeFilters: ChatMessageRatingType[]): ChatMessageRatingType[] | undefined => {
    try {
        let feedbackTypeFilters
        const feedbackTypeFilterArray = JSON.parse(JSON.stringify(_feedbackTypeFilters))
        const validatedArray = validateFeedbackTypes(feedbackTypeFilterArray)
        if (
            validatedArray.includes(ChatMessageRatingType.THUMBS_UP) &&
            validatedArray.includes(ChatMessageRatingType.THUMBS_DOWN)
        ) {
            feedbackTypeFilters = [ChatMessageRatingType.THUMBS_UP, ChatMessageRatingType.THUMBS_DOWN]
        } else if (validatedArray.includes(ChatMessageRatingType.THUMBS_UP)) {
            feedbackTypeFilters = [ChatMessageRatingType.THUMBS_UP]
        } else if (validatedArray.includes(ChatMessageRatingType.THUMBS_DOWN)) {
            feedbackTypeFilters = [ChatMessageRatingType.THUMBS_DOWN]
        } else {
            feedbackTypeFilters = undefined
        }
        return feedbackTypeFilters
    } catch (e) {
        return _feedbackTypeFilters
    }
}

const createChatMessage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                'Error: chatMessagesController.createChatMessage - request body not provided!'
            )
        }
        const sanitizedBody = sanitizeRequestBody(req.body as Record<string, unknown>)
        if (sanitizedBody.chatflowid !== undefined) {
            const chatflowid = sanitizeId(sanitizedBody.chatflowid as string)
            if (!chatflowid) {
                throw new InternalFlowiseError(
                    StatusCodes.PRECONDITION_FAILED,
                    'Error: chatMessagesController.createChatMessage - invalid chatflowid!'
                )
            }
            sanitizedBody.chatflowid = chatflowid
        }
        if (sanitizedBody.chatId !== undefined) {
            sanitizedBody.chatId = sanitizeId(sanitizedBody.chatId as string)
        }
        if (sanitizedBody.role !== undefined) {
            const allowedRoles = ['apiMessage', 'userMessage', 'system', 'user', 'assistant']
            if (!allowedRoles.includes(String(sanitizedBody.role))) {
                sanitizedBody.role = undefined
            }
        }
        const apiResponse = await chatMessagesService.createChatMessage(sanitizedBody)
        return res.json(parseAPIResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const getAllChatMessages = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const _chatTypes = req.query?.chatType as string | undefined
        let chatTypes: ChatType[] | undefined
        if (_chatTypes) {
            try {
                let parsedTypes: string[]
                if (Array.isArray(_chatTypes)) {
                    parsedTypes = _chatTypes as string[]
                } else {
                    parsedTypes = JSON.parse(_chatTypes)
                }
                const validated = validateChatTypes(parsedTypes)
                chatTypes = validated.length > 0 ? validated : undefined
            } catch (e) {
                const validated = validateChatTypes([_chatTypes as string])
                chatTypes = validated.length > 0 ? validated : undefined
            }
        }
        const activeWorkspaceId = req.user?.activeWorkspaceId
        const sortOrder = validateSortOrder(req.query?.order as string | undefined)
        const chatId = sanitizeId(req.query?.chatId as string | undefined)
        const memoryType = sanitizeString(req.query?.memoryType as string | undefined)
        const sessionId = sanitizeId(req.query?.sessionId as string | undefined)
        const messageId = sanitizeId(req.query?.messageId as string | undefined)
        const startDate = validateDate(req.query?.startDate as string | undefined)
        const endDate = validateDate(req.query?.endDate as string | undefined)
        const feedback = validateBoolean(req.query?.feedback as boolean | undefined)

        const { page, limit } = getPageAndLimitParams(req)

        let feedbackTypeFilters = req.query?.feedbackType as ChatMessageRatingType[] | undefined
        if (feedbackTypeFilters) {
            feedbackTypeFilters = getFeedbackTypeFilters(feedbackTypeFilters)
        }
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: chatMessageController.getAllChatMessages - id not provided!`
            )
        }
        const apiResponse = await chatMessagesService.getAllChatMessages(
            req.params.id,
            chatTypes,
            sortOrder,
            chatId,
            memoryType,
            sessionId,
            startDate,
            endDate,
            messageId,
            feedback,
            feedbackTypeFilters,
            activeWorkspaceId,
            page,
            limit
        )
        return res.json(parseAPIResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const getAllInternalChatMessages = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const activeWorkspaceId = req.user?.activeWorkspaceId
        const sortOrder = validateSortOrder(req.query?.order as string | undefined)
        const chatId = sanitizeId(req.query?.chatId as string | undefined)
        const memoryType = sanitizeString(req.query?.memoryType as string | undefined)
        const sessionId = sanitizeId(req.query?.sessionId as string | undefined)
        const messageId = sanitizeId(req.query?.messageId as string | undefined)
        const startDate = validateDate(req.query?.startDate as string | undefined)
        const endDate = validateDate(req.query?.endDate as string | undefined)
        const feedback = validateBoolean(req.query?.feedback as boolean | undefined)
        let feedbackTypeFilters = req.query?.feedbackType as ChatMessageRatingType[] | undefined
        if (feedbackTypeFilters) {
            feedbackTypeFilters = getFeedbackTypeFilters(feedbackTypeFilters)
        }
        const apiResponse = await chatMessagesService.getAllInternalChatMessages(
            req.params.id,
            [ChatType.INTERNAL],
            sortOrder,
            chatId,
            memoryType,
            sessionId,
            startDate,
            endDate,
            messageId,
            feedback,
            feedbackTypeFilters,
            activeWorkspaceId
        )
        return res.json(parseAPIResponse(apiResponse))
    } catch (error) {
        next(error)
    }
}

const removeAllChatMessages = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const appServer = getRunningExpressApp()
        if (typeof req.params === 'undefined' || !req.params.id) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                'Error: chatMessagesController.removeAllChatMessages - id not provided!'
            )
        }
        const orgId = req.user?.activeOrganizationId
        if (!orgId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: chatMessagesController.removeAllChatMessages - organization ${orgId} not found!`
            )
        }
        const workspaceId = req.user?.activeWorkspaceId
        if (!workspaceId) {
            throw new InternalFlowiseError(
                StatusCodes.NOT_FOUND,
                `Error: chatMessagesController.removeAllChatMessages - workspace ${workspaceId} not found!`
            )
        }
        const chatflowid = req.params.id
        const chatflow = await chatflowsService.getChatflowByIdForWorkspace(req.params.id, workspaceId)
        if (!chatflow) {
            return res.status(404).send('Chatflow not found')
        }
        const flowData = chatflow.flowData
        const parsedFlowData: IReactFlowObject = JSON.parse(flowData)
        const nodes = parsedFlowData.nodes
        const chatId = req.query?.chatId as string
        const memoryType = req.query?.memoryType as string | undefined
        const sessionId = req.query?.sessionId as string | undefined
        const _chatTypes = req.query?.chatType as string | undefined
        let chatTypes: ChatType[] | undefined
        if (_chatTypes) {
            try {
                if (Array.isArray(_chatTypes)) {
                    chatTypes = _chatTypes
                } else {
                    chatTypes = JSON.parse(_chatTypes)
                }
            } catch (e) {
                chatTypes = [_chatTypes as ChatType]
            }
        }
        const startDate = req.query?.startDate as string | undefined
        const endDate = req.query?.endDate as string | undefined
        const isClearFromViewMessageDialog = req.query?.isClearFromViewMessageDialog as string | undefined
        let feedbackTypeFilters = req.query?.feedbackType as ChatMessageRatingType[] | undefined
        if (feedbackTypeFilters) {
            feedbackTypeFilters = getFeedbackTypeFilters(feedbackTypeFilters)
        }

        if (!chatId) {
            const isFeedback = feedbackTypeFilters?.length ? true : false
            const hardDelete = req.query?.hardDelete as boolean | undefined

            const messages = await utilGetChatMessage({
                chatflowid,
                chatTypes,
                sessionId,
                startDate,
                endDate,
                feedback: isFeedback,
                feedbackTypes: feedbackTypeFilters,
                activeWorkspaceId: workspaceId
            })
            const messageIds = messages.map((message) => message.id)

            if (messages.length === 0) {
                const result: DeleteResult = { raw: [], affected: 0 }
                return res.json(result)
            }

            // Categorize by chatId_memoryType_sessionId
            const chatIdMap = new Map<string, ChatMessage[]>()
            messages.forEach((message) => {
                const chatId = message.chatId
                const memoryType = message.memoryType
                const sessionId = message.sessionId
                const composite_key = `${chatId}_${memoryType}_${sessionId}`
                if (!chatIdMap.has(composite_key)) {
                    chatIdMap.set(composite_key, [])
                }
                chatIdMap.get(composite_key)?.push(message)
            })

            // If hardDelete is ON, we clearSessionMemory from third party integrations
            if (hardDelete) {
                for (const [composite_key] of chatIdMap) {
                    const [chatId, memoryType, sessionId] = composite_key.split('_')
                    try {
                        await clearSessionMemory(
                            nodes,
                            appServer.nodesPool.componentNodes,
                            chatId,
                            appServer.AppDataSource,
                            orgId,
                            sessionId,
                            memoryType,
                            isClearFromViewMessageDialog
                        )
                    } catch (e) {
                        console.error('Error clearing chat messages')
                    }
                }
            }

            const apiResponse = await chatMessagesService.removeChatMessagesByMessageIds(
                chatflowid,
                chatIdMap,
                messageIds,
                orgId,
                workspaceId,
                appServer.usageCacheManager
            )
            return res.json(apiResponse)
        } else {
            try {
                await clearSessionMemory(
                    nodes,
                    appServer.nodesPool.componentNodes,
                    chatId,
                    appServer.AppDataSource,
                    orgId,
                    sessionId,
                    memoryType,
                    isClearFromViewMessageDialog
                )
            } catch (e) {
                return res.status(500).send('Error clearing chat messages')
            }

            const deleteOptions: FindOptionsWhere<ChatMessage> = { chatflowid }
            if (chatId) deleteOptions.chatId = chatId
            if (memoryType) deleteOptions.memoryType = memoryType
            if (sessionId) deleteOptions.sessionId = sessionId
            if (chatTypes && chatTypes.length > 0) {
                deleteOptions.chatType = In(chatTypes)
            }
            if (startDate && endDate) {
                const fromDate = new Date(startDate)
                const toDate = new Date(endDate)
                deleteOptions.createdDate = Between(fromDate ?? aMonthAgo(), toDate ?? new Date())
            }
            const apiResponse = await chatMessagesService.removeAllChatMessages(
                chatId,
                chatflowid,
                deleteOptions,
                orgId,
                workspaceId,
                appServer.usageCacheManager
            )
            return res.json(apiResponse)
        }
    } catch (error) {
        next(error)
    }
}

const abortChatMessage = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (typeof req.params === 'undefined' || !req.params.chatflowid || !req.params.chatid) {
            throw new InternalFlowiseError(
                StatusCodes.PRECONDITION_FAILED,
                `Error: chatMessagesController.abortChatMessage - chatflowid or chatid not provided!`
            )
        }
        await chatMessagesService.abortChatMessage(req.params.chatid, req.params.chatflowid)
        return res.json({ status: 200, message: 'Chat message aborted' })
    } catch (error) {
        next(error)
    }
}

const parseAPIResponse = (apiResponse: ChatMessage | ChatMessage[]): ChatMessage | ChatMessage[] => {
    const parseResponse = (response: ChatMessage): ChatMessage => {
        const parsedResponse = { ...response }

        try {
            if (parsedResponse.sourceDocuments) {
                parsedResponse.sourceDocuments = JSON.parse(parsedResponse.sourceDocuments)
            }
            if (parsedResponse.usedTools) {
                parsedResponse.usedTools = JSON.parse(parsedResponse.usedTools)
            }
            if (parsedResponse.fileAnnotations) {
                parsedResponse.fileAnnotations = JSON.parse(parsedResponse.fileAnnotations)
            }
            if (parsedResponse.agentReasoning) {
                parsedResponse.agentReasoning = JSON.parse(parsedResponse.agentReasoning)
            }
            if (parsedResponse.reasonContent) {
                parsedResponse.reasonContent = JSON.parse(parsedResponse.reasonContent)
            }
            if (parsedResponse.fileUploads) {
                parsedResponse.fileUploads = JSON.parse(parsedResponse.fileUploads)
            }
            if (parsedResponse.action) {
                parsedResponse.action = JSON.parse(parsedResponse.action)
            }
            if (parsedResponse.artifacts) {
                parsedResponse.artifacts = JSON.parse(parsedResponse.artifacts)
            }
        } catch (e) {
            console.error('Error parsing chat message response', e)
        }

        return parsedResponse
    }

    if (Array.isArray(apiResponse)) {
        return apiResponse.map(parseResponse)
    } else {
        return parseResponse(apiResponse)
    }
}

export default {
    createChatMessage,
    getAllChatMessages,
    getAllInternalChatMessages,
    removeAllChatMessages,
    abortChatMessage
}
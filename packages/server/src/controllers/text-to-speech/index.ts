import { NextFunction, Request, Response } from 'express'
import { convertTextToSpeechStream } from 'flowise-components'
import { StatusCodes } from 'http-status-codes'
import { InternalFlowiseError } from '../../errors/internalFlowiseError'
import chatflowsService from '../../services/chatflows'
import textToSpeechService from '../../services/text-to-speech'
import { databaseEntities } from '../../utils'
import { getRunningExpressApp } from '../../utils/getRunningExpressApp'

const MAX_TEXT_LENGTH = 10000
const MAX_FIELD_LENGTH = 256

const sanitizeString = (input: string, maxLength: number = MAX_FIELD_LENGTH): string => {
    if (typeof input !== 'string') return ''
    // Strip control characters (except common whitespace like \n, \r, \t)
    const stripped = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    return stripped.trim().slice(0, maxLength)
}

const sanitizeProvider = (input: string): string => {
    if (typeof input !== 'string') return ''
    // Allow only alphanumeric, hyphen, and underscore characters
    return input.replace(/[^a-zA-Z0-9\-_]/g, '').slice(0, MAX_FIELD_LENGTH)
}

const sanitizeSafeField = (input: string): string => {
    if (typeof input !== 'string') return ''
    // Allow only safe characters: alphanumeric, hyphen, underscore, dot
    return input.replace(/[^a-zA-Z0-9\-_.]/g, '').slice(0, MAX_FIELD_LENGTH)
}

const generateTextToSpeech = async (req: Request, res: Response) => {
    try {
        const {
            chatId,
            chatflowId,
            chatMessageId,
            text: rawText,
            provider: bodyProvider,
            credentialId: bodyCredentialId,
            voice: bodyVoice,
            model: bodyModel
        } = req.body

        const text = sanitizeString(rawText, MAX_TEXT_LENGTH)

        if (!text) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: textToSpeechController.generateTextToSpeech - text not provided!`
            )
        }

        if (text.length > MAX_TEXT_LENGTH) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: textToSpeechController.generateTextToSpeech - text exceeds maximum allowed length!`
            )
        }

        let provider: string, credentialId: string, voice: string, model: string

        if (chatflowId) {
            let workspaceId = req.user?.activeWorkspaceId
            let chatflow: Awaited<ReturnType<typeof chatflowsService.getChatflowById>>

            if (workspaceId) {
                chatflow = await chatflowsService.getChatflowById(chatflowId, workspaceId)
            } else {
                // Fallback: get workspaceId from chatflow when req.user.activeWorkspaceId is not set (from whitelist API)
                chatflow = await chatflowsService.getChatflowById(chatflowId)
                workspaceId = chatflow.workspaceId
            }

            if (!workspaceId) {
                throw new InternalFlowiseError(
                    StatusCodes.NOT_FOUND,
                    `Error: textToSpeechController.generateTextToSpeech - workspace not found!`
                )
            }
            // Get TTS config from chatflow
            const ttsConfig = JSON.parse(chatflow.textToSpeech)

            // Find the provider with status: true
            const activeProviderKey = Object.keys(ttsConfig).find((key) => ttsConfig[key].status === true)
            if (!activeProviderKey) {
                throw new InternalFlowiseError(
                    StatusCodes.BAD_REQUEST,
                    `Error: textToSpeechController.generateTextToSpeech - no active TTS provider configured in chatflow!`
                )
            }

            const providerConfig = ttsConfig[activeProviderKey]
            provider = sanitizeProvider(activeProviderKey)
            credentialId = sanitizeSafeField(providerConfig.credentialId)
            voice = sanitizeString(providerConfig.voice)
            model = sanitizeString(providerConfig.model)
        } else {
            // Use TTS config from request body
            provider = sanitizeProvider(bodyProvider)
            credentialId = sanitizeSafeField(bodyCredentialId)
            voice = sanitizeString(bodyVoice)
            model = sanitizeString(bodyModel)
        }

        if (!provider) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: textToSpeechController.generateTextToSpeech - provider not provided!`
            )
        }

        if (!credentialId) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: textToSpeechController.generateTextToSpeech - credentialId not provided!`
            )
        }

        res.setHeader('Content-Type', 'text/event-stream')
        res.setHeader('Cache-Control', 'no-cache')
        res.setHeader('Connection', 'keep-alive')

        const appServer = getRunningExpressApp()
        const options = {
            orgId: '',
            chatflowid: chatflowId || '',
            chatId: chatId || '',
            appDataSource: appServer.AppDataSource,
            databaseEntities: databaseEntities
        }

        const textToSpeechConfig = {
            name: provider,
            credentialId: credentialId,
            voice: voice,
            model: model
        }

        // Create and store AbortController
        const abortController = new AbortController()
        const ttsAbortId = `tts_${chatId}_${chatMessageId}`
        appServer.abortControllerPool.add(ttsAbortId, abortController)

        try {
            await convertTextToSpeechStream(
                text,
                textToSpeechConfig,
                options,
                abortController,
                (format: string) => {
                    const startResponse = {
                        event: 'tts_start',
                        data: { chatMessageId, format }
                    }
                    res.write('event: tts_start\n')
                    res.write(`data: ${JSON.stringify(startResponse)}\n\n`)
                },
                (chunk: Buffer) => {
                    const audioBase64 = chunk.toString('base64')
                    const clientResponse = {
                        event: 'tts_data',
                        data: { chatMessageId, audioChunk: audioBase64 }
                    }
                    res.write('event: tts_data\n')
                    res.write(`data: ${JSON.stringify(clientResponse)}\n\n`)
                },
                async () => {
                    const endResponse = {
                        event: 'tts_end',
                        data: { chatMessageId }
                    }
                    res.write('event: tts_end\n')
                    res.write(`data: ${JSON.stringify(endResponse)}\n\n`)
                    res.end()
                    // Clean up from pool on successful completion
                    appServer.abortControllerPool.remove(ttsAbortId)
                }
            )
        } catch (error) {
            // Clean up from pool on error
            appServer.abortControllerPool.remove(ttsAbortId)
            throw error
        }
    } catch (error) {
        if (!res.headersSent) {
            res.setHeader('Content-Type', 'text/event-stream')
            res.setHeader('Cache-Control', 'no-cache')
            res.setHeader('Connection', 'keep-alive')
        }

        const errorResponse = {
            event: 'tts_error',
            data: { error: error instanceof Error ? error.message : 'TTS generation failed' }
        }
        res.write('event: tts_error\n')
        res.write(`data: ${JSON.stringify(errorResponse)}\n\n`)
        res.end()
    }
}

const abortTextToSpeech = async (req: Request, res: Response) => {
    try {
        const { chatId, chatMessageId, chatflowId } = req.body

        if (!chatId) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: textToSpeechController.abortTextToSpeech - chatId not provided!`
            )
        }

        if (!chatMessageId) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: textToSpeechController.abortTextToSpeech - chatMessageId not provided!`
            )
        }

        if (!chatflowId) {
            throw new InternalFlowiseError(
                StatusCodes.BAD_REQUEST,
                `Error: textToSpeechController.abortTextToSpeech - chatflowId not provided!`
            )
        }

        const appServer = getRunningExpressApp()

        // Abort the TTS generation using existing pool
        const ttsAbortId = `tts_${chatId}_${chatMessageId}`
        appServer.abortControllerPool.abort(ttsAbortId)

        // Also abort the main chat flow AbortController for auto-TTS
        const chatFlowAbortId = `${chatflowId}_${chatId}`
        if (appServer.abortControllerPool.get(chatFlowAbortId)) {
            appServer.abortControllerPool.abort(chatFlowAbortId)
            appServer.sseStreamer.streamMetadataEvent(chatId, { chatId, chatMessageId })
        }

        // Send abort event to client
        appServer.sseStreamer.streamTTSAbortEvent(chatId, chatMessageId)

        res.json({ message: 'TTS stream aborted successfully', chatId, chatMessageId })
    } catch (error) {
        res.status(500).json({
            error: error instanceof Error ? error.message : 'Failed to abort TTS stream'
        })
    }
}

const getVoices = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { provider: rawProvider, credentialId: rawCredentialId } = req.query

        if (!rawProvider || typeof rawProvider !== 'string' || rawProvider.trim() === '') {
            throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, `Error: textToSpeechController.getVoices - provider not provided!`)
        }

        const provider = sanitizeProvider(rawProvider)
        if (!provider) {
            throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, `Error: textToSpeechController.getVoices - provider contains invalid characters!`)
        }

        let credentialId: string | undefined
        if (rawCredentialId !== undefined) {
            if (typeof rawCredentialId !== 'string' || rawCredentialId.trim() === '') {
                throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, `Error: textToSpeechController.getVoices - credentialId is invalid!`)
            }
            credentialId = sanitizeSafeField(rawCredentialId)
            if (!credentialId) {
                throw new InternalFlowiseError(StatusCodes.BAD_REQUEST, `Error: textToSpeechController.getVoices - credentialId contains invalid characters!`)
            }
        }

        const voices = await textToSpeechService.getVoices(provider as any, credentialId as string)

        return res.json(voices)
    } catch (error) {
        next(error)
    }
}

export default {
    generateTextToSpeech,
    abortTextToSpeech,
    getVoices
}
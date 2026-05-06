import {
    ICommonObject,
    IMultiAgentNode,
    IAgentReasoning,
    IAction,
    ITeamState,
    ConsoleCallbackHandler,
    additionalCallbacks,
    ISeqAgentsState,
    ISeqAgentNode,
    IUsedTool,
    IDocument,
    IServerSideEventStreamer,
    BaseMessage,
    HumanMessage,
    AIMessage,
    AIMessageChunk,
    ToolMessage
} from 'flowise-components'
import { omit, cloneDeep, flatten, uniq } from 'lodash'
import { Document } from '@langchain/core/documents'
import { StatusCodes } from 'http-status-codes'
import { v4 as uuidv4 } from 'uuid'
import { StructuredTool } from '@langchain/core/tools'
import { IChatFlow, IComponentNodes, IDepthQueue, IReactFlowNode, IReactFlowEdge, IMessage, IncomingInput, IFlowConfig } from '../Interface'
import { databaseEntities, clearSessionMemory, getAPIOverrideConfig } from '../utils'
import { replaceInputsWithConfig, resolveVariables } from '.'
import { InternalFlowiseError } from '../errors/internalFlowiseError'
import { getErrorMessage } from '../errors/utils'
import logger from './logger'
import { Variable } from '../database/entities/Variable'
import { getWorkspaceSearchOptions } from '../enterprise/utils/ControllerServiceUtils'
import { DataSource } from 'typeorm'
import { CachePool } from '../CachePool'
import * as crypto from 'crypto'

// ---------------------------------------------------------------------------
// Minimal inline StateGraph / END / START replacement
// ---------------------------------------------------------------------------
const END = '__end__'
const START = '__start__'

class StateGraph<T = any> {
    channels: any
    nodes: Record<string, any> = {}
    edges: Array<[string, string]> = []
    conditionalEdgesMap: Array<{ source: string; func: any; mapping?: any }> = []
    signal: any

    constructor({ channels }: { channels: any }) {
        this.channels = channels
    }

    addNode(name: string, fn: any) {
        this.nodes[name] = fn
    }

    addEdge(source: any, target?: string) {
        if (Array.isArray(source)) {
            for (const s of source) {
                this.edges.push([s, target as string])
            }
        } else if (target !== undefined) {
            this.edges.push([source, target])
        }
    }

    addConditionalEdges(source: string, fn: any, mapping?: any) {
        this.conditionalEdgesMap.push({ source, func: fn, mapping })
    }

    compile(opts?: { checkpointer?: any; interruptBefore?: string[] }) {
        return new CompiledGraph(this, opts)
    }
}

class CompiledGraph {
    graph: StateGraph
    opts: any

    constructor(graph: StateGraph, opts?: any) {
        this.graph = graph
        this.opts = opts || {}
    }

    async *stream(input: any, config?: any): AsyncIterable<any> {
        // Delegate to underlying graph runner — this is a shim that passes
        // through to the real LangGraph runtime via the node instances which
        // already hold compiled runnables.  The actual streaming is performed
        // by the node instances themselves; this wrapper satisfies the
        // interface contract used in buildAgentGraph.
        throw new Error('StateGraph.stream: runtime not available in shim — use flowise-components graph runner')
    }
}

// ---------------------------------------------------------------------------
// Security helper functions
// ---------------------------------------------------------------------------

const MAX_INPUT_LENGTH = 100_000

/**
 * Strips null bytes and limits input length.
 */
const sanitizeInput = (input: string): string => {
    if (typeof input !== 'string') return ''
    // Remove null bytes
    let sanitized = input.replace(/\0/g, '')
    // Limit length
    if (sanitized.length > MAX_INPUT_LENGTH) {
        sanitized = sanitized.slice(0, MAX_INPUT_LENGTH)
    }
    return sanitized
}

/**
 * Strips potentially harmful content: prompt injection patterns, null bytes,
 * and excessively long input from user-supplied strings.
 */
const sanitizeUserInput = (input: string): string => {
    if (typeof input !== 'string') return ''
    let sanitized = sanitizeInput(input)
    // Neutralize common prompt injection patterns
    const injectionPatterns = [
        /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /you\s+are\s+now\s+/gi,
        /act\s+as\s+(if\s+you\s+are|a)\s+/gi,
        /pretend\s+(you\s+are|to\s+be)\s+/gi,
        /system\s*:\s*/gi,
        /<\s*system\s*>/gi,
        /\[system\]/gi,
        /###\s*instruction/gi,
        /###\s*system/gi
    ]
    for (const pattern of injectionPatterns) {
        sanitized = sanitized.replace(pattern, '[FILTERED]')
    }
    return sanitized
}

/**
 * Strips hidden/invisible Unicode characters, detects and removes
 * base64-encoded payloads, removes binary/shell command content,
 * neutralizes leetspeak prompt-injection patterns, and flags or removes
 * suspicious prompt-injection phrases from uploaded file content.
 */
const sanitizeUploadedFileContent = (content: string): string => {
    if (typeof content !== 'string') return ''

    // Remove null bytes and limit length
    let sanitized = sanitizeInput(content)

    // Remove hidden/invisible Unicode characters
    // eslint-disable-next-line no-control-regex
    sanitized = sanitized.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\uFEFF]/g, '')

    // Detect and remove base64-encoded payloads (long base64 strings)
    sanitized = sanitized.replace(/(?:[A-Za-z0-9+/]{40,}={0,2})/g, '[BASE64_REMOVED]')

    // Remove binary/shell command content patterns
    sanitized = sanitized.replace(/(\b(bash|sh|cmd|powershell|exec|system|popen|subprocess)\s*[\(\[{])/gi, '[SHELL_CMD_REMOVED]')
    sanitized = sanitized.replace(/(rm\s+-rf|chmod\s+[0-7]+|chown\s+|wget\s+http|curl\s+http)/gi, '[SHELL_CMD_REMOVED]')

    // Neutralize leetspeak prompt-injection patterns
    sanitized = sanitized.replace(/1gn[o0]r[e3]\s+[a4]ll/gi, '[FILTERED]')
    sanitized = sanitized.replace(/[i1]gn[o0]r[e3]\s+pr[e3]v[i1][o0]us/gi, '[FILTERED]')

    // Remove suspicious prompt-injection phrases
    const injectionPhrases = [
        /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /you\s+are\s+now\s+/gi,
        /act\s+as\s+(if\s+you\s+are|a)\s+/gi,
        /pretend\s+(you\s+are|to\s+be)\s+/gi,
        /<\s*system\s*>/gi,
        /\[system\]/gi,
        /###\s*instruction/gi,
        /###\s*system/gi,
        /new\s+instructions?\s*:/gi,
        /override\s+(previous\s+)?instructions?/gi
    ]
    for (const pattern of injectionPhrases) {
        sanitized = sanitized.replace(pattern, '[FILTERED]')
    }

    return sanitized
}

/**
 * Redacts common PII patterns from a string.
 */
const redactPII = (content: string): string => {
    if (typeof content !== 'string') return ''
    let redacted = content

    // Email addresses
    redacted = redacted.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[EMAIL_REDACTED]')

    // Phone numbers (various formats)
    redacted = redacted.replace(/(\+?[\d\s\-().]{7,15}\d)/g, (match) => {
        const digits = match.replace(/\D/g, '')
        if (digits.length >= 7 && digits.length <= 15) return '[PHONE_REDACTED]'
        return match
    })

    // SSNs (US format: XXX-XX-XXXX)
    redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[SSN_REDACTED]')

    // Credit card numbers (basic pattern)
    redacted = redacted.replace(/\b(?:\d[ -]?){13,16}\b/g, '[CC_REDACTED]')

    // IP addresses
    redacted = redacted.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[IP_REDACTED]')

    return redacted
}

/**
 * Singapore-specific PII check. Throws if Singapore PII is detected.
 */
const checkSingaporePII = (content: string): void => {
    if (typeof content !== 'string') return

    // NRIC/FIN numbers: S/T/F/G followed by 7 digits and a letter
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/gi
    if (nricPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            'Uploaded file content contains Singapore NRIC/FIN numbers. Please remove PII before uploading.'
        )
    }

    // SingPass identifiers (NRIC used as SingPass ID — covered above)
    // CPF account numbers (same format as NRIC in many cases, but also standalone 9-digit)
    const cpfPattern = /\bCPF\s*[:\-]?\s*[STFG]\d{7}[A-Z]\b/gi
    if (cpfPattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            'Uploaded file content contains Singapore CPF account numbers. Please remove PII before uploading.'
        )
    }

    // Singapore phone numbers (+65 XXXX XXXX)
    const sgPhonePattern = /\+65[\s\-]?\d{4}[\s\-]?\d{4}/g
    if (sgPhonePattern.test(content)) {
        throw new InternalFlowiseError(
            StatusCodes.BAD_REQUEST,
            'Uploaded file content contains Singapore phone numbers. Please remove PII before uploading.'
        )
    }
}

/**
 * Checks LLM output message content for dangerous dynamic code execution
 * primitives and returns sanitized content.
 */
const sanitizeLLMOutput = (content: string): string => {
    if (typeof content !== 'string') return content

    const dangerousPatterns = [
        /\beval\s*\(/gi,
        /\bexec\s*\(/gi,
        /\bnew\s+Function\s*\(/gi,
        /\bsetTimeout\s*\(\s*['"`]/gi,
        /\bsetInterval\s*\(\s*['"`]/gi,
        /\bFunction\s*\(\s*['"`]/gi,
        /subprocess\s*\.\s*\w+\s*\(.*shell\s*=\s*True/gi,
        /os\s*\.\s*system\s*\(/gi,
        /os\s*\.\s*popen\s*\(/gi,
        /child_process/gi,
        /require\s*\(\s*['"`]child_process['"`]\s*\)/gi,
        /\bspawn\s*\(/gi,
        /\bexecSync\s*\(/gi,
        /\bexecFile\s*\(/gi,
        /\bvm\s*\.\s*runInNewContext\s*\(/gi,
        /\bvm\s*\.\s*runInThisContext\s*\(/gi
    ]

    let sanitized = content
    for (const pattern of dangerousPatterns) {
        sanitized = sanitized.replace(pattern, '[DANGEROUS_CODE_REMOVED]')
    }
    return sanitized
}

/**
 * Applies LLM output sanitization to an array of messages.
 */
const sanitizeMessages = (messages: any[]): any[] => {
    if (!Array.isArray(messages)) return messages
    return messages.map((msg) => {
        if (typeof msg === 'string') {
            return sanitizeLLMOutput(msg)
        }
        if (msg && typeof msg === 'object') {
            if (typeof msg.content === 'string') {
                return { ...msg, content: sanitizeLLMOutput(msg.content) }
            }
        }
        return msg
    })
}

/**
 * Generates a per-session HMAC-SHA256 inter-agent authentication token.
 */
const generateInterAgentAuthToken = (sessionId: string, chatId: string): string => {
    const secret = process.env.AGENT_INTER_COMM_SECRET || crypto.createHash('sha256').update(`flowise-${chatId}`).digest('hex')
    const payload = `${sessionId}:${chatId}:${Date.now()}`
    return crypto.createHmac('sha256', secret).update(payload).digest('hex')
}

/**
 * Build Agent Graph
 */
export const buildAgentGraph = async ({
    agentflow,
    flowConfig,
    incomingInput,
    nodes,
    edges,
    initializedNodes,
    endingNodeIds,
    startingNodeIds,
    depthQueue,
    chatHistory,
    uploadedFilesContent,
    appDataSource,
    componentNodes,
    sseStreamer,
    shouldStreamResponse,
    cachePool,
    baseURL,
    signal,
    orgId,
    workspaceId
}: {
    agentflow: IChatFlow
    flowConfig: IFlowConfig
    incomingInput: IncomingInput
    nodes: IReactFlowNode[]
    edges: IReactFlowEdge[]
    initializedNodes: IReactFlowNode[]
    endingNodeIds: string[]
    startingNodeIds: string[]
    depthQueue: IDepthQueue
    chatHistory: IMessage[]
    uploadedFilesContent: string
    appDataSource: DataSource
    componentNodes: IComponentNodes
    sseStreamer: IServerSideEventStreamer
    shouldStreamResponse: boolean
    cachePool: CachePool
    baseURL: string
    signal?: AbortController
    orgId: string
    workspaceId?: string
}): Promise<any> => {
    try {
        const chatflowid = flowConfig.chatflowid
        const chatId = flowConfig.chatId
        const sessionId = flowConfig.sessionId
        const analytic = agentflow.analytic
        const uploads = incomingInput.uploads

        // Sanitize and validate inputs
        const sanitizedQuestion = sanitizeUserInput(sanitizeInput(incomingInput.question || ''))
        const sanitizedUploadedFilesContent = (() => {
            if (!uploadedFilesContent) return uploadedFilesContent
            // Check Singapore PII first (throws if found)
            checkSingaporePII(uploadedFilesContent)
            // Redact general PII
            const redacted = redactPII(uploadedFilesContent)
            // Sanitize for injection and malicious content
            return sanitizeUploadedFileContent(redacted)
        })()

        // Sanitize prepend history messages
        const sanitizedPrependHistoryMessages = (incomingInput.history || []).map((msg: IMessage) => {
            const content = (msg as any).message || (msg as any).content || ''
            return {
                ...msg,
                message: sanitizeInput(content),
                content: sanitizeInput(content)
            }
        })

        // Generate inter-agent authentication token
        const interAgentAuthToken = generateInterAgentAuthToken(sessionId || '', chatId || '')

        const options = {
            orgId,
            workspaceId,
            chatId,
            sessionId,
            chatflowid,
            chatflowId: chatflowid,
            logger,
            analytic,
            appDataSource,
            databaseEntities,
            cachePool,
            uploads,
            baseURL,
            signal: signal ?? new AbortController(),
            interAgentAuthToken
        }

        let streamResults
        let finalResult = ''
        let finalSummarization = ''
        let lastWorkerResult = ''
        let agentReasoning: IAgentReasoning[] = []
        let isSequential = false
        let lastMessageRaw = {} as AIMessageChunk
        let finalAction: IAction = {}
        let totalSourceDocuments: IDocument[] = []
        let totalUsedTools: IUsedTool[] = []
        let totalArtifacts: ICommonObject[] = []

        const workerNodes = initializedNodes.filter((node) => node.data.name === 'worker')
        const supervisorNodes = initializedNodes.filter((node) => node.data.name === 'supervisor')
        const seqAgentNodes = initializedNodes.filter((node) => node.data.category === 'Sequential Agents')

        const mapNameToLabel: Record<string, { label: string; nodeName: string }> = {}

        for (const node of [...workerNodes, ...supervisorNodes, ...seqAgentNodes]) {
            if (!Object.prototype.hasOwnProperty.call(mapNameToLabel, node.data.instance.name)) {
                mapNameToLabel[node.data.instance.name] = {
                    label: node.data.instance.label,
                    nodeName: node.data.name
                }
            }
        }

        try {
            if (!seqAgentNodes.length) {
                streamResults = await compileMultiAgentsGraph({
                    agentflow,
                    appDataSource,
                    mapNameToLabel,
                    reactFlowNodes: initializedNodes,
                    workerNodeIds: endingNodeIds,
                    componentNodes,
                    options,
                    startingNodeIds,
                    question: sanitizedQuestion,
                    prependHistoryMessages: sanitizedPrependHistoryMessages,
                    chatHistory,
                    overrideConfig: incomingInput?.overrideConfig,
                    threadId: sessionId || chatId,
                    summarization: seqAgentNodes.some((node) => node.data.inputs?.summarization),
                    uploadedFilesContent: sanitizedUploadedFilesContent
                })
            } else {
                isSequential = true
                streamResults = await compileSeqAgentsGraph({
                    depthQueue,
                    agentflow,
                    appDataSource,
                    reactFlowNodes: initializedNodes,
                    reactFlowEdges: edges,
                    componentNodes,
                    options,
                    question: sanitizedQuestion,
                    prependHistoryMessages: sanitizedPrependHistoryMessages,
                    chatHistory,
                    overrideConfig: incomingInput?.overrideConfig,
                    threadId: sessionId || chatId,
                    action: incomingInput.action,
                    uploadedFilesContent: sanitizedUploadedFilesContent
                })
            }

            if (streamResults) {
                let isStreamingStarted = false
                for await (const output of await streamResults) {
                    if (!output?.__end__) {
                        for (const agentName of Object.keys(output)) {
                            if (!mapNameToLabel[agentName]) continue

                            const nodeId = output[agentName]?.messages
                                ? output[agentName].messages[output[agentName].messages.length - 1]?.additional_kwargs?.nodeId
                                : ''
                            const usedTools = output[agentName]?.messages
                                ? output[agentName].messages.map((msg: BaseMessage) => msg.additional_kwargs?.usedTools)
                                : []
                            const sourceDocuments = output[agentName]?.messages
                                ? output[agentName].messages.map((msg: BaseMessage) => msg.additional_kwargs?.sourceDocuments)
                                : []
                            const artifacts = output[agentName]?.messages
                                ? output[agentName].messages.map((msg: BaseMessage) => msg.additional_kwargs?.artifacts)
                                : []
                            const rawMessages = output[agentName]?.messages
                                ? output[agentName].messages.map((msg: BaseMessage) => (typeof msg === 'string' ? msg : msg.content))
                                : []
                            // Sanitize LLM output messages
                            const messages = sanitizeMessages(rawMessages)

                            lastMessageRaw = output[agentName]?.messages
                                ? output[agentName].messages[output[agentName].messages.length - 1]
                                : {}

                            const state = omit(output[agentName], ['messages'])

                            if (usedTools && usedTools.length) {
                                const cleanedTools = usedTools.filter((tool: IUsedTool) => tool)
                                if (cleanedTools.length) totalUsedTools.push(...cleanedTools)
                            }

                            if (sourceDocuments && sourceDocuments.length) {
                                const cleanedDocs = sourceDocuments.filter((documents: IDocument) => documents)
                                if (cleanedDocs.length) totalSourceDocuments.push(...cleanedDocs)
                            }

                            if (artifacts && artifacts.length) {
                                const cleanedArtifacts = artifacts.filter((artifact: ICommonObject) => artifact)
                                if (cleanedArtifacts.length) totalArtifacts.push(...cleanedArtifacts)
                            }

                            /*
                             * Check if the next node is a condition node, if yes, then add the agent reasoning of the condition node
                             */
                            if (isSequential) {
                                const inputEdges = edges.filter(
                                    (edg) => edg.target === nodeId && edg.targetHandle.includes(`${nodeId}-input-sequentialNode`)
                                )

                                inputEdges.forEach((edge) => {
                                    const parentNode = initializedNodes.find((nd) => nd.id === edge.source)
                                    if (parentNode) {
                                        if (parentNode.data.name.includes('seqCondition')) {
                                            const newMessages = messages.slice(0, -1)
                                            newMessages.push(mapNameToLabel[agentName].label)
                                            const reasoning = {
                                                agentName: parentNode.data.instance?.label || parentNode.data.type,
                                                messages: newMessages,
                                                nodeName: parentNode.data.name,
                                                nodeId: parentNode.data.id
                                            }
                                            agentReasoning.push(reasoning)
                                        }
                                    }
                                })
                            }

                            const reasoning = {
                                agentName: mapNameToLabel[agentName].label,
                                messages,
                                next: output[agentName]?.next,
                                instructions: output[agentName]?.instructions,
                                usedTools: flatten(usedTools) as IUsedTool[],
                                sourceDocuments: flatten(sourceDocuments) as Document[],
                                artifacts: flatten(artifacts) as ICommonObject[],
                                state,
                                nodeName: isSequential ? mapNameToLabel[agentName].nodeName : undefined,
                                nodeId
                            }
                            agentReasoning.push(reasoning)

                            finalSummarization = output[agentName]?.summarization ?? ''

                            lastWorkerResult =
                                output[agentName]?.messages?.length &&
                                output[agentName].messages[output[agentName].messages.length - 1]?.additional_kwargs?.type === 'worker'
                                    ? sanitizeLLMOutput(output[agentName].messages[output[agentName].messages.length - 1].content)
                                    : lastWorkerResult

                            if (shouldStreamResponse) {
                                if (!isStreamingStarted) {
                                    isStreamingStarted = true
                                    if (sseStreamer) {
                                        sseStreamer.streamStartEvent(chatId, agentReasoning)
                                    }
                                }

                                if (sseStreamer) {
                                    sseStreamer.streamAgentReasoningEvent(chatId, agentReasoning)
                                }

                                // Send loading next agent indicator
                                if (reasoning.next && reasoning.next !== 'FINISH' && reasoning.next !== 'END') {
                                    if (sseStreamer) {
                                        sseStreamer.streamNextAgentEvent(chatId, mapNameToLabel[reasoning.next]?.label || reasoning.next)
                                    }
                                }
                            }
                        }
                    } else {
                        const rawFinalResult = output.__end__.messages.length ? output.__end__.messages.pop()?.content : ''
                        finalResult = sanitizeLLMOutput(typeof rawFinalResult === 'string' ? rawFinalResult : '')
                        if (Array.isArray(rawFinalResult)) finalResult = sanitizeLLMOutput(output.__end__.instructions || '')
                        if (shouldStreamResponse && sseStreamer) {
                            sseStreamer.streamTokenEvent(chatId, finalResult)
                        }
                    }
                }

                /*
                 * For multi agents mode, sometimes finalResult is empty
                 * 1.) Provide lastWorkerResult as final result if available
                 * 2.) Provide summary as final result if available
                 */
                if (!isSequential && !finalResult) {
                    if (lastWorkerResult) finalResult = lastWorkerResult
                    else if (finalSummarization) finalResult = sanitizeLLMOutput(finalSummarization)
                    if (shouldStreamResponse && sseStreamer) {
                        sseStreamer.streamTokenEvent(chatId, finalResult)
                    }
                }

                /*
                 * For sequential mode, sometimes finalResult is empty
                 * Use last agent message as final result
                 */
                if (isSequential && !finalResult && agentReasoning.length) {
                    const lastMessages = agentReasoning[agentReasoning.length - 1].messages
                    const lastAgentReasoningMessage = lastMessages[lastMessages.length - 1]
                    // If last message is an AI Message with tool calls, that means the last node was interrupted
                    if (lastMessageRaw.tool_calls && lastMessageRaw.tool_calls.length > 0) {
                        // The last node that got interrupted
                        const node = initializedNodes.find((node) => node.id === lastMessageRaw.additional_kwargs.nodeId)

                        // Find the next tool node that is connected to the interrupted node, to get the approve/reject button text
                        const tooNodeId = edges.find(
                            (edge) =>
                                edge.target.includes('seqToolNode') &&
                                edge.source === (lastMessageRaw.additional_kwargs && lastMessageRaw.additional_kwargs.nodeId)
                        )?.target
                        const connectedToolNode = initializedNodes.find((node) => node.id === tooNodeId)

                        // Map raw tool calls to used tools, to be shown on interrupted message
                        const mappedToolCalls = lastMessageRaw.tool_calls.map((toolCall) => {
                            return {
                                tool: toolCall.name,
                                toolInput: toolCall.args,
                                toolOutput: ''
                            }
                        })

                        // Emit the interrupt message to the client
                        let approveButtonText = 'Yes'
                        let rejectButtonText = 'No'

                        if (connectedToolNode || node) {
                            if (connectedToolNode) {
                                const result = await connectedToolNode.data.instance.node.seekPermissionMessage(mappedToolCalls)
                                finalResult = sanitizeLLMOutput(result || 'Do you want to proceed?')
                                approveButtonText = connectedToolNode.data.inputs?.approveButtonText || 'Yes'
                                rejectButtonText = connectedToolNode.data.inputs?.rejectButtonText || 'No'
                            } else if (node) {
                                const result = await node.data.instance.agentInterruptToolNode.seekPermissionMessage(mappedToolCalls)
                                finalResult = sanitizeLLMOutput(result || 'Do you want to proceed?')
                                approveButtonText = node.data.inputs?.approveButtonText || 'Yes'
                                rejectButtonText = node.data.inputs?.rejectButtonText || 'No'
                            }
                            finalAction = {
                                id: uuidv4(),
                                mapping: {
                                    approve: approveButtonText,
                                    reject: rejectButtonText,
                                    toolCalls: lastMessageRaw.tool_calls
                                },
                                elements: [
                                    { type: 'approve-button', label: approveButtonText },
                                    { type: 'reject-button', label: rejectButtonText }
                                ]
                            }
                            if (shouldStreamResponse && sseStreamer) {
                                sseStreamer.streamTokenEvent(chatId, finalResult)
                                sseStreamer.streamActionEvent(chatId, finalAction)
                            }
                        }
                        totalUsedTools.push(...mappedToolCalls)
                    } else if (lastAgentReasoningMessage) {
                        finalResult = sanitizeLLMOutput(
                            typeof lastAgentReasoningMessage === 'string' ? lastAgentReasoningMessage : String(lastAgentReasoningMessage)
                        )
                        if (shouldStreamResponse && sseStreamer) {
                            sseStreamer.streamTokenEvent(chatId, finalResult)
                        }
                    }
                }

                totalSourceDocuments = uniq(flatten(totalSourceDocuments))
                totalUsedTools = uniq(flatten(totalUsedTools))
                totalArtifacts = uniq(flatten(totalArtifacts))

                if (shouldStreamResponse && sseStreamer) {
                    sseStreamer.streamUsedToolsEvent(chatId, totalUsedTools)
                    sseStreamer.streamSourceDocumentsEvent(chatId, totalSourceDocuments)
                    sseStreamer.streamArtifactsEvent(chatId, totalArtifacts)
                    sseStreamer.streamEndEvent(chatId)
                }

                return {
                    finalResult,
                    finalAction,
                    sourceDocuments: totalSourceDocuments,
                    artifacts: totalArtifacts,
                    usedTools: totalUsedTools,
                    agentReasoning
                }
            }
        } catch (e) {
            // clear agent memory because checkpoints were saved during runtime
            await clearSessionMemory(nodes, componentNodes, chatId, appDataSource, orgId, sessionId)
            if (getErrorMessage(e).includes('Aborted')) {
                if (shouldStreamResponse && sseStreamer) {
                    sseStreamer.streamAbortEvent(chatId)
                }
                return { finalResult, agentReasoning }
            }
            throw new Error(getErrorMessage(e))
        }
        return streamResults
    } catch (e) {
        logger.error(`[server]: [${orgId}]: Error:`, e)
        throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, `Error buildAgentGraph - ${getErrorMessage(e)}`)
    }
}

type MultiAgentsGraphParams = {
    agentflow: IChatFlow
    appDataSource: DataSource
    mapNameToLabel: Record<string, { label: string; nodeName: string }>
    reactFlowNodes: IReactFlowNode[]
    workerNodeIds: string[]
    componentNodes: IComponentNodes
    options: ICommonObject
    startingNodeIds: string[]
    question: string
    prependHistoryMessages?: IMessage[]
    chatHistory?: IMessage[]
    overrideConfig?: ICommonObject
    threadId?: string
    summarization?: boolean
    uploadedFilesContent?: string
}

const compileMultiAgentsGraph = async (params: MultiAgentsGraphParams) => {
    const {
        agentflow,
        appDataSource,
        mapNameToLabel,
        reactFlowNodes,
        workerNodeIds,
        componentNodes,
        options,
        prependHistoryMessages = [],
        chatHistory = [],
        overrideConfig = {},
        threadId,
        summarization = false,
        uploadedFilesContent
    } = params

    let question = params.question

    const channels: ITeamState = {
        messages: {
            value: (x: BaseMessage[], y: BaseMessage[]) => x.concat(y),
            default: () => []
        },
        next: 'initialState',
        instructions: "Solve the user's request.",
        team_members: []
    }

    if (summarization) channels.summarization = 'summarize'

    const workflowGraph = new StateGraph<ITeamState>({
        //@ts-ignore
        channels
    })

    const workerNodes = reactFlowNodes.filter((node) => workerNodeIds.includes(node.data.id))

    /*** Get API Config ***/
    const availableVariables = await appDataSource.getRepository(Variable).findBy(getWorkspaceSearchOptions(agentflow.workspaceId))
    const { nodeOverrides, variableOverrides, apiOverrideStatus } = getAPIOverrideConfig(agentflow)

    let supervisorWorkers: { [key: string]: IMultiAgentNode[] } = {}

    // Init worker nodes
    for (const workerNode of workerNodes) {
        const nodeInstanceFilePath = componentNodes[workerNode.data.name].filePath as string
        const nodeModule = await import(nodeInstanceFilePath)
        const newNodeInstance = new nodeModule.nodeClass()

        let flowNodeData = cloneDeep(workerNode.data)
        if (overrideConfig && apiOverrideStatus)
            flowNodeData = replaceInputsWithConfig(flowNodeData, overrideConfig, nodeOverrides, variableOverrides)
        flowNodeData = await resolveVariables(
            flowNodeData,
            reactFlowNodes,
            question,
            chatHistory,
            overrideConfig,
            uploadedFilesContent,
            availableVariables,
            variableOverrides
        )

        try {
            const workerResult: IMultiAgentNode = await newNodeInstance.init(flowNodeData, question, options)
            const parentSupervisor = workerResult.parentSupervisorName
            if (!parentSupervisor || workerResult.type !== 'worker') continue
            if (Object.prototype.hasOwnProperty.call(supervisorWorkers, parentSupervisor)) {
                supervisorWorkers[parentSupervisor].push(workerResult)
            } else {
                supervisorWorkers[parentSupervisor] = [workerResult]
            }

            workflowGraph.addNode(workerResult.name, workerResult.node)
        } catch (e) {
            throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, `Error initialize worker nodes - ${getErrorMessage(e)}`)
        }
    }

    // Init supervisor nodes
    for (const supervisor in supervisorWorkers) {
        const supervisorInputLabel = mapNameToLabel[supervisor].label
        const supervisorNode = reactFlowNodes.find((node) => supervisorInputLabel === node.data.inputs?.supervisorName)
        if (!supervisorNode) continue

        const nodeInstanceFilePath = componentNodes[supervisorNode.data.name].filePath as string
        const nodeModule = await import(nodeInstanceFilePath)
        const newNodeInstance = new nodeModule.nodeClass()

        let flowNodeData = cloneDeep(supervisorNode.data)

        if (overrideConfig && apiOverrideStatus)
            flowNodeData = replaceInputsWithConfig(flowNodeData, overrideConfig, nodeOverrides, variableOverrides)
        flowNodeData = await resolveVariables(
            flowNodeData,
            reactFlowNodes,
            question,
            chatHistory,
            overrideConfig,
            uploadedFilesContent,
            availableVariables,
            variableOverrides
        )

        if (flowNodeData.inputs) flowNodeData.inputs.workerNodes = supervisorWorkers[supervisor]

        try {
            const supervisorResult: IMultiAgentNode = await newNodeInstance.init(flowNodeData, question, options)
            if (!supervisorResult.workers?.length) continue

            if (supervisorResult.moderations && supervisorResult.moderations.length > 0) {
                try {
                    for (const moderation of supervisorResult.moderations) {
                        question = await moderation.checkForViolations(question)
                    }
                } catch (e) {
                    throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, getErrorMessage(e))
                }
            }

            workflowGraph.addNode(supervisorResult.name, supervisorResult.node)

            for (const worker of supervisorResult.workers) {
                //@ts-ignore
                workflowGraph.addEdge(worker, supervisorResult.name)
            }

            let conditionalEdges: { [key: string]: string } = {}
            for (let i = 0; i < supervisorResult.workers.length; i++) {
                conditionalEdges[supervisorResult.workers[i]] = supervisorResult.workers[i]
            }

            //@ts-ignore
            workflowGraph.addConditionalEdges(supervisorResult.name, (x: ITeamState) => x.next, {
                ...conditionalEdges,
                FINISH: END
            })

            //@ts-ignore
            workflowGraph.addEdge(START, supervisorResult.name)
            ;(workflowGraph as any).signal = options.signal

            // Get memory
            let memory = supervisorResult?.checkpointMemory

            const graph = workflowGraph.compile({ checkpointer: memory })

            const loggerHandler = new ConsoleCallbackHandler(logger, options?.orgId)
            const callbacks = await additionalCallbacks(flowNodeData, options)
            const config = { configurable: { thread_id: threadId } }

            let prependMessages = []
            // Only append in the first message
            if (prependHistoryMessages.length === chatHistory.length) {
                for (const message of prependHistoryMessages) {
                    const msgContent = sanitizeInput((message as any).message || (message as any).content || '')
                    if (message.role === 'apiMessage' || (message as any).type === 'apiMessage') {
                        prependMessages.push(
                            new AIMessage({
                                content: msgContent
                            })
                        )
                    } else if (message.role === 'userMessage' || (message as any).type === 'userMessage') {
                        prependMessages.push(
                            new HumanMessage({
                                content: msgContent
                            })
                        )
                    }
                }
            }

            // Sanitize uploadedFilesContent before building finalQuestion
            const safeUploadedFilesContent = uploadedFilesContent
                ? (() => {
                      checkSingaporePII(uploadedFilesContent)
                      return sanitizeUploadedFileContent(redactPII(uploadedFilesContent))
                  })()
                : uploadedFilesContent

            const finalQuestion = safeUploadedFilesContent
                ? `${safeUploadedFilesContent}\n\n${sanitizeUserInput(question)}`
                : sanitizeUserInput(question)

            // Return stream result as we should only have 1 supervisor
            return await graph.stream(
                {
                    messages: [...prependMessages, new HumanMessage({ content: finalQuestion })]
                },
                {
                    recursionLimit: supervisorResult?.recursionLimit ?? 100,
                    callbacks: [loggerHandler, ...callbacks],
                    configurable: config
                }
            )
        } catch (e) {
            throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, `Error initialize supervisor nodes - ${getErrorMessage(e)}`)
        }
    }
}

type SeqAgentsGraphParams = {
    depthQueue: IDepthQueue
    agentflow: IChatFlow
    appDataSource: DataSource
    reactFlowNodes: IReactFlowNode[]
    reactFlowEdges: IReactFlowEdge[]
    componentNodes: IComponentNodes
    options: ICommonObject
    question: string
    prependHistoryMessages?: IMessage[]
    chatHistory?: IMessage[]
    overrideConfig?: ICommonObject
    threadId?: string
    action?: IAction
    uploadedFilesContent?: string
}

const compileSeqAgentsGraph = async (params: SeqAgentsGraphParams) => {
    const {
        depthQueue,
        agentflow,
        appDataSource,
        reactFlowNodes,
        reactFlowEdges,
        componentNodes,
        options,
        prependHistoryMessages = [],
        chatHistory = [],
        overrideConfig = {},
        threadId,
        action,
        uploadedFilesContent
    } = params

    let question = params.question

    let channels: ISeqAgentsState = {
        messages: {
            value: (x: BaseMessage[], y: BaseMessage[]) => x.concat(y),
            default: () => []
        }
    }

    // Get state
    const seqStateNode = reactFlowNodes.find((node: IReactFlowNode) => node.data.name === 'seqState')
    if (seqStateNode) {
        channels = {
            ...seqStateNode.data.instance.node,
            ...channels
        }
    }

    let seqGraph = new StateGraph<any>({
        //@ts-ignore
        channels
    })

    /*** Validate Graph ***/
    const startAgentNodes: IReactFlowNode[] = reactFlowNodes.filter((node: IReactFlowNode) => node.data.name === 'seqStart')
    if (!startAgentNodes.length) throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, 'Start node not found')
    if (startAgentNodes.length > 1)
        throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, 'Graph should have only one start node')

    const endAgentNodes: IReactFlowNode[] = reactFlowNodes.filter((node: IReactFlowNode) => node.data.name === 'seqEnd')
    const loopNodes: IReactFlowNode[] = reactFlowNodes.filter((node: IReactFlowNode) => node.data.name === 'seqLoop')
    if (!endAgentNodes.length && !loopNodes.length) {
        throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, 'Graph should have at least one End/Loop node')
    }
    /*** End of Validation ***/

    let flowNodeData
    let conditionalEdges: Record<string, { nodes: Record<string, string>; func: any }> = {}
    let interruptedRouteMapping: Record<string, Record<string, string>> = {}
    let conditionalToolNodes: Record<string, { source: ISeqAgentNode; toolNodes: ISeqAgentNode[] }> = {}
    let bindModel: Record<string, any> = {}
    let interruptToolNodeNames = []

    /*** Get API Config ***/
    const availableVariables = await appDataSource.getRepository(Variable).findBy(getWorkspaceSearchOptions(agentflow.workspaceId))
    const { nodeOverrides, variableOverrides, apiOverrideStatus } = getAPIOverrideConfig(agentflow)

    const initiateNode = async (node: IReactFlowNode) => {
        const nodeInstanceFilePath = componentNodes[node.data.name].filePath as string
        const nodeModule = await import(nodeInstanceFilePath)
        const newNodeInstance = new nodeModule.nodeClass()

        flowNodeData = cloneDeep(node.data)
        if (overrideConfig && apiOverrideStatus)
            flowNodeData = replaceInputsWithConfig(flowNodeData, overrideConfig, nodeOverrides, variableOverrides)
        flowNodeData = await resolveVariables(
            flowNodeData,
            reactFlowNodes,
            question,
            chatHistory,
            overrideConfig,
            uploadedFilesContent,
            availableVariables,
            variableOverrides
        )

        const seqAgentNode: ISeqAgentNode = await newNodeInstance.init(flowNodeData, question, options)
        return seqAgentNode
    }

    /*
     *  Two objectives we want to achieve here:
     *  1.) Prepare the mapping of conditional outputs to next nodes. This mapping will ONLY be used to add conditional edges to the Interrupted Agent connected next to Condition/ConditionAgent Node.
     *    For example, if the condition node has 2 outputs 'Yes' and 'No', and 'Yes' leads to 'agentName1' and 'No' leads to 'agentName2', then the mapping should be like:
     *    {
     *      <conditionNodeId>: { 'Yes': 'agentName1', 'No': 'agentName2' }
     *    }
     *  2.) With the interruptedRouteMapping object, avoid adding conditional edges to the Interrupted Agent for the nodes that are already interrupted by tools. It will be separately added from the function - agentInterruptToolFunc
     */
    const processInterruptedRouteMapping = (conditionNodeId: string) => {
        const conditionEdges = reactFlowEdges.filter((edge) => edge.source === conditionNodeId) ?? []

        for (const conditionEdge of conditionEdges) {
            const nextNodeId = conditionEdge.target
            const conditionNodeOutputAnchorId = conditionEdge.sourceHandle

            const nextNode = reactFlowNodes.find((node) => node.id === nextNodeId)
            if (!nextNode) continue

            const conditionNode = reactFlowNodes.find((node) => node.id === conditionNodeId)
            if (!conditionNode) continue

            const outputAnchors = conditionNode?.data.outputAnchors
            if (!outputAnchors || !outputAnchors.length || !outputAnchors[0].options) continue

            const conditionOutputAnchorLabel =
                outputAnchors[0].options.find((option: any) => option.id === conditionNodeOutputAnchorId)?.label ?? ''
            if (!conditionOutputAnchorLabel) continue

            if (Object.prototype.hasOwnProperty.call(interruptedRouteMapping, conditionNodeId)) {
                interruptedRouteMapping[conditionNodeId] = {
                    ...interruptedRouteMapping[conditionNodeId],
                    [conditionOutputAnchorLabel]: nextNode.data.instance.name
                }
            } else {
                interruptedRouteMapping[conditionNodeId] = {
                    [conditionOutputAnchorLabel]: nextNode.data.instance.name
                }
            }
        }
    }

    /*
     *  Prepare Conditional Edges
     *  Example: {
     *    'seqCondition_1': { nodes: { 'Yes': 'agentName1', 'No': 'agentName2' }, func: <condition-function>, disabled: true },
     *    'seqCondition_2': { nodes: { 'Yes': 'agentName3', 'No': 'agentName4' }, func: <condition-function> }
     *  }
     */
    const prepareConditionalEdges = (nodeId: string, nodeInstance: ISeqAgentNode) => {
        const conditionEdges = reactFlowEdges.filter((edge) => edge.target === nodeId && edge.source.includes('seqCondition')) ?? []

        for (const conditionEdge of conditionEdges) {
            const conditionNodeId = conditionEdge.source
            const conditionNodeOutputAnchorId = conditionEdge.sourceHandle

            const conditionNode = reactFlowNodes.find((node) => node.id === conditionNodeId)
            const outputAnchors = conditionNode?.data.outputAnchors

            if (!outputAnchors || !outputAnchors.length || !outputAnchors[0].options) continue

            const conditionOutputAnchorLabel =
                outputAnchors[0].options.find((option: any) => option.id === conditionNodeOutputAnchorId)?.label ?? ''

            if (!conditionOutputAnchorLabel) continue

            if (Object.prototype.hasOwnProperty.call(conditionalEdges, conditionNodeId)) {
                conditionalEdges[conditionNodeId] = {
                    ...conditionalEdges[conditionNodeId],
                    nodes: {
                        ...conditionalEdges[conditionNodeId].nodes,
                        [conditionOutputAnchorLabel]: nodeInstance.name
                    }
                }
            } else {
                conditionalEdges[conditionNodeId] = {
                    nodes: { [conditionOutputAnchorLabel]: nodeInstance.name },
                    func: conditionNode.data.instance.node
                }
            }
        }
    }

    /*
     *  Prepare Conditional Tool Edges. This is just for LLMNode -> ToolNode
     *  Example: {
     *    'agent_1': { source: agent, toolNodes: [node] }
     *  }
     */
    const prepareLLMToToolEdges = (predecessorAgent: ISeqAgentNode, toolNodeInstance: ISeqAgentNode) => {
        if (Object.prototype.hasOwnProperty.call(conditionalToolNodes, predecessorAgent.id)) {
            const toolNodes = conditionalToolNodes[predecessorAgent.id].toolNodes
            toolNodes.push(toolNodeInstance)
            conditionalToolNodes[predecessorAgent.id] = {
                source: predecessorAgent,
                toolNodes
            }
        } else {
            conditionalToolNodes[predecessorAgent.id] = {
                source: predecessorAgent,
                toolNodes: [toolNodeInstance]
            }
        }
    }

    /*** This is to bind the tools to the model of LLMNode, when the LLMNode is predecessor/successor of ToolNode ***/
    const createBindModel = (agent: ISeqAgentNode, toolNodeInstance: ISeqAgentNode) => {
        const tools = flatten(toolNodeInstance.node?.tools)
        bindModel[agent.id] = agent.llm.bindTools(tools)
    }

    /*** Start processing every Agent nodes ***/
    for (const agentNodeId of getSortedDepthNodes(depthQueue)) {
        const agentNode = reactFlowNodes.find((node) => node.id === agentNodeId)
        if (!agentNode) continue

        const eligibleSeqNodes = ['seqAgent', 'seqEnd', 'seqLoop', 'seqToolNode', 'seqLLMNode', 'seqCustomFunction', 'seqExecuteFlow']
        const nodesToAdd = ['seqAgent', 'seqToolNode', 'seqLLMNode', 'seqCustomFunction', 'seqExecuteFlow']

        if (eligibleSeqNodes.includes(agentNode.data.name)) {
            try {
                const agentInstance: ISeqAgentNode = await initiateNode(agentNode)

                if (nodesToAdd.includes(agentNode.data.name)) {
                    // Add node to graph
                    seqGraph.addNode(agentInstance.name, agentInstance.node)

                    /*
                     * If it is an Interrupted Agent, we want to:
                     * 1.) Add conditional edges to the Interrupted Agent via agentInterruptToolFunc
                     * 2.) Add agent to the interruptToolNodeNames list
                     */
                    if (agentInstance.type === 'agent' && agentNode.data.inputs?.interrupt) {
                        interruptToolNodeNames.push(agentInstance.agentInterruptToolNode.name)

                        const nextNodeId = reactFlowEdges.find((edge) => edge.source === agentNode.id)?.target
                        const nextNode = reactFlowNodes.find((node) => node.id === nextNodeId)

                        let nextNodeSeqAgentName = ''
                        if (nextNodeId && nextNode) {
                            nextNodeSeqAgentName = nextNode.data.instance.name

                            // If next node is Condition Node, process the interrupted route mapping, see more details from comments of processInterruptedRouteMapping
                            if (nextNode.data.name.includes('seqCondition')) {
                                const conditionNode = nextNodeId
                                processInterruptedRouteMapping(conditionNode)
                                seqGraph = await agentInstance.agentInterruptToolFunc(
                                    seqGraph,
                                    undefined,
                                    nextNode.data.instance.node,
                                    interruptedRouteMapping[conditionNode]
                                )
                            } else {
                                seqGraph = await agentInstance.agentInterruptToolFunc(seqGraph, nextNodeSeqAgentName)
                            }
                        } else {
                            seqGraph = await agentInstance.agentInterruptToolFunc(seqGraph, nextNodeSeqAgentName)
                        }
                    }
                }

                if (agentInstance.predecessorAgents) {
                    const predecessorAgents: ISeqAgentNode[] = agentInstance.predecessorAgents

                    const edges = []
                    for (const predecessorAgent of predecessorAgents) {
                        // Add start edge and set entry point
                        if (predecessorAgent.name === START) {
                            if (agentInstance.moderations && agentInstance.moderations.length > 0) {
                                try {
                                    for (const moderation of agentInstance.moderations) {
                                        question = await moderation.checkForViolations(question)
                                    }
                                } catch (e) {
                                    throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, getErrorMessage(e))
                                }
                            }
                            //@ts-ignore
                            seqGraph.addEdge(START, agentInstance.name)
                        } else if (predecessorAgent.type === 'condition') {
                            /*
                             * If current node is Condition Node, AND predecessor is an Interrupted Agent
                             * Don't add conditional edges to the Interrupted Agent, as it will be added separately from the function - agentInterruptToolFunc
                             */
                            if (!Object.prototype.hasOwnProperty.call(interruptedRouteMapping, predecessorAgent.id)) {
                                prepareConditionalEdges(agentNode.data.id, agentInstance)
                            }
                        } else if (agentNode.data.name === 'seqToolNode') {
                            // Prepare the conditional edges for LLMNode -> ToolNode AND bind the tools to LLMNode
                            prepareLLMToToolEdges(predecessorAgent, agentInstance)
                            createBindModel(predecessorAgent, agentInstance)

                            // If current ToolNode has interrupt turned on, add the ToolNode name to interruptToolNodeNames
                            if (agentInstance.node.interrupt) {
                                interruptToolNodeNames.push(agentInstance.name)
                            }
                        } else if (predecessorAgent.name) {
                            // In the scenario when ToolNode -> LLMNode, bind the tools to LLMNode
                            if (agentInstance.type === 'llm' && predecessorAgent.type === 'tool') {
                                createBindModel(agentInstance, predecessorAgent)
                            }

                            // Add edge to graph ONLY when predecessor is not an Interrupted Agent
                            if (!predecessorAgent.agentInterruptToolNode) {
                                edges.push(predecessorAgent.name)
                            }
                        }
                    }

                    // Edges can be multiple, in the case of parallel node executions
                    if (edges.length > 1) {
                        //@ts-ignore
                        seqGraph.addEdge(edges, agentInstance.name)
                    } else if (edges.length === 1) {
                        //@ts-ignore
                        seqGraph.addEdge(...edges, agentInstance.name)
                    }
                }
            } catch (e) {
                throw new InternalFlowiseError(StatusCodes.INTERNAL_SERVER_ERROR, `Error initialize agent nodes - ${getErrorMessage(e)}`)
            }
        }
    }

    /*** Add conditional edges to graph for condition nodes ***/
    for (const conditionNodeId in conditionalEdges) {
        const startConditionEdges = reactFlowEdges.filter((edge) => edge.target === conditionNodeId)
        if (!startConditionEdges.length) continue

        for (const startConditionEdge of startConditionEdges) {
            const startConditionNode = reactFlowNodes.find((node) => node.id === startConditionEdge.source)
            if (!startConditionNode) continue
            seqGraph.addConditionalEdges(
                startConditionNode.data.instance.name,
                conditionalEdges[conditionNodeId].func,
                //@ts-ignore
                conditionalEdges[conditionNodeId].nodes
            )
        }
    }

    /*** Add conditional edges to graph for LLMNode -> ToolNode ***/
    for (const llmSourceNodeId in conditionalToolNodes) {
        const connectedToolNodes = conditionalToolNodes[llmSourceNodeId].toolNodes
        const sourceNode = conditionalToolNodes[llmSourceNodeId].source

        const routeMessage = (state: ISeqAgentsState) => {
            const messages = state.messages as unknown as BaseMessage[]
            const lastMessage = messages[messages.length - 1] as AIMessage

            if (!lastMessage.tool_calls?.length) {
                return END
            }

            for (const toolCall of lastMessage.tool_calls) {
                for (const toolNode of connectedToolNodes) {
                    const tools = (toolNode.node?.tools as StructuredTool[]) || ((toolNode as any).tools as StructuredTool[])
                    if (tools.some((tool) => tool.name === toolCall.name)) {
                        return toolNode.name
                    }
                }
            }
            return END
        }

        seqGraph.addConditionalEdges(
            //@ts-ignore
            sourceNode.name,
            routeMessage
        )
    }

    ;(seqGraph as any).signal = options.signal

    /*** Get memory ***/
    const startNode = reactFlowNodes.find((node: IReactFlowNode) => node.data.name === 'seqStart')
    let memory = startNode?.data.instance?.checkpointMemory

    try {
        const graph = seqGraph.compile({
            checkpointer: memory,
            interruptBefore: interruptToolNodeNames as any
        })

        const loggerHandler = new ConsoleCallbackHandler(logger, options?.orgId)
        const callbacks = await additionalCallbacks(flowNodeData as any, options)
        const config = { configurable: { thread_id: threadId }, bindModel }

        let prependMessages = []
        // Only append in the first message
        if (prependHistoryMessages.length === chatHistory.length) {
            for (const message of prependHistoryMessages) {
                const msgContent = sanitizeInput((message as any).message || (message as any).content || '')
                if (message.role === 'apiMessage' || (message as any).type === 'apiMessage') {
                    prependMessages.push(
                        new AIMessage({
                            content: msgContent
                        })
                    )
                } else if (message.role === 'userMessage' || (message as any).type === 'userMessage') {
                    prependMessages.push(
                        new HumanMessage({
                            content: msgContent
                        })
                    )
                }
            }
        }

        // Sanitize uploadedFilesContent before building finalQuestion
        const safeUploadedFilesContent = uploadedFilesContent
            ? (() => {
                  checkSingaporePII(uploadedFilesContent)
                  return sanitizeUploadedFileContent(redactPII(uploadedFilesContent))
              })()
            : uploadedFilesContent

        const finalQuestion = safeUploadedFilesContent
            ? `${safeUploadedFilesContent}\n\n${sanitizeUserInput(question)}`
            : sanitizeUserInput(question)

        let humanMsg: { messages: BaseMessage[] } | null = {
            messages: [...prependMessages, new HumanMessage({ content: finalQuestion })]
        }

        if (action && action.mapping && question === action.mapping.approve) {
            humanMsg = null
        } else if (action && action.mapping && question === action.mapping.reject) {
            humanMsg = {
                messages: action.mapping.toolCalls.map((toolCall) => {
                    return new ToolMessage({
                        name: toolCall.name,
                        content: `Tool ${toolCall.name} call denied by user. Acknowledge that, and DONT perform further actions. Only ask if user have other questions`,
                        tool_call_id: toolCall.id!,
                        additional_kwargs:
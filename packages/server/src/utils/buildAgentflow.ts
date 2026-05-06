import { DataSource } from 'typeorm'
import { v4 as uuidv4 } from 'uuid'
import { cloneDeep, get } from 'lodash'
import TurndownService from 'turndown'
import {
    AnalyticHandler,
    ICommonObject,
    ICondition,
    IFileUpload,
    IHumanInput,
    IMessage,
    IServerSideEventStreamer,
    convertChatHistoryToText,
    generateFollowUpPrompts,
    tracingEnvEnabled
} from 'flowise-components'
import {
    IncomingAgentflowInput,
    INodeData,
    IReactFlowObject,
    IExecuteFlowParams,
    IFlowConfig,
    IAgentflowExecutedData,
    ExecutionState,
    IExecution,
    IChatMessage,
    ChatType,
    IReactFlowNode,
    IReactFlowEdge,
    IComponentNodes,
    INodeOverrides,
    IVariableOverride,
    INodeDirectedGraph
} from '../Interface'
import {
    RUNTIME_MESSAGES_LENGTH_VAR_PREFIX,
    CHAT_HISTORY_VAR_PREFIX,
    databaseEntities,
    FILE_ATTACHMENT_PREFIX,
    getAppVersion,
    getGlobalVariable,
    getStartingNode,
    getTelemetryFlowObj,
    QUESTION_VAR_PREFIX,
    CURRENT_DATE_TIME_VAR_PREFIX,
    _removeCredentialId,
    validateHistorySchema,
    LOOP_COUNT_VAR_PREFIX
} from '.'
import { ChatFlow } from '../database/entities/ChatFlow'
import { Variable } from '../database/entities/Variable'
import { replaceInputsWithConfig, constructGraphs, getAPIOverrideConfig } from '../utils'
import logger from './logger'
import { getErrorMessage } from '../errors/utils'
import { Execution } from '../database/entities/Execution'
import { utilAddChatMessage } from './addChatMesage'
import { CachePool } from '../CachePool'
import { ChatMessage } from '../database/entities/ChatMessage'
import { Telemetry } from './telemetry'
import { getWorkspaceSearchOptions } from '../enterprise/utils/ControllerServiceUtils'
import { UsageCacheManager } from '../UsageCacheManager'
import { generateTTSForResponseStream, shouldAutoPlayTTS } from './buildChatflow'

interface IWaitingNode {
    nodeId: string
    receivedInputs: Map<string, any>
    expectedInputs: Set<string>
    isConditional: boolean
    conditionalGroups: Map<string, string[]>
}

interface INodeQueue {
    nodeId: string
    data: any
    inputs: Record<string, any>
}

interface IProcessNodeOutputsParams {
    nodeId: string
    nodeName: string
    result: any
    humanInput?: IHumanInput
    graph: Record<string, string[]>
    nodes: IReactFlowNode[]
    edges: IReactFlowEdge[]
    nodeExecutionQueue: INodeQueue[]
    waitingNodes: Map<string, IWaitingNode>
    loopCounts: Map<string, number>
    abortController?: AbortController
    sseStreamer?: IServerSideEventStreamer
    chatId: string
}

interface IAgentFlowRuntime {
    state?: ICommonObject
    chatHistory?: IMessage[]
    form?: Record<string, any>
}

interface IExecuteNodeParams {
    nodeId: string
    reactFlowNode: IReactFlowNode
    nodes: IReactFlowNode[]
    edges: IReactFlowEdge[]
    graph: INodeDirectedGraph
    reversedGraph: INodeDirectedGraph
    incomingInput: IncomingAgentflowInput
    chatflow: ChatFlow
    chatId: string
    sessionId: string
    apiMessageId: string
    evaluationRunId?: string
    isInternal: boolean
    pastChatHistory: IMessage[]
    prependedChatHistory: IMessage[]
    appDataSource: DataSource
    usageCacheManager: UsageCacheManager
    telemetry: Telemetry
    componentNodes: IComponentNodes
    cachePool: CachePool
    sseStreamer: IServerSideEventStreamer
    baseURL: string
    overrideConfig?: ICommonObject
    apiOverrideStatus?: boolean
    nodeOverrides?: INodeOverrides
    variableOverrides?: IVariableOverride[]
    uploadedFilesContent?: string
    fileUploads?: IFileUpload[]
    humanInput?: IHumanInput
    agentFlowExecutedData?: IAgentflowExecutedData[]
    agentflowRuntime: IAgentFlowRuntime
    abortController?: AbortController
    parentTraceIds?: ICommonObject
    analyticHandlers?: AnalyticHandler
    parentExecutionId?: string
    isRecursive?: boolean
    iterationContext?: ICommonObject
    loopCounts?: Map<string, number>
    orgId: string
    workspaceId: string
    subscriptionId: string
    productId: string
    interAgentAuthToken?: string
}

interface IExecuteAgentFlowParams extends Omit<IExecuteFlowParams, 'incomingInput'> {
    incomingInput: IncomingAgentflowInput
    interAgentAuthToken?: string
}

const MAX_LOOP_COUNT = process.env.MAX_LOOP_COUNT ? parseInt(process.env.MAX_LOOP_COUNT) : 10

// Maximum allowed input string length to prevent payload injection
const MAX_INPUT_LENGTH = 100000

// Approved component node name allowlist
const APPROVED_COMPONENT_NODES = new Set([
    'startAgentflow',
    'endAgentflow',
    'llmAgentflow',
    'agentAgentflow',
    'toolAgentflow',
    'conditionAgentflow',
    'conditionAgentAgentflow',
    'humanInputAgentflow',
    'loopAgentflow',
    'iterationAgentflow',
    'customFunctionAgentflow',
    'stickyNoteAgentflow',
    'subflowAgentflow',
    'requestsGet',
    'requestsPost',
    'requestsPut',
    'requestsDelete',
    'requestsPatch',
    'chatflowTool',
    'calculator',
    'serpAPI',
    'bingSearch',
    'braveSearch',
    'searchAPI',
    'serper',
    'googleCustomSearch',
    'openAITool',
    'anthropicTool',
    'mistralAITool',
    'groqTool',
    'ollamaTool',
    'azureOpenAITool',
    'googleVertexAITool',
    'awsBedrockTool',
    'togetherAITool',
    'fireworksAITool',
    'deepseekTool',
    'xAITool',
    'openAIAssistantTool',
    'retrieverTool',
    'writeFileTool',
    'readFileTool',
    'codeInterpreterTool',
    'webBrowserTool',
    'tavilySearch',
    'exa',
    'jinaSearch',
    'firecrawl',
    'apify',
    'gmail',
    'googleCalendar',
    'slack',
    'notion',
    'airtable',
    'github',
    'jira',
    'confluence',
    'zapier',
    'make',
    'n8n'
])

/**
 * Validates that a component node name is in the approved allowlist.
 * Throws an error if the node is not approved.
 */
const validateApprovedComponent = (nodeName: string): void => {
    if (!APPROVED_COMPONENT_NODES.has(nodeName)) {
        logger.warn(`[server]: Attempted to use non-approved component node: ${nodeName}`)
        throw new Error(`Component node '${nodeName}' is not in the approved components list and cannot be executed.`)
    }
}

/**
 * Sanitizes a string input value before substitution.
 * - Converts null/undefined to empty string
 * - Limits string length to prevent payload injection
 * - Strips null bytes and dangerous control characters
 */
const sanitizeInputValue = (value: any): string => {
    if (value === null || value === undefined) {
        return ''
    }
    let str = String(value)
    // Strip null bytes and dangerous control characters (except common whitespace)
    str = str.replace(/\x00/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    // Limit length
    if (str.length > MAX_INPUT_LENGTH) {
        logger.warn(`[server]: Input value truncated from ${str.length} to ${MAX_INPUT_LENGTH} characters`)
        str = str.substring(0, MAX_INPUT_LENGTH)
    }
    return str
}

/**
 * Sanitizes and validates MCP server tool output values before substitution.
 * Applies the same rules as sanitizeInputValue but also logs the sanitization.
 */
const sanitizeMCPOutput = (value: any, context: string): string => {
    if (value === null || value === undefined) {
        return ''
    }
    let str = typeof value === 'object' ? JSON.stringify(value) : String(value)
    // Strip null bytes and dangerous control characters
    str = str.replace(/\x00/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    // Limit length
    if (str.length > MAX_INPUT_LENGTH) {
        logger.warn(`[server]: MCP output value truncated in context '${context}' from ${str.length} to ${MAX_INPUT_LENGTH} characters`)
        str = str.substring(0, MAX_INPUT_LENGTH)
    }
    return str
}

/**
 * Sanitizes LLM output by checking for dangerous code execution primitives.
 * Throws or strips dangerous patterns from LLM-generated content.
 */
const sanitizeLLMOutput = (value: any, context: string): string => {
    if (value === null || value === undefined) {
        return ''
    }
    let str = typeof value === 'object' ? JSON.stringify(value) : String(value)

    // Patterns that indicate dynamic code execution attempts
    const dangerousPatterns = [
        /\beval\s*\(/gi,
        /\bexec\s*\(/gi,
        /\bexecSync\s*\(/gi,
        /\bspawnSync\s*\(/gi,
        /\bspawn\s*\(/gi,
        /\bchild_process\b/gi,
        /\brequire\s*\(\s*['"`]child_process['"`]\s*\)/gi,
        /\bFunction\s*\(/gi,
        /\bnew\s+Function\b/gi,
        /\bsetTimeout\s*\(\s*['"`]/gi,
        /\bsetInterval\s*\(\s*['"`]/gi,
        /\bimport\s*\(\s*['"`]/gi,
        /\bprocess\.binding\b/gi,
        /\bprocess\.dlopen\b/gi,
        /\b__import__\s*\(/gi,
        /\bsubprocess\b/gi,
        /\bos\.system\s*\(/gi,
        /\bos\.popen\s*\(/gi
    ]

    for (const pattern of dangerousPatterns) {
        if (pattern.test(str)) {
            logger.warn(`[server]: Dangerous code execution pattern detected in LLM output (context: ${context}). Pattern: ${pattern}`)
            // Strip the dangerous pattern rather than throwing to allow partial content
            str = str.replace(pattern, '[REDACTED]')
        }
    }

    // Strip null bytes and dangerous control characters
    str = str.replace(/\x00/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

    // Limit length
    if (str.length > MAX_INPUT_LENGTH) {
        logger.warn(`[server]: LLM output truncated in context '${context}' from ${str.length} to ${MAX_INPUT_LENGTH} characters`)
        str = str.substring(0, MAX_INPUT_LENGTH)
    }

    return str
}

/**
 * Sanitizes uploaded file content to prevent prompt injection attacks.
 * - Strips hidden/invisible Unicode characters
 * - Detects and rejects base64-encoded prompt injections
 * - Removes shell/binary command patterns
 * - Neutralizes leetspeak instruction overrides
 * - Truncates suspiciously long single-token lines
 */
const sanitizeUploadedFileContent = (content: string): string => {
    if (!content) return content

    // Strip hidden/invisible Unicode characters (zero-width, soft hyphen, etc.)
    let sanitized = content.replace(/[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00A0]/g, '')

    // Remove null bytes and dangerous control characters
    sanitized = sanitized.replace(/\x00/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

    // Detect base64-encoded content that might contain prompt injections
    // Base64 strings of significant length that decode to instruction-like content
    const base64Pattern = /[A-Za-z0-9+/]{100,}={0,2}/g
    sanitized = sanitized.replace(base64Pattern, (match) => {
        try {
            const decoded = Buffer.from(match, 'base64').toString('utf8')
            const injectionKeywords = /ignore\s+previous|disregard\s+instructions|system\s+prompt|you\s+are\s+now/i
            if (injectionKeywords.test(decoded)) {
                logger.warn('[server]: Base64-encoded prompt injection detected in uploaded file content, removing.')
                return '[REDACTED_BASE64]'
            }
        } catch {
            // Not valid base64, leave as is
        }
        return match
    })

    // Remove shell/binary command patterns
    const shellPatterns = [
        /\$\([^)]*\)/g,           // $(command)
        /`[^`]*`/g,               // `command`
        /\|\s*bash/gi,            // | bash
        /\|\s*sh\b/gi,            // | sh
        /;\s*rm\s+-/gi,           // ; rm -
        /&&\s*curl\s+/gi,         // && curl
        /&&\s*wget\s+/gi,         // && wget
    ]
    for (const pattern of shellPatterns) {
        sanitized = sanitized.replace(pattern, '[REDACTED_CMD]')
    }

    // Neutralize common prompt injection instruction overrides
    const injectionPatterns = [
        /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
        /you\s+are\s+now\s+/gi,
        /new\s+instructions?:/gi,
        /system\s+prompt:/gi,
        /\[system\]/gi,
        /\[assistant\]/gi,
        /<\|im_start\|>/gi,
        /<\|im_end\|>/gi,
    ]
    for (const pattern of injectionPatterns) {
        sanitized = sanitized.replace(pattern, '[REDACTED_INJECTION]')
    }

    // Truncate suspiciously long single-token lines (> 10000 chars without whitespace)
    sanitized = sanitized.replace(/\S{10000,}/g, (match) => {
        logger.warn(`[server]: Suspiciously long token in uploaded file content truncated (length: ${match.length})`)
        return match.substring(0, 1000) + '[TRUNCATED]'
    })

    // Overall length limit
    if (sanitized.length > MAX_INPUT_LENGTH * 10) {
        logger.warn(`[server]: Uploaded file content truncated from ${sanitized.length} characters`)
        sanitized = sanitized.substring(0, MAX_INPUT_LENGTH * 10)
    }

    return sanitized
}

/**
 * Redacts PII from uploaded file content before it is used in prompts.
 * Masks email addresses, phone numbers, SSNs, credit card numbers, etc.
 */
const redactPIIFromContent = (content: string): string => {
    if (!content) return content

    let redacted = content

    // Redact email addresses
    redacted = redacted.replace(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]')

    // Redact credit card numbers (various formats)
    redacted = redacted.replace(/\b(?:\d[ \-]?){13,16}\b/g, (match) => {
        // Simple Luhn-like check: if it looks like a CC number
        const digits = match.replace(/[\s\-]/g, '')
        if (digits.length >= 13 && digits.length <= 19 && /^\d+$/.test(digits)) {
            return '[REDACTED_CC]'
        }
        return match
    })

    // Redact US SSNs
    redacted = redacted.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, '[REDACTED_SSN]')

    // Redact US phone numbers
    redacted = redacted.replace(/\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[REDACTED_PHONE]')

    // Redact Singapore NRIC/FIN (S/T/F/G followed by 7 digits and a letter)
    redacted = redacted.replace(/\b[STFG]\d{7}[A-Z]\b/gi, '[REDACTED_NRIC]')

    // Redact Singapore phone numbers (+65 followed by 8 digits)
    redacted = redacted.replace(/\b(?:\+65[-.\s]?)?\d{4}[-.\s]?\d{4}\b/g, '[REDACTED_SG_PHONE]')

    // Redact passport numbers (generic pattern)
    redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, '[REDACTED_PASSPORT]')

    // Redact IP addresses
    redacted = redacted.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[REDACTED_IP]')

    return redacted
}

/**
 * Detects Singapore PII in content and throws if found.
 * Used to enforce Singapore PII policy on uploaded files.
 */
const detectSingaporePII = (content: string): void => {
    if (!content) return

    // Singapore NRIC/FIN
    if (/\b[STFG]\d{7}[A-Z]\b/i.test(content)) {
        throw new Error('Uploaded file content contains Singapore NRIC/FIN number. Processing blocked to protect PII.')
    }

    // Singapore phone numbers
    if (/\b(?:\+65[-.\s]?)?\d{4}[-.\s]?\d{4}\b/.test(content)) {
        // Only flag if it looks like a SG number (starts with 6, 8, or 9 after country code)
        if (/\b(?:\+65[-.\s]?)?[689]\d{3}[-.\s]?\d{4}\b/.test(content)) {
            logger.warn('[server]: Potential Singapore phone number detected in uploaded file content.')
            // Log warning but do not throw - redaction will handle it
        }
    }

    // Singapore postal codes (6 digits starting with valid district codes)
    // Just warn, don't block
}

/**
 * Generates an inter-agent authentication token for recursive sub-flow calls.
 */
const generateInterAgentAuthToken = (parentChatId: string, parentSessionId: string): string => {
    const secret = process.env.INTER_AGENT_SECRET || process.env.FLOWISE_SECRETKEY_OVERWRITE || 'flowise-inter-agent-secret'
    const payload = `${parentChatId}:${parentSessionId}:${Date.now()}`
    // Simple HMAC-like token using base64 encoding with secret prefix
    const token = Buffer.from(`${secret}:${payload}`).toString('base64')
    return token
}

/**
 * Validates an inter-agent authentication token for recursive sub-flow calls.
 */
const validateInterAgentAuthToken = (token: string | undefined): void => {
    if (!token) {
        throw new Error('Inter-agent authentication token is required for recursive sub-flow execution.')
    }
    const secret = process.env.INTER_AGENT_SECRET || process.env.FLOWISE_SECRETKEY_OVERWRITE || 'flowise-inter-agent-secret'
    try {
        const decoded = Buffer.from(token, 'base64').toString('utf8')
        if (!decoded.startsWith(`${secret}:`)) {
            throw new Error('Invalid inter-agent authentication token.')
        }
    } catch {
        throw new Error('Invalid inter-agent authentication token.')
    }
}

/**
 * Add execution to database
 * @param {DataSource} appDataSource
 * @param {string} agentflowId
 * @param {IAgentflowExecutedData[]} agentFlowExecutedData
 * @param {string} sessionId
 * @returns {Promise<Execution>}
 */
const addExecution = async (
    appDataSource: DataSource,
    agentflowId: string,
    agentFlowExecutedData: IAgentflowExecutedData[],
    sessionId: string,
    workspaceId: string
) => {
    logger.info(`[server]: MCP interaction - addExecution: agentflowId=${agentflowId}, sessionId=${sessionId}, workspaceId=${workspaceId}`)
    const newExecution = new Execution()
    const bodyExecution = {
        agentflowId,
        state: 'INPROGRESS',
        sessionId,
        workspaceId,
        executionData: JSON.stringify(agentFlowExecutedData)
    }
    Object.assign(newExecution, bodyExecution)

    const execution = appDataSource.getRepository(Execution).create(newExecution)
    const savedExecution = await appDataSource.getRepository(Execution).save(execution)
    logger.info(`[server]: MCP interaction - addExecution completed: executionId=${savedExecution.id}`)
    return savedExecution
}

/**
 * Update execution in database
 * @param {DataSource} appDataSource
 * @param {string} executionId
 * @param {Partial<IExecution>} data
 * @returns {Promise<void>}
 */
const updateExecution = async (appDataSource: DataSource, executionId: string, workspaceId: string, data?: Partial<IExecution>) => {
    logger.info(`[server]: MCP interaction - updateExecution: executionId=${executionId}, workspaceId=${workspaceId}, state=${data?.state}`)
    const execution = await appDataSource.getRepository(Execution).findOneBy({
        id: executionId,
        workspaceId
    })

    if (!execution) {
        throw new Error(`Execution ${executionId} not found`)
    }

    const updateExecution = new Execution()
    const bodyExecution: ICommonObject = {}
    if (data && data.executionData) {
        bodyExecution.executionData = typeof data.executionData === 'string' ? data.executionData : JSON.stringify(data.executionData)
    }
    if (data && data.state) {
        bodyExecution.state = data.state

        if (data.state === 'STOPPED') {
            bodyExecution.stoppedDate = new Date()
        }
    }

    Object.assign(updateExecution, bodyExecution)

    appDataSource.getRepository(Execution).merge(execution, updateExecution)
    await appDataSource.getRepository(Execution).save(execution)
    logger.info(`[server]: MCP interaction - updateExecution completed: executionId=${executionId}`)
}

export const resolveVariables = async (
    reactFlowNodeData: INodeData,
    question: string,
    form: Record<string, any>,
    flowConfig: IFlowConfig | undefined,
    availableVariables: Variable[],
    variableOverrides: IVariableOverride[],
    uploadedFilesContent: string,
    chatHistory: IMessage[],
    componentNodes: IComponentNodes,
    agentFlowExecutedData?: IAgentflowExecutedData[],
    iterationContext?: ICommonObject,
    loopCounts?: Map<string, number>
): Promise<INodeData> => {
    let flowNodeData = cloneDeep(reactFlowNodeData)
    const types = 'inputs'

    const resolveNodeReference = async (value: any): Promise<any> => {
        // If value is an array, process each element
        if (Array.isArray(value)) {
            return Promise.all(value.map((item) => resolveNodeReference(item)))
        }

        // If value is an object, process each property
        if (typeof value === 'object' && value !== null) {
            const resolvedObj: any = {}
            for (const [key, val] of Object.entries(value)) {
                resolvedObj[key] = await resolveNodeReference(val)
            }
            return resolvedObj
        }

        // If value is not a string, return as is
        if (typeof value !== 'string') return value

        // Convert legacy HTML content to markdown, preserving any markdown syntax within.
        // Legacy content from old getHTML() starts with a TipTap block tag (e.g. <p>text</p>).
        // Anchor with ^ to avoid matching intentional HTML/XML tags in user prompts
        // (e.g. <instruction><div>...</div></instruction>).
        if (/^\s*<(?:p|div|h[1-6]|ul|ol|blockquote|pre|table)\b/i.test(value)) {
            const turndownService = new TurndownService()
            // Disable escaping so markdown characters (e.g. ###, -, *) inside HTML are preserved as-is
            turndownService.escape = (str: string) => str
            value = turndownService.turndown(value)
        }

        const matches = value.match(/{{(.*?)}}/g)

        if (!matches) return value

        let resolvedValue = value
        for (const match of matches) {
            // Remove {{ }} and trim whitespace
            const reference = match.replace(/[{}]/g, '').trim()
            const variableFullPath = reference

            if (variableFullPath === QUESTION_VAR_PREFIX) {
                const sanitizedQuestion = sanitizeInputValue(question)
                resolvedValue = resolvedValue.replace(match, sanitizedQuestion)
                if (uploadedFilesContent) {
                    // Sanitize, redact PII, and check for Singapore PII in uploaded file content
                    let sanitizedUploadedContent = sanitizeUploadedFileContent(uploadedFilesContent)
                    detectSingaporePII(sanitizedUploadedContent)
                    sanitizedUploadedContent = redactPIIFromContent(sanitizedUploadedContent)
                    resolvedValue = `${sanitizedUploadedContent}\n\n${resolvedValue}`
                }
            }

            if (variableFullPath.startsWith('$form.')) {
                const variableValue = get(form, variableFullPath.replace('$form.', ''))
                if (variableValue != null) {
                    // For arrays and objects, stringify them to prevent toString() conversion issues
                    const rawValue =
                        Array.isArray(variableValue) || (typeof variableValue === 'object' && variableValue !== null)
                            ? JSON.stringify(variableValue)
                            : variableValue
                    const formattedValue = sanitizeInputValue(rawValue)
                    resolvedValue = resolvedValue.replace(match, formattedValue)
                }
            }

            if (variableFullPath === FILE_ATTACHMENT_PREFIX) {
                let sanitizedUploadedContent = sanitizeUploadedFileContent(uploadedFilesContent)
                detectSingaporePII(sanitizedUploadedContent)
                sanitizedUploadedContent = redactPIIFromContent(sanitizedUploadedContent)
                resolvedValue = resolvedValue.replace(match, sanitizedUploadedContent)
            }

            if (variableFullPath === CHAT_HISTORY_VAR_PREFIX) {
                const sanitizedChatHistory = sanitizeInputValue(convertChatHistoryToText(chatHistory))
                resolvedValue = resolvedValue.replace(match, sanitizedChatHistory)
            }

            if (variableFullPath === RUNTIME_MESSAGES_LENGTH_VAR_PREFIX) {
                resolvedValue = resolvedValue.replace(match, flowConfig?.runtimeChatHistoryLength ?? 0)
            }

            if (variableFullPath === LOOP_COUNT_VAR_PREFIX) {
                // Get the current loop count from the most recent loopAgentflow node execution
                let currentLoopCount = 0
                if (loopCounts && agentFlowExecutedData) {
                    // Find the most recent loopAgentflow node execution to get its loop count
                    const loopNodes = [...agentFlowExecutedData].reverse().filter((data) => data.data?.name === 'loopAgentflow')
                    if (loopNodes.length > 0) {
                        const latestLoopNode = loopNodes[0]
                        currentLoopCount = loopCounts.get(latestLoopNode.nodeId) || 0
                    }
                }
                resolvedValue = resolvedValue.replace(match, currentLoopCount.toString())
            }

            if (variableFullPath === CURRENT_DATE_TIME_VAR_PREFIX) {
                resolvedValue = resolvedValue.replace(match, new Date().toISOString())
            }

            if (variableFullPath.startsWith('$iteration')) {
                if (iterationContext && iterationContext.value) {
                    if (variableFullPath === '$iteration') {
                        // If it's exactly $iteration, stringify the entire value
                        const rawValue =
                            typeof iterationContext.value === 'object' ? JSON.stringify(iterationContext.value) : iterationContext.value
                        const formattedValue = sanitizeInputValue(rawValue)
                        resolvedValue = resolvedValue.replace(match, formattedValue)
                    } else if (typeof iterationContext.value === 'string') {
                        resolvedValue = resolvedValue.replace(match, sanitizeInputValue(iterationContext?.value))
                    } else if (typeof iterationContext.value === 'object') {
                        const iterationValue = get(iterationContext.value, variableFullPath.replace('$iteration.', ''))
                        // For arrays and objects, stringify them to prevent toString() conversion issues
                        const rawValue =
                            Array.isArray(iterationValue) || (typeof iterationValue === 'object' && iterationValue !== null)
                                ? JSON.stringify(iterationValue)
                                : iterationValue
                        const formattedValue = sanitizeInputValue(rawValue)
                        resolvedValue = resolvedValue.replace(match, formattedValue)
                    }
                }
            }

            if (variableFullPath.startsWith('$vars.')) {
                const vars = await getGlobalVariable(flowConfig, availableVariables, variableOverrides)
                const variableValue = get(vars, variableFullPath.replace('$vars.', ''))
                if (variableValue != null) {
                    // For arrays and objects, stringify them to prevent toString() conversion issues
                    const rawValue =
                        Array.isArray(variableValue) || (typeof variableValue === 'object' && variableValue !== null)
                            ? JSON.stringify(variableValue)
                            : variableValue
                    const formattedValue = sanitizeInputValue(rawValue)
                    resolvedValue = resolvedValue.replace(match, formattedValue)
                }
            }

            if (variableFullPath.startsWith('$flow.') && flowConfig) {
                const variableValue = get(flowConfig, variableFullPath.replace('$flow.', ''))
                if (variableValue != null) {
                    // For arrays and objects, stringify them to prevent toString() conversion issues
                    const rawValue =
                        Array.isArray(variableValue) || (typeof variableValue === 'object' && variableValue !== null)
                            ? JSON.stringify(variableValue)
                            : variableValue
                    const formattedValue = sanitizeInputValue(rawValue)
                    resolvedValue = resolvedValue.replace(match, formattedValue)
                }
            }

            // Check if the variable is an output reference like `nodeId.output.path`
            const outputMatch = variableFullPath.match(/^(.*?)\.output\.(.+)$/)
            if (outputMatch && agentFlowExecutedData) {
                // Extract nodeId and outputPath from the match
                const [, nodeIdPart, outputPath] = outputMatch
                // Clean nodeId (handle escaped underscores)
                const cleanNodeId = nodeIdPart.replace(/\\/g, '')

                // Find the last (most recent) matching node data instead of the first one
                const nodeData = [...agentFlowExecutedData].reverse().find((d) => d.nodeId === cleanNodeId)

                if (nodeData?.data?.output && outputPath.trim()) {
                    const variableValue = get(nodeData.data.output, outputPath)
                    if (variableValue !== undefined) {
                        logger.debug(`[server]: MCP tool output retrieved for node ${cleanNodeId}, path ${outputPath}`)
                        // Sanitize and validate MCP tool output
                        const rawValue =
                            Array.isArray(variableValue) || (typeof variableValue === 'object' && variableValue !== null)
                                ? JSON.stringify(variableValue)
                                : variableValue
                        const sanitizedValue = sanitizeMCPOutput(rawValue, `node:${cleanNodeId}:${outputPath}`)
                        const formattedValue = sanitizeLLMOutput(sanitizedValue, `node:${cleanNodeId}:${outputPath}`)
                        // If the resolved value is exactly the match, replace it directly
                        if (resolvedValue === match) {
                            resolvedValue = formattedValue
                        } else {
                            // Otherwise do a standard string‐replace
                            resolvedValue = String(resolvedValue).replace(match, String(formattedValue))
                        }
                        // Skip fallback logic
                        continue
                    }
                }
            }

            // Find node data in executed data
            // sometimes turndown value returns a backslash like `llmAgentflow\_1`, remove the backslash
            const cleanNodeId = variableFullPath.replace(/\\/g, '')
            // Find the last (most recent) matching node data instead of the first one
            const nodeData = agentFlowExecutedData
                ? [...agentFlowExecutedData].reverse().find((data) => data.nodeId === cleanNodeId)
                : undefined
            if (nodeData && nodeData.data) {
                logger.debug(`[server]: MCP tool output retrieved for node ${cleanNodeId}`)
                // Replace the reference with actual value
                const nodeOutput = nodeData.data['output'] as ICommonObject
                const rawActualValue = nodeOutput?.content ?? nodeOutput?.http?.data
                // Sanitize MCP output and LLM output
                const sanitizedActualValue = sanitizeMCPOutput(rawActualValue, `node:${cleanNodeId}`)
                const actualValue = sanitizeLLMOutput(sanitizedActualValue, `node:${cleanNodeId}`)
                // For arrays and objects, stringify them to prevent toString() conversion issues
                const formattedValue =
                    Array.isArray(actualValue) || (typeof actualValue === 'object' && actualValue !== null)
                        ? JSON.stringify(actualValue)
                        : actualValue?.toString() ?? match
                resolvedValue = resolvedValue.replace(match, formattedValue)
            }
        }

        return resolvedValue
    }

    const getParamValues = async (paramsObj: ICommonObject) => {
        /*
         * EXAMPLE SCENARIO:
         *
         * 1. Agent node has inputParam: { name: "agentTools", type: "array", array: [{ name: "agentSelectedTool", loadConfig: true }] }
         * 2. Inputs contain: { agentTools: [{ agentSelectedTool: "requestsGet", agentSelectedToolConfig: { requestsGetHeaders: "Bearer {{ $vars.TOKEN }}" } }] }
         * 3. We need to resolve the variable in requestsGetHeaders because RequestsGet node defines requestsGetHeaders with acceptVariable: true
         *
         * STEP 1: Find all parameters with loadConfig=true (e.g., "agentSelectedTool")
         * STEP 2: Find their values in inputs (e.g., "requestsGet")
         * STEP 3: Look up component node definition for "requestsGet"
         * STEP 4: Find which of its parameters have acceptVariable=true (e.g., "requestsGetHeaders")
         * STEP 5: Find the config object (e.g., "agentSelectedToolConfig")
         * STEP 6: Resolve variables in config parameters that accept variables
         */

        // Helper function to find params with loadConfig recursively
        // Example: Finds ["agentModel", "agentSelectedTool"] from the inputParams structure
        const findParamsWithLoadConfig = (inputParams: any[]): string[] => {
            const paramsWithLoadConfig: string[] = []

            for (const param of inputParams) {
                // Direct loadConfig param (e.g., agentModel with loadConfig: true)
                if (param.loadConfig === true) {
                    paramsWithLoadConfig.push(param.name)
                }

                // Check nested array parameters (e.g., agentTools.array contains agentSelectedTool with loadConfig: true)
                if (param.type === 'array' && param.array && Array.isArray(param.array)) {
                    const nestedParams = findParamsWithLoadConfig(param.array)
                    paramsWithLoadConfig.push(...nestedParams)
                }
            }

            return paramsWithLoadConfig
        }

        // Helper function to find value of a parameter recursively in nested objects/arrays
        // Example: Searches for "agentSelectedTool" value in complex nested inputs structure
        // Returns "requestsGet" when found in agentTools[0].agentSelectedTool
        const findParamValue = (obj: any, paramName: string): any => {
            if (typeof obj !== 'object' || obj === null) {
                return undefined
            }

            // Handle arrays (e.g., agentTools array)
            if (Array.isArray(obj)) {
                for (const item of obj) {
                    const result = findParamValue(item, paramName)
                    if (result !== undefined) {
                        return result
                    }
                }
                return undefined
            }

            // Direct property match
            if (Object.prototype.hasOwnProperty.call(obj, paramName)) {
                return obj[paramName]
            }

            // Recursively search nested objects
            for (const value of Object.values(obj)) {
                const result = findParamValue(value, paramName)
                if (result !== undefined) {
                    return result
                }
            }

            return undefined
        }

        // Helper function to process config parameters with acceptVariable
        // Example: Processes agentSelectedToolConfig object, resolving variables in requestsGetHeaders
        const processConfigParams = async (configObj: any, configParamWithAcceptVariables: string[]) => {
            if (typeof configObj !== 'object' || configObj === null) {
                return
            }

            // Handle arrays of config objects
            if (Array.isArray(configObj)) {
                for (const item of configObj) {
                    await processConfigParams(item, configParamWithAcceptVariables)
                }
                return
            }

            for (const [key, value] of Object.entries(configObj)) {
                // Only resolve variables for parameters that accept them
                // Example: requestsGetHeaders is in configParamWithAcceptVariables, so resolve "Bearer {{ $vars.TOKEN }}"
                if (configParamWithAcceptVariables.includes(key)) {
                    configObj[key] = await resolveNodeReference(value)
                }
            }
        }

        // STEP 1: Get all params with loadConfig from inputParams
        // Example result: ["agentModel", "agentSelectedTool"]
        const paramsWithLoadConfig = findParamsWithLoadConfig(reactFlowNodeData.inputParams)

        // STEP 2-6: Process each param with loadConfig
        for (const paramWithLoadConfig of paramsWithLoadConfig) {
            // STEP 2: Find the value of this parameter in the inputs
            // Example: paramWithLoadConfig="agentSelectedTool", paramValue="requestsGet"
            const paramValue = findParamValue(paramsObj, paramWithLoadConfig)

            if (paramValue && componentNodes[paramValue]) {
                // STEP 3: Get the node instance inputs to find params with acceptVariable
                // Example: componentNodes["requestsGet"] contains the RequestsGet node definition
                const nodeInstance = componentNodes[paramValue]
                const configParamWithAcceptVariables: string[] = []

                // STEP 4: Find which parameters of the component accept variables
                // Example: RequestsGet has inputs like { name: "requestsGetHeaders", acceptVariable: true }
                if (nodeInstance.inputs && Array.isArray(nodeInstance.inputs)) {
                    for (const input of nodeInstance.inputs) {
                        if (input.acceptVariable === true) {
                            configParamWithAcceptVariables.push(input.name)
                        }
                    }
                }
                // Example result: configParamWithAcceptVariables = ["requestsGetHeaders", "requestsGetUrl", ...]

                // STEP 5: Look for the config object (paramName + "Config")
                // Example: Look for "agentSelectedToolConfig" in the inputs
                const configParamName = paramWithLoadConfig + 'Config'

                // Find all config values (handle arrays)
                const findAllConfigValues = (obj: any, paramName: string): any[] => {
                    const results: any[] = []

                    if (typeof obj !== 'object' || obj === null) {
                        return results
                    }

                    // Handle arrays (e.g., agentTools array)
                    if (Array.isArray(obj)) {
                        for (const item of obj) {
                            results.push(...findAllConfigValues(item, paramName))
                        }
                        return results
                    }

                    // Direct property match
                    if (Object.prototype.hasOwnProperty.call(obj, paramName)) {
                        results.push(obj[paramName])
                    }

                    // Recursively search nested objects
                    for (const value of Object.values(obj)) {
                        results.push(...findAllConfigValues(value, paramName))
                    }

                    return results
                }

                const configValues = findAllConfigValues(paramsObj, configParamName)

                // STEP 6: Process all config objects to resolve variables
                // Example: Resolve "Bearer {{ $vars.TOKEN }}" in requestsGetHeaders
                if (configValues.length > 0 && configParamWithAcceptVariables.length > 0) {
                    for (const configValue of configValues) {
                        await processConfigParams(configValue, configParamWithAcceptVariables)
                    }
                }
            }
        }

        // Original logic for direct acceptVariable params (maintains backward compatibility)
        // Example: Direct params like agentUserMessage with acceptVariable: true
        for (const key in paramsObj) {
            const paramValue = paramsObj[key]
            const isAcceptVariable = reactFlowNodeData.inputParams.find((param) => param.name === key)?.acceptVariable ?? false
            if (isAcceptVariable) {
                paramsObj[key] = await resolveNodeReference(paramValue)
            }
        }
    }

    const paramsObj = flowNodeData[types] ?? {}
    await getParamValues(paramsObj)

    return flowNodeData
}

/*
 * Gets all input connections for a specific node
 * @param {IEdge[]} edges - Array of all edges (connections) in the workflow
 * @param {string} nodeId - ID of the node to get input connections for
 * @returns {IEdge[]} Array of input connections for the specified node
 *
 * @example
 * // For llmAgentflow_2 which has two inputs from llmAgentflow_0 and llmAgentflow_1
 * const connections = getNodeInputConnections(nodes, edges, 'llmAgentflow_2');
 * // Returns array of two edge objects connecting to llmAgentflow_2
 */
function getNodeInputConnections(edges: IReactFlowEdge[], nodeId: string): IReactFlowEdge[] {
    // Filter edges where target matches the nodeId
    const inputConnections = edges.filter((edge) => edge.target === nodeId)

    // Sort connections by sourceHandle to maintain consistent order
    // This is important for nodes that have multiple inputs that need to be processed in order
    inputConnections.sort((a, b) => {
        // Extract index from sourceHandle (e.g., "output-0" vs "output-1")
        const indexA = parseInt(a.sourceHandle.split('-').find((part) => !isNaN(parseInt(part))) || '0')
        const indexB = parseInt(b.sourceHandle.split('-').find((part) => !isNaN(parseInt(part))) || '0')
        return indexA - indexB
    })

    return inputConnections
}

/**
 * Analyzes node dependencies and sets up expected inputs
 */
function setupNodeDependencies(nodeId: string, edges: IReactFlowEdge[], nodes: IReactFlowNode[]): IWaitingNode {
    logger.debug(`\n🔍 Analyzing dependencies for node: ${nodeId}`)
    const inputConnections = getNodeInputConnections(edges, nodeId)
    const waitingNode: IWaitingNode = {
        nodeId,
        receivedInputs: new Map(),
        expectedInputs: new Set(),
        isConditional: false,
        conditionalGroups: new Map()
    }

    // Group inputs by their parent condition nodes
    const inputsByCondition = new Map<string | null, string[]>()

    for (const connection of inputConnections) {
        const sourceNode = nodes.find((n) => n.id === connection.source)
        if (!sourceNode) continue

        // Find if this input comes from a conditional branch
        const conditionParent = findConditionParent(connection.source, edges, nodes)

        if (conditionParent) {
            logger.debug(`  📌 Found conditional input from ${connection.source} (condition: ${conditionParent})`)
            waitingNode.isConditional = true
            const group = inputsByCondition.get(conditionParent) || []
            group.push(connection.source)
            inputsByCondition.set(conditionParent, group)
        } else {
            logger.debug(`  📌 Found required input from ${connection.source}`)
            waitingNode.expectedInputs.add(connection.source)
        }
    }

    // Set up conditional groups
    inputsByCondition.forEach((sources, conditionId) => {
        if (conditionId) {
            logger.debug(`  📋 Conditional group ${conditionId}: [${sources.join(', ')}]`)
            waitingNode.conditionalGroups.set(conditionId, sources)
        }
    })

    return waitingNode
}

/**
 * Finds the parent condition node for a given node, if any
 */
function findConditionParent(nodeId: string, edges: IReactFlowEdge[], nodes: IReactFlowNode[]): string | null {
    const currentNode = nodes.find((n) => n.id === nodeId)
    if (!currentNode) return null
    if (
        currentNode.data.name === 'conditionAgentflow' ||
        currentNode.data.name === 'conditionAgentAgentflow' ||
        currentNode.data.name === 'humanInputAgentflow'
    ) {
        return currentNode.id
    }

    let currentId = nodeId
    const visited = new Set<string>()

    let shouldContinue = true
    while (shouldContinue) {
        if (visited.has(currentId)) {
            shouldContinue = false
            continue
        }
        visited.add(currentId)

        const parentEdge = edges.find((edge) => edge.target === currentId)
        if (!parentEdge) {
            shouldContinue = false
            continue
        }

        const parentNode = nodes.find((n) => n.id === parentEdge.source)
        if (!parentNode) {
            shouldContinue = false
            continue
        }

        if (
            parentNode.data.name === 'conditionAgentflow' ||
            parentNode.data.name === 'conditionAgentAgentflow' ||
            parentNode.data.name === 'humanInputAgentflow'
        ) {
            return parentNode.id
        }

        currentId = parentNode.id
    }

    return null
}

/**
 * Checks if a node has received all required inputs
 */
function hasReceivedRequiredInputs(waitingNode: IWaitingNode): boolean {
    logger.debug(`\n✨ Checking inputs for node: ${waitingNode.nodeId}`)

    // Check non-conditional required inputs
    for (const required of waitingNode.expectedInputs) {
        const hasInput = waitingNode.receivedInputs.has(required)
        logger.debug(`  📊 Required input ${required}: ${hasInput ? '✅' : '❌'}`)
        if (!hasInput) return false
    }

    // Check conditional groups
    for (const [groupId, possibleSources] of waitingNode.conditionalGroups) {
        // Need at least one input from each conditional group
        const hasInputFromGroup = possibleSources.some((source) => waitingNode.receivedInputs.has(source))
        logger.debug(`  📊 Conditional group ${groupId}: ${hasInputFromGroup ? '✅' : '❌'}`)
        if (!hasInputFromGroup) return false
    }

    return true
}

/**
 * Determines which nodes should be ignored based on condition results
 * @param currentNode - The node being processed
 * @param result - The execution result from the node
 * @param edges - All edges in the workflow
 * @param nodeId - Current node ID
 * @returns Array of node IDs that should be ignored
 */
async function determineNodesToIgnore(
    currentNode: IReactFlowNode,
    result: any,
    edges: IReactFlowEdge[],
    nodeId: string
): Promise<string[]> {
    const ignoreNodeIds: string[] = []

    // Check if this is a decision node
    const isDecisionNode =
        currentNode.data.name === 'conditionAgentflow' ||
        currentNode.data.name === 'conditionAgentAgentflow' ||
        currentNode.data.name === 'humanInputAgentflow'

    if (isDecisionNode && result.output?.conditions) {
        const outputConditions: ICondition[] = result.output.conditions

        // safety net: if no conditions were fulfilled, don't ignore ALL children
        // treat the last condition as an else/default fallback
        const anyFulfilled = outputConditions.some((c) => c.isFulfilled === true)
        if (!anyFulfilled && outputConditions.length > 0) {
            // mark the last condition as fulfilled so at least one branch executes
            outputConditions[outputConditions.length - 1].isFulfilled = true
        }

        // Find indexes of unfulfilled conditions
        const unfulfilledIndexes = outputConditions
            .map((condition, index) =>
                condition.isFulfilled === false || !Object.prototype.hasOwnProperty.call(condition, 'isFulfilled') ? index : -1
            )
            .filter((index) => index !== -1)

        // Find nodes to ignore based on unfulfilled conditions
        for (const index of unfulfilledIndexes) {
            const ignoreEdge = edges.find((edge) => edge.source === nodeId && edge.sourceHandle === `${nodeId}-output-${index}`)

            if (ignoreEdge) {
                ignoreNodeIds.push(ignoreEdge.target)
            }
        }
    }

    return ignoreNodeIds
}

/**
 * Process node outputs and handle branching logic
 */
async function processNodeOutputs({
    nodeId,
    nodeName,
    result,
    humanInput,
    graph,
    nodes,
    edges,
    nodeExecutionQueue,
    waitingNodes,
    loopCounts,
    sseStreamer,
    chatId
}: IProcessNodeOutputsParams): Promise<{ humanInput?: IHumanInput }> {
    logger.debug(`\n🔄 Processing outputs from node: ${nodeId}`)

    let updatedHumanInput = humanInput

    const childNodeIds = graph[nodeId] || []
    logger.debug(`  👉 Child nodes: [${childNodeIds.join(', ')}]`)

    const currentNode = nodes.find((n) => n.id === nodeId)
    if (!currentNode) return { humanInput: updatedHumanInput }

    // Get nodes to ignore based on conditions
    const ignoreNodeIds = await determineNodesToIgnore(currentNode, result, edges, nodeId)
    if (ignoreNodeIds.length) {
        logger.debug(`  ⏭️  Skipping nodes: [${ignoreNodeIds.join(', ')}]`)
    }

    for (const childId of childNodeIds) {
        if (ignoreNodeIds.includes(childId)) continue

        const childNode = nodes.find((n) => n.id === childId)
        if (!childNode) continue

        logger.debug(`  📝 Processing child node: ${childId}`)

        let waitingNode = waitingNodes.get(childId)

        if (!waitingNode) {
            logger.debug(`    🆕 First time seeing node ${childId} - analyzing dependencies`)
            waitingNode = setupNodeDependencies(childId, edges, nodes)
            waitingNodes.set(childId, waitingNode)
        }

        waitingNode.receivedInputs.set(nodeId, result)
        logger.debug(`    ➕ Added input from ${nodeId}`)

        // Check if node is ready to execute
        if (hasReceivedRequiredInputs(waitingNode)) {
            logger.debug(`    ✅ Node ${childId} ready for execution!`)
            waitingNodes.delete(childId)
            nodeExecutionQueue.push({
                nodeId: childId,
                data: combineNodeInputs(waitingNode.receivedInputs),
                inputs: Object.fromEntries(waitingNode.receivedInputs)
            })
        } else {
            logger.debug(`    ⏳ Node ${childId} still waiting for inputs`)
            logger.debug(`      Has: [${Array.from(waitingNode.receivedInputs.keys()).join(', ')}]`)
            logger.debug(`      Needs: [${Array.from(waitingNode.expectedInputs).join(', ')}]`)
            if (waitingNode.conditionalGroups.size > 0) {
                logger.debug('      Conditional groups:')
                waitingNode.conditionalGroups.forEach((sources, groupId) => {
                    logger.debug(`        ${groupId}: [${sources.join(', ')}]`)
                })
            }
        }
    }

    if (nodeName === 'loopAgentflow' && result.output?.nodeID) {
        logger.debug(`  🔄 Looping back to node: ${result.output.nodeID}`)

        const loopCount = (loopCounts.get(nodeId) || 0) + 1
        const maxLoop = result.output.maxLoopCount || MAX_LOOP_COUNT

        if (loopCount < maxLoop) {
            logger.debug(`    Loop count: ${loopCount}/${maxLoop}`)
            loopCounts.set(nodeId, loopCount)
            nodeExecutionQueue.push({
                nodeId: result.output.nodeID,
                data: result.output,
                inputs: {}
            })

            // Clear humanInput when looping to prevent it from being reused
            if (updatedHumanInput) {
                logger.debug(`    🧹 Clearing humanInput for loop iteration`)
                updatedHumanInput = undefined
            }
        } else {
            logger.debug(`    ⚠️ Maximum loop count (${maxLoop}) reached, stopping loop`)
            const fallbackMessage = result.output.fallbackMessage || `Loop completed after reaching maximum iteration count of ${maxLoop}.`
            if (sseStreamer) {
                sseStreamer.streamTokenEvent(chatId, fallbackMessage)
            }
            result.output = { ...result.output, content: fallbackMessage }
        }
    }

    return { humanInput: updatedHumanInput }
}

/**
 * Combines inputs from multiple source nodes into a single input object
 * @param {Map<string, any>} receivedInputs - Map of inputs received from different nodes
 * @returns {any} Combined input data
 *
 * @example
 * const inputs = new Map();
 * inputs.set('node1', { json: { value: 1 }, text: 'Hello' });
 * inputs.set('node2', { json: { value: 2 }, text: 'World' });
 *
 * const combined = combineNodeInputs(inputs);
 *  Result:
 *  {
 *    json: {
 *      node1: { value: 1 },
 *      node2: { value: 2 }
 *    },
 *    text: 'Hello\nWorld'
 *  }
 */
function combineNodeInputs(receivedInputs: Map<string, any>): any {
    // Filter out null/undefined inputs
    const validInputs = new Map(Array.from(receivedInputs.entries()).filter(([_, value]) => value !== null && value !== undefined))

    if (validInputs.size === 0) {
        return null
    }

    if (validInputs.size === 1) {
        return Array.from(validInputs.values())[0]
    }

    // Initialize result object to store combined data
    const result: {
        json: any
        text?: string
        binary?: any
        error?: Error
    } = {
        json: {}
    }

    // Sort inputs by source node ID to ensure consistent ordering
    const sortedInputs = Array.from(validInputs.entries()).sort((a, b) => a[0].localeCompare(b[0]))

    for (const [sourceNodeId, inputData] of sortedInputs) {
        if (!inputData) continue

        try {
            // Handle different types of input data
            if (typeof inputData === 'object') {
                // Merge JSON data
                if (inputData.json) {
                    result.json = {
                        ...result.json,
                        [sourceNodeId]: inputData.json
                    }
                }

                // Combine text data if present
                if (inputData.text) {
                    result.text = result.text ? `${result.text}\n${inputData.text}` : inputData.text
                }

                // Merge binary data if present
                if (inputData.binary) {
                    result.binary = {
                        ...result.binary,
                        [sourceNodeId]: inputData.binary
                    }
                }

                // Handle error data
                if (inputData.error) {
                    result.error = inputData.error
                }
            } else {
                // Handle primitive data types
                result.json[sourceNodeId] = inputData
            }
        } catch (error) {
            // Log error but continue processing other inputs
            console.error(`Error combining input from node ${sourceNodeId}:`, error)
            result.error = error as Error
        }
    }

    // Special handling for text-only nodes
    if (Object.keys(result.json).length === 0 && result.text) {
        result.json = { text: result.text }
    }

    return result
}

/**
 * Executes a single node in the workflow
 * @param params - Parameters needed for node execution
 * @returns The result of the node execution
 */
const executeNode = async ({
    nodeId,
    reactFlowNode,
    nodes,
    edges,
    graph,
    reversedGraph,
    incomingInput,
    chatflow,
    chatId,
    sessionId,
    apiMessageId,
    evaluationRunId,
    parentExecutionId,
    pastChatHistory,
    prependedChatHistory,
    appDataSource,
    usageCacheManager,
    telemetry,
    componentNodes,
    cachePool,
    sseStreamer,
    baseURL,
    overrideConfig = {},
    apiOverrideStatus = false,
    nodeOverrides = {},
    variableOverrides = [],
    uploadedFilesContent = '',
    fileUploads,
    humanInput,
    agentFlowExecutedData = [],
    agentflowRuntime,
    abortController,
    parentTraceIds,
    analyticHandlers,
    isInternal,
    isRecursive,
    iterationContext,
    loopCounts,
    orgId,
    workspaceId,
    subscriptionId,
    productId,
    interAgentAuthToken
}: IExecuteNodeParams): Promise<{
    result:
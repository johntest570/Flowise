import { Request, Response, NextFunction } from 'express'
import agentflowv2Service from '../../services/agentflowv2-generator'

const MAX_QUESTION_LENGTH = 4000
const MAX_MODEL_LENGTH = 256

const DANGEROUS_CHARS_REGEX = /[<>"'`\\]/g
const CONTROL_CHARS_REGEX = /[\x00-\x1F\x7F]/g
const PROMPT_INJECTION_REGEX = /(\bignore\s+(previous|above|all)\s+instructions?\b|\bsystem\s*prompt\b|\bjailbreak\b)/gi
const DYNAMIC_CODE_PRIMITIVES_REGEX = /\b(eval|exec|Function\s*\(|new\s+Function|setTimeout\s*\(|setInterval\s*\(|execSync|execFile|spawnSync|spawn|child_process|require\s*\(|import\s*\(|__import__|os\.system|subprocess)\b/g

function sanitizeInput(value: string): string {
    let sanitized = value.trim()
    sanitized = sanitized.replace(CONTROL_CHARS_REGEX, '')
    sanitized = sanitized.replace(DANGEROUS_CHARS_REGEX, '')
    sanitized = sanitized.replace(PROMPT_INJECTION_REGEX, '')
    return sanitized
}

function sanitizeLLMOutput(output: unknown): unknown {
    if (typeof output === 'string') {
        return output.replace(DYNAMIC_CODE_PRIMITIVES_REGEX, '[REDACTED]')
    }
    if (Array.isArray(output)) {
        return output.map(sanitizeLLMOutput)
    }
    if (output !== null && typeof output === 'object') {
        const sanitized: Record<string, unknown> = {}
        for (const [key, value] of Object.entries(output as Record<string, unknown>)) {
            sanitized[key] = sanitizeLLMOutput(value)
        }
        return sanitized
    }
    return output
}

const generateAgentflowv2 = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.body.question || !req.body.selectedChatModel) {
            throw new Error('Question and selectedChatModel are required')
        }

        // Type checking
        if (typeof req.body.question !== 'string') {
            throw new Error('question must be a string')
        }
        if (typeof req.body.selectedChatModel !== 'string') {
            throw new Error('selectedChatModel must be a string')
        }

        // Length limits
        if (req.body.question.trim().length > MAX_QUESTION_LENGTH) {
            throw new Error(`question exceeds maximum allowed length of ${MAX_QUESTION_LENGTH} characters`)
        }
        if (req.body.selectedChatModel.trim().length > MAX_MODEL_LENGTH) {
            throw new Error(`selectedChatModel exceeds maximum allowed length of ${MAX_MODEL_LENGTH} characters`)
        }

        // Sanitize inputs
        const sanitizedQuestion = sanitizeInput(req.body.question)
        const sanitizedModel = sanitizeInput(req.body.selectedChatModel)

        if (!sanitizedQuestion) {
            throw new Error('question is empty after sanitization')
        }
        if (!sanitizedModel) {
            throw new Error('selectedChatModel is empty after sanitization')
        }

        // Log LLM request inputs
        console.info('[agentflowv2-generator] LLM request', {
            question: sanitizedQuestion,
            selectedChatModel: sanitizedModel
        })

        const apiResponse = await agentflowv2Service.generateAgentflowv2(sanitizedQuestion, sanitizedModel)

        // Log LLM response
        console.info('[agentflowv2-generator] LLM response', { apiResponse })

        // Sanitize LLM output for dynamic code execution primitives
        const sanitizedResponse = sanitizeLLMOutput(apiResponse)

        return res.json(sanitizedResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    generateAgentflowv2
}
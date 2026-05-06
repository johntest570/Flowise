import { createPortal } from 'react-dom'
import PropTypes from 'prop-types'
import { useState, useEffect, useRef } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { enqueueSnackbar as enqueueSnackbarAction, closeSnackbar as closeSnackbarAction } from '@/store/actions'
import { v4 as uuidv4 } from 'uuid'

import {
    Chip,
    Card,
    CardContent,
    Box,
    Typography,
    Button,
    IconButton,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Stack,
    OutlinedInput
} from '@mui/material'

import { TooltipWithParser } from '@/ui-component/tooltip/TooltipWithParser'
import { Dropdown } from '@/ui-component/dropdown/Dropdown'
import { MultiDropdown } from '@/ui-component/dropdown/MultiDropdown'
import CredentialInputHandler from '@/views/canvas/CredentialInputHandler'
import { File } from '@/ui-component/file/File'
import { BackdropLoader } from '@/ui-component/loading/BackdropLoader'
import DeleteConfirmDialog from './DeleteConfirmDialog'
import AssistantVectorStoreDialog from './AssistantVectorStoreDialog'
import { StyledPermissionButton } from '@/ui-component/button/RBACButtons'

// Icons
import { IconX, IconPlus } from '@tabler/icons-react'

// API
import assistantsApi from '@/api/assistants'

// Hooks
import useApi from '@/hooks/useApi'

// utils
import useNotifier from '@/utils/useNotifier'
import { HIDE_CANVAS_DIALOG, SHOW_CANVAS_DIALOG } from '@/store/actions'
import { maxScroll } from '@/store/constant'

// ─── Security / Validation Constants ────────────────────────────────────────

const ALLOWED_MIME_TYPES = [
    'text/plain',
    'text/csv',
    'text/html',
    'text/markdown',
    'application/pdf',
    'application/json',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'image/png',
    'image/jpeg',
    'image/gif',
    'image/webp'
]

const MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024 // 20 MB

const MAX_NAME_LENGTH = 256
const MAX_DESC_LENGTH = 512
const MAX_INSTRUCTIONS_LENGTH = 32768
const TEMPERATURE_MIN = 0
const TEMPERATURE_MAX = 2
const TOP_P_MIN = 0
const TOP_P_MAX = 1

// ─── Text Sanitization Helper ────────────────────────────────────────────────

const sanitizeText = (text) => {
    if (!text || typeof text !== 'string') return ''
    // Trim whitespace
    let sanitized = text.trim()
    // Strip null bytes and other dangerous control characters (keep newlines/tabs)
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    return sanitized
}

// ─── Assistant Input Validation ──────────────────────────────────────────────

const validateAssistantInputs = ({ assistantModel, assistantCredential, assistantName, assistantDesc, assistantInstructions, temperature, topP }) => {
    if (!assistantModel || !assistantCredential) {
        return 'Assistant Model and Credential are required.'
    }
    if (assistantName && assistantName.length > MAX_NAME_LENGTH) {
        return `Assistant Name must not exceed ${MAX_NAME_LENGTH} characters.`
    }
    if (assistantDesc && assistantDesc.length > MAX_DESC_LENGTH) {
        return `Assistant Description must not exceed ${MAX_DESC_LENGTH} characters.`
    }
    if (assistantInstructions && assistantInstructions.length > MAX_INSTRUCTIONS_LENGTH) {
        return `Assistant Instructions must not exceed ${MAX_INSTRUCTIONS_LENGTH} characters.`
    }
    const tempVal = parseFloat(temperature)
    if (!isNaN(tempVal) && (tempVal < TEMPERATURE_MIN || tempVal > TEMPERATURE_MAX)) {
        return `Temperature must be between ${TEMPERATURE_MIN} and ${TEMPERATURE_MAX}.`
    }
    const topPVal = parseFloat(topP)
    if (!isNaN(topPVal) && (topPVal < TOP_P_MIN || topPVal > TOP_P_MAX)) {
        return `Top P must be between ${TOP_P_MIN} and ${TOP_P_MAX}.`
    }
    return null
}

// ─── FormData File Validation ────────────────────────────────────────────────

const validateAndSanitizeFormData = (formData) => {
    const errors = []
    for (const [, value] of formData.entries()) {
        if (value instanceof File || (typeof value === 'object' && value.name && value.size !== undefined)) {
            const file = value
            if (!ALLOWED_MIME_TYPES.includes(file.type)) {
                errors.push(`File "${file.name}" has a disallowed type: ${file.type}.`)
            }
            if (file.size > MAX_FILE_SIZE_BYTES) {
                errors.push(`File "${file.name}" exceeds the maximum allowed size of ${MAX_FILE_SIZE_BYTES / (1024 * 1024)} MB.`)
            }
        }
    }
    return errors
}

// ─── Prompt Injection / Malicious Content Detection ─────────────────────────

const SUSPICIOUS_PROMPT_PATTERNS = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /you\s+are\s+now\s+(a\s+)?[\w\s]+assistant/i,
    /act\s+as\s+(a\s+)?[\w\s]+/i,
    /disregard\s+(all\s+)?(previous|prior|above)/i,
    /forget\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /new\s+instructions?:/i,
    /system\s*:\s*you/i,
    /\[system\]/i,
    /\[user\]/i,
    /\[assistant\]/i,
    /<\|im_start\|>/i,
    /<\|im_end\|>/i,
    /###\s*instruction/i,
    /###\s*system/i,
    /jailbreak/i,
    /prompt\s*injection/i,
    /bypass\s+(your\s+)?(safety|filter|restriction)/i,
    /override\s+(your\s+)?(safety|filter|restriction|instruction)/i
]

const INVISIBLE_UNICODE_PATTERN = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/

const BASE64_PROMPT_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

const BINARY_EXECUTABLE_SIGNATURES = [
    '\x7fELF',   // ELF binary
    'MZ',        // PE/DOS executable
    '\xca\xfe\xba\xbe', // Mach-O fat binary
    '\xfe\xed\xfa\xce', // Mach-O 32-bit
    '\xfe\xed\xfa\xcf', // Mach-O 64-bit
    '#!/',       // Shell script shebang
    '#!/'
]

const SHELL_COMMAND_PATTERN = /(\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\b\s*[\(\[`])/i

const isBase64EncodedPrompt = (str) => {
    if (!str || str.length < 20) return false
    if (!BASE64_PROMPT_PATTERN.test(str.trim())) return false
    try {
        const decoded = atob(str.trim())
        return SUSPICIOUS_PROMPT_PATTERNS.some((p) => p.test(decoded))
    } catch {
        return false
    }
}

const containsLeetspeak = (str) => {
    // Detect common leetspeak substitutions for suspicious words
    const leetspeakMap = { '4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '@': 'a', '$': 's' }
    let normalized = str.toLowerCase()
    for (const [leet, char] of Object.entries(leetspeakMap)) {
        normalized = normalized.split(leet).join(char)
    }
    return SUSPICIOUS_PROMPT_PATTERNS.some((p) => p.test(normalized))
}

const sanitizeFormDataFiles = async (formData) => {
    const suspiciousFiles = []

    for (const [, value] of formData.entries()) {
        if (value instanceof Blob || (typeof value === 'object' && value.name && value.size !== undefined)) {
            const file = value
            // Only scan text-based files for prompt injection
            if (file.type.startsWith('text/') || file.type === 'application/json') {
                const text = await file.text()

                // Check for invisible Unicode characters
                if (INVISIBLE_UNICODE_PATTERN.test(text)) {
                    suspiciousFiles.push(`"${file.name}" contains invisible/hidden Unicode characters.`)
                    continue
                }

                // Check for suspicious prompt injection patterns
                if (SUSPICIOUS_PROMPT_PATTERNS.some((p) => p.test(text))) {
                    suspiciousFiles.push(`"${file.name}" contains suspicious prompt injection content.`)
                    continue
                }

                // Check for base64-encoded prompts
                const words = text.split(/\s+/)
                if (words.some((w) => isBase64EncodedPrompt(w))) {
                    suspiciousFiles.push(`"${file.name}" contains base64-encoded suspicious content.`)
                    continue
                }

                // Check for leetspeak prompt injection
                if (containsLeetspeak(text)) {
                    suspiciousFiles.push(`"${file.name}" contains leetspeak prompt injection content.`)
                    continue
                }

                // Check for shell commands
                if (SHELL_COMMAND_PATTERN.test(text)) {
                    suspiciousFiles.push(`"${file.name}" contains suspicious shell command patterns.`)
                    continue
                }
            }

            // Check binary executables by reading first bytes
            if (
                file.type === 'application/octet-stream' ||
                file.type === '' ||
                file.name.match(/\.(exe|elf|sh|bat|cmd|ps1|msi|dll|so|dylib)$/i)
            ) {
                const buffer = await file.arrayBuffer()
                const bytes = new Uint8Array(buffer.slice(0, 8))
                const header = String.fromCharCode(...bytes)
                if (BINARY_EXECUTABLE_SIGNATURES.some((sig) => header.startsWith(sig))) {
                    suspiciousFiles.push(`"${file.name}" appears to be a binary executable.`)
                    continue
                }
            }
        }
    }

    return suspiciousFiles
}

// ─── PII Detection & Redaction ───────────────────────────────────────────────

const PII_PATTERNS = [
    { name: 'Email', pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: '[REDACTED_EMAIL]' },
    { name: 'Phone (US)', pattern: /(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}/g, replacement: '[REDACTED_PHONE]' },
    { name: 'SSN', pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, replacement: '[REDACTED_SSN]' },
    { name: 'Credit Card', pattern: /\b(?:\d[ \-]?){13,16}\b/g, replacement: '[REDACTED_CC]' },
    { name: 'IPv4', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[REDACTED_IP]' },
    // Singapore-specific PII
    { name: 'Singapore NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/gi, replacement: '[REDACTED_NRIC]' },
    { name: 'Singapore Phone', pattern: /\b[689]\d{7}\b/g, replacement: '[REDACTED_SG_PHONE]' },
    { name: 'Singapore Postal Code', pattern: /\bSingapore\s+\d{6}\b/gi, replacement: '[REDACTED_SG_POSTAL]' },
    { name: 'CPF Account', pattern: /\bCPF\s*[A-Z0-9]{6,12}\b/gi, replacement: '[REDACTED_CPF]' },
    { name: 'SingPass', pattern: /\bSingPass\s*[A-Z0-9]{6,12}\b/gi, replacement: '[REDACTED_SINGPASS]' }
]

const SINGAPORE_PII_PATTERNS = [
    { name: 'NRIC/FIN', pattern: /\b[STFGM]\d{7}[A-Z]\b/gi },
    { name: 'Singapore Phone', pattern: /\b[689]\d{7}\b/g },
    { name: 'Singapore Postal Code', pattern: /\bSingapore\s+\d{6}\b/gi },
    { name: 'CPF', pattern: /\bCPF\s*[A-Z0-9]{6,12}\b/gi },
    { name: 'SingPass', pattern: /\bSingPass\s*[A-Z0-9]{6,12}\b/gi },
    { name: 'FIN', pattern: /\bFIN\s*[STFGM]\d{7}[A-Z]\b/gi }
]

const redactPIIFromText = (text) => {
    let redacted = text
    for (const { pattern, replacement } of PII_PATTERNS) {
        redacted = redacted.replace(pattern, replacement)
    }
    return redacted
}

const detectSingaporePII = (text) => {
    const found = []
    for (const { name, pattern } of SINGAPORE_PII_PATTERNS) {
        if (pattern.test(text)) {
            found.push(name)
        }
        // Reset lastIndex for global patterns
        pattern.lastIndex = 0
    }
    return found
}

const scanAndRedactFormDataFiles = async (formData) => {
    const redactedFormData = new FormData()
    const sgPIIDetected = []

    for (const [key, value] of formData.entries()) {
        if (value instanceof Blob || (typeof value === 'object' && value.name && value.size !== undefined)) {
            const file = value
            if (file.type.startsWith('text/') || file.type === 'application/json') {
                const text = await file.text()

                // Check for Singapore PII — block upload if found
                const sgPII = detectSingaporePII(text)
                if (sgPII.length > 0) {
                    sgPIIDetected.push({ filename: file.name, types: sgPII })
                }

                // Redact general PII
                const redactedText = redactPIIFromText(text)
                const redactedBlob = new Blob([redactedText], { type: file.type })
                const redactedFile = new File([redactedBlob], file.name, { type: file.type, lastModified: file.lastModified })
                redactedFormData.append(key, redactedFile)
            } else {
                redactedFormData.append(key, value)
            }
        } else {
            redactedFormData.append(key, value)
        }
    }

    return { redactedFormData, sgPIIDetected }
}

// ─── Available Models ────────────────────────────────────────────────────────

const assistantAvailableModels = [
    {
        label: 'gpt-4.1',
        name: 'gpt-4.1'
    },
    {
        label: 'gpt-4.1-mini',
        name: 'gpt-4.1-mini'
    },
    {
        label: 'gpt-4.1-nano',
        name: 'gpt-4.1-nano'
    },
    {
        label: 'gpt-4.5-preview',
        name: 'gpt-4.5-preview'
    },
    {
        label: 'gpt-4o-mini',
        name: 'gpt-4o-mini'
    },
    {
        label: 'gpt-4o',
        name: 'gpt-4o'
    },
    {
        label: 'gpt-4-turbo',
        name: 'gpt-4-turbo'
    },
    {
        label: 'gpt-4-turbo-preview',
        name: 'gpt-4-turbo-preview'
    },
    {
        label: 'gpt-4-1106-preview',
        name: 'gpt-4-1106-preview'
    },
    {
        label: 'gpt-4-0613',
        name: 'gpt-4-0613'
    },
    {
        label: 'gpt-4',
        name: 'gpt-4'
    },
    {
        label: 'gpt-3.5-turbo',
        name: 'gpt-3.5-turbo'
    },
    {
        label: 'gpt-3.5-turbo-0125',
        name: 'gpt-3.5-turbo-0125'
    },
    {
        label: 'gpt-3.5-turbo-1106',
        name: 'gpt-3.5-turbo-1106'
    },
    {
        label: 'gpt-3.5-turbo-0613',
        name: 'gpt-3.5-turbo-0613'
    },
    {
        label: 'gpt-3.5-turbo-16k',
        name: 'gpt-3.5-turbo-16k'
    },
    {
        label: 'gpt-3.5-turbo-16k-0613',
        name: 'gpt-3.5-turbo-16k-0613'
    }
]

const AssistantDialog = ({ show, dialogProps, onCancel, onConfirm, setError }) => {
    const portalElement = document.getElementById('portal')
    useNotifier()
    const dispatch = useDispatch()
    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))
    const customization = useSelector((state) => state.customization)
    const dialogRef = useRef()

    // Sanitize image URL to prevent XSS attacks via javascript:, data:, or blob: schemes
    const sanitizeImageUrl = (url) => {
        const fallbackUrl = `https://api.dicebear.com/7.x/bottts/svg?seed=fallback`
        if (!url || typeof url !== 'string') {
            return fallbackUrl
        }
        try {
            const parsed = new URL(url, window.location.origin)
            // Only allow http and https protocols
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return url
            }
        } catch (e) {
            // Invalid URL
        }
        // Return default avatar if URL is invalid or uses disallowed protocol
        return fallbackUrl
    }

    const getSpecificAssistantApi = useApi(assistantsApi.getSpecificAssistant)
    const getAssistantObjApi = useApi(assistantsApi.getAssistantObj)

    const [assistantId, setAssistantId] = useState('')
    const [openAIAssistantId, setOpenAIAssistantId] = useState('')
    const [assistantName, setAssistantName] = useState('')
    const [assistantDesc, setAssistantDesc] = useState('')
    const [assistantIcon, setAssistantIcon] = useState(`https://api.dicebear.com/7.x/bottts/svg?seed=${uuidv4()}`)
    const [assistantModel, setAssistantModel] = useState('')
    const [assistantCredential, setAssistantCredential] = useState('')
    const [assistantInstructions, setAssistantInstructions] = useState('')
    const [assistantTools, setAssistantTools] = useState(['code_interpreter', 'file_search'])
    const [toolResources, setToolResources] = useState({})
    const [temperature, setTemperature] = useState(1)
    const [topP, setTopP] = useState(1)
    const [uploadCodeInterpreterFiles, setUploadCodeInterpreterFiles] = useState('')
    const [uploadVectorStoreFiles, setUploadVectorStoreFiles] = useState('')
    const [loading, setLoading] = useState(false)
    const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
    const [deleteDialogProps, setDeleteDialogProps] = useState({})
    const [assistantVectorStoreDialogOpen, setAssistantVectorStoreDialogOpen] = useState(false)
    const [assistantVectorStoreDialogProps, setAssistantVectorStoreDialogProps] = useState({})

    useEffect(() => {
        if (show) dispatch({ type: SHOW_CANVAS_DIALOG })
        else dispatch({ type: HIDE_CANVAS_DIALOG })
        return () => dispatch({ type: HIDE_CANVAS_DIALOG })
    }, [show, dispatch])

    useEffect(() => {
        if (getSpecificAssistantApi.data) {
            setAssistantId(getSpecificAssistantApi.data.id)
            setAssistantIcon(getSpecificAssistantApi.data.iconSrc)
            setAssistantCredential(getSpecificAssistantApi.data.credential)

            const assistantDetails = JSON.parse(getSpecificAssistantApi.data.details)
            setOpenAIAssistantId(assistantDetails.id)
            setAssistantName(assistantDetails.name)
            setAssistantDesc(assistantDetails.description)
            setAssistantModel(assistantDetails.model)
            setAssistantInstructions(assistantDetails.instructions)
            setTemperature(assistantDetails.temperature)
            setTopP(assistantDetails.top_p)
            setAssistantTools(assistantDetails.tools ?? [])
            setToolResources(assistantDetails.tool_resources ?? {})
        }
    }, [getSpecificAssistantApi.data])

    useEffect(() => {
        if (getAssistantObjApi.data) {
            syncData(getAssistantObjApi.data)
        }
    }, [getAssistantObjApi.data])

    useEffect(() => {
        if (getAssistantObjApi.error) {
            let errMsg = 'Internal Server Error'
            let error = getAssistantObjApi.error
            if (error?.response?.data) {
                errMsg = typeof error.response.data === 'object' ? error.response.data.message : error.response.data
            }
            enqueueSnackbar({
                message: `Failed to get assistant: ${errMsg}`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [getAssistantObjApi.error])

    useEffect(() => {
        if (getSpecificAssistantApi.error) {
            const error = getSpecificAssistantApi.error
            let errMsg = ''
            if (error?.response?.data) {
                errMsg = typeof error.response.data === 'object' ? error.response.data.message : error.response.data
            }
            enqueueSnackbar({
                message: `Failed to get assistant: ${errMsg}`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [getSpecificAssistantApi.error])

    useEffect(() => {
        if (dialogProps.type === 'EDIT' && dialogProps.data) {
            // When assistant dialog is opened from Assistants dashboard
            setAssistantId(dialogProps.data.id)
            setAssistantIcon(dialogProps.data.iconSrc)
            setAssistantCredential(dialogProps.data.credential)

            const assistantDetails = JSON.parse(dialogProps.data.details)
            setOpenAIAssistantId(assistantDetails.id)
            setAssistantName(assistantDetails.name)
            setAssistantDesc(assistantDetails.description)
            setAssistantModel(assistantDetails.model)
            setAssistantInstructions(assistantDetails.instructions)
            setTemperature(assistantDetails.temperature)
            setTopP(assistantDetails.top_p)
            setAssistantTools(assistantDetails.tools ?? [])
            setToolResources(assistantDetails.tool_resources ?? {})
        } else if (dialogProps.type === 'EDIT' && dialogProps.assistantId) {
            // When assistant dialog is opened from OpenAIAssistant node in canvas
            getSpecificAssistantApi.request(dialogProps.assistantId)
        } else if (dialogProps.type === 'ADD' && dialogProps.selectedOpenAIAssistantId && dialogProps.credential) {
            // When assistant dialog is to add new assistant from existing
            setAssistantId('')
            setAssistantIcon(`https://api.dicebear.com/7.x/bottts/svg?seed=${uuidv4()}`)
            setAssistantCredential(dialogProps.credential)

            getAssistantObjApi.request(dialogProps.selectedOpenAIAssistantId, dialogProps.credential)
        } else if (dialogProps.type === 'ADD' && !dialogProps.selectedOpenAIAssistantId) {
            // When assistant dialog is to add a blank new assistant
            setAssistantId('')
            setAssistantIcon(`https://api.dicebear.com/7.x/bottts/svg?seed=${uuidv4()}`)
            setAssistantCredential('')

            setOpenAIAssistantId('')
            setAssistantName('')
            setAssistantDesc('')
            setAssistantModel('')
            setAssistantInstructions('')
            setTemperature(1)
            setTopP(1)
            setAssistantTools(['code_interpreter', 'file_search'])
            setUploadCodeInterpreterFiles('')
            setUploadVectorStoreFiles('')
            setToolResources({})
        }

        return () => {
            setAssistantId('')
            setAssistantIcon(`https://api.dicebear.com/7.x/bottts/svg?seed=${uuidv4()}`)
            setAssistantCredential('')

            setOpenAIAssistantId('')
            setAssistantName('')
            setAssistantDesc('')
            setAssistantModel('')
            setAssistantInstructions('')
            setTemperature(1)
            setTopP(1)
            setAssistantTools(['code_interpreter', 'file_search'])
            setUploadCodeInterpreterFiles('')
            setUploadVectorStoreFiles('')
            setToolResources({})
            setLoading(false)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [dialogProps])

    const syncData = (data) => {
        setOpenAIAssistantId(data.id)
        setAssistantName(data.name)
        setAssistantDesc(data.description)
        setAssistantModel(data.model)
        setAssistantInstructions(data.instructions)
        setTemperature(data.temperature)
        setTopP(data.top_p)
        setToolResources(data.tool_resources ?? {})

        let tools = []
        if (data.tools && data.tools.length) {
            for (const tool of data.tools) {
                tools.push(tool.type)
            }
        }
        setAssistantTools(tools)
    }

    const onEditAssistantVectorStoreClick = (vectorStoreObject) => {
        const dialogProp = {
            title: `Edit ${vectorStoreObject.name ? vectorStoreObject.name : vectorStoreObject.id}`,
            type: 'EDIT',
            cancelButtonName: 'Cancel',
            confirmButtonName: 'Save',
            data: vectorStoreObject,
            credential: assistantCredential
        }
        setAssistantVectorStoreDialogProps(dialogProp)
        setAssistantVectorStoreDialogOpen(true)
    }

    const onAddAssistantVectorStoreClick = () => {
        const dialogProp = {
            title: `Add Vector Store`,
            type: 'ADD',
            cancelButtonName: 'Cancel',
            confirmButtonName: 'Add',
            credential: assistantCredential
        }
        setAssistantVectorStoreDialogProps(dialogProp)
        setAssistantVectorStoreDialogOpen(true)
    }

    const addNewAssistant = async () => {
        // Validate inputs before proceeding
        const validationError = validateAssistantInputs({
            assistantModel,
            assistantCredential,
            assistantName: sanitizeText(assistantName),
            assistantDesc: sanitizeText(assistantDesc),
            assistantInstructions: sanitizeText(assistantInstructions),
            temperature,
            topP
        })
        if (validationError) {
            enqueueSnackbar({
                message: validationError,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        setLoading(true)
        try {
            const assistantDetails = {
                id: openAIAssistantId,
                name: sanitizeText(assistantName),
                description: sanitizeText(assistantDesc),
                model: assistantModel,
                instructions: sanitizeText(assistantInstructions),
                temperature: temperature ? parseFloat(temperature) : null,
                top_p: topP ? parseFloat(topP) : null,
                tools: assistantTools,
                tool_resources: toolResources
            }
            const obj = {
                details: JSON.stringify(assistantDetails),
                iconSrc: assistantIcon,
                credential: assistantCredential,
                type: 'OPENAI'
            }

            const createResp = await assistantsApi.createNewAssistant(obj)
            if (createResp.data) {
                enqueueSnackbar({
                    message: 'New Assistant added',
                    options: {
                        key: new Date().getTime() + Math.random(),
                        variant: 'success',
                        action: (key) => (
                            <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                <IconX />
                            </Button>
                        )
                    }
                })
                onConfirm(createResp.data.id)
            }
            setLoading(false)
        } catch (error) {
            enqueueSnackbar({
                message: `Failed to add new Assistant: ${
                    typeof error.response.data === 'object' ? error.response.data.message : error.response.data
                }`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            setLoading(false)
        }
    }

    const saveAssistant = async () => {
        // Validate inputs before proceeding
        const validationError = validateAssistantInputs({
            assistantModel,
            assistantCredential,
            assistantName: sanitizeText(assistantName),
            assistantDesc: sanitizeText(assistantDesc),
            assistantInstructions: sanitizeText(assistantInstructions),
            temperature,
            topP
        })
        if (validationError) {
            enqueueSnackbar({
                message: validationError,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        setLoading(true)
        try {
            const assistantDetails = {
                name: sanitizeText(assistantName),
                description: sanitizeText(assistantDesc),
                model: assistantModel,
                instructions: sanitizeText(assistantInstructions),
                temperature: temperature ? parseFloat(temperature) : null,
                top_p: topP ? parseFloat(topP) : null,
                tools: assistantTools,
                tool_resources: toolResources
            }
            const obj = {
                details: JSON.stringify(assistantDetails),
                iconSrc: assistantIcon,
                credential: assistantCredential
            }
            const saveResp = await assistantsApi.updateAssistant(assistantId, obj)
            if (saveResp.data) {
                enqueueSnackbar({
                    message: 'Assistant saved',
                    options: {
                        key: new Date().getTime() + Math.random(),
                        variant: 'success',
                        action: (key) => (
                            <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                <IconX />
                            </Button>
                        )
                    }
                })
                onConfirm(saveResp.data.id)
            }
            setLoading(false)
        } catch (error) {
            enqueueSnackbar({
                message: `Failed to save Assistant: ${
                    typeof error.response.data === 'object' ? error.response.data.message : error.response.data
                }`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            setLoading(false)
        }
    }

    const onSyncClick = async () => {
        setLoading(true)
        try {
            const getResp = await assistantsApi.getAssistantObj(openAIAssistantId, assistantCredential)
            if (getResp.data) {
                syncData(getResp.data)
                enqueueSnackbar({
                    message: 'Assistant successfully synced!',
                    options: {
                        key: new Date().getTime() + Math.random(),
                        variant: 'success',
                        action: (key) => (
                            <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                <IconX />
                            </Button>
                        )
                    }
                })
            }
            setLoading(false)
        } catch (error) {
            enqueueSnackbar({
                message: `Failed to sync Assistant: ${
                    typeof error.response.data === 'object' ? error.response.data.message : error.response.data
                }`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            setLoading(false)
        }
    }

    const uploadFormDataToVectorStore = async (formData) => {
        // Validate file types and sizes
        const fileErrors = validateAndSanitizeFormData(formData)
        if (fileErrors.length > 0) {
            enqueueSnackbar({
                message: `File validation failed: ${fileErrors.join(' ')}`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        // Check for malicious/prompt injection content
        const suspiciousFiles = await sanitizeFormDataFiles(formData)
        if (suspiciousFiles.length > 0) {
            enqueueSnackbar({
                message: `Upload blocked — suspicious content detected: ${suspiciousFiles.join(' ')}`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        // Scan and redact PII (including Singapore-specific PII)
        const { redactedFormData, sgPIIDetected } = await scanAndRedactFormDataFiles(formData)
        if (sgPIIDetected.length > 0) {
            const details = sgPIIDetected.map((f) => `"${f.filename}" (${f.types.join(', ')})`).join('; ')
            enqueueSnackbar({
                message: `Upload blocked — Singapore PII detected in: ${details}. Please remove PII before uploading.`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        setLoading(true)
        try {
            const vectorStoreId = toolResources.file_search?.vector_store_ids?.length ? toolResources.file_search.vector_store_ids[0] : ''
            const uploadResp = await assistantsApi.uploadFilesToAssistantVectorStore(vectorStoreId, assistantCredential, redactedFormData)
            if (uploadResp.data) {
                enqueueSnackbar({
                    message: 'File uploaded successfully!',
                    options: {
                        key: new Date().getTime() + Math.random(),
                        variant: 'success',
                        action: (key) => (
                            <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                <IconX />
                            </Button>
                        )
                    }
                })

                const uploadedFiles = uploadResp.data
                const existingFiles = toolResources?.file_search.files ?? []

                setToolResources({
                    ...toolResources,
                    file_search: {
                        ...toolResources?.file_search,
                        files: [...existingFiles, ...uploadedFiles]
                    }
                })
            }
            setLoading(false)
        } catch (error) {
            enqueueSnackbar({
                message: `Failed to upload file: ${
                    typeof error.response.data === 'object' ? error.response.data.message : error.response.data
                }`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            setLoading(false)
        }
    }

    const uploadFormDataToCodeInterpreter = async (formData) => {
        // Validate file types and sizes
        const fileErrors = validateAndSanitizeFormData(formData)
        if (fileErrors.length > 0) {
            enqueueSnackbar({
                message: `File validation failed: ${fileErrors.join(' ')}`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        // Check for malicious/prompt injection content
        const suspiciousFiles = await sanitizeFormDataFiles(formData)
        if (suspiciousFiles.length > 0) {
            enqueueSnackbar({
                message: `Upload blocked — suspicious content detected: ${suspiciousFiles.join(' ')}`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        // Scan and redact PII (including Singapore-specific PII)
        const { redactedFormData, sgPIIDetected } = await scanAndRedactFormDataFiles(formData)
        if (sgPIIDetected.length > 0) {
            const details = sgPIIDetected.map((f) => `"${f.filename}" (${f.types.join(', ')})`).join('; ')
            enqueueSnackbar({
                message: `Upload blocked — Singapore PII detected in: ${details}. Please remove PII before uploading.`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        setLoading(true)
        try {
            const uploadResp = await assistantsApi.uploadFilesToAssistant(assistantCredential, redactedFormData)
            if (uploadResp.data) {
                enqueueSnackbar({
                    message: 'File uploaded successfully!',
                    options: {
                        key: new Date().getTime() + Math.random(),
                        variant: 'success',
                        action: (key) => (
                            <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                <IconX />
                            </Button>
                        )
                    }
                })

                const uploadedFiles = uploadResp.data
                const existingFiles = toolResources?.code_interpreter?.files ?? []
                const existingFileIds = toolResources?.code_interpreter?.file_ids ?? []

                setToolResources({
                    ...toolResources,
                    code_interpreter: {
                        ...toolResources?.code_interpreter,
                        files: [...existingFiles, ...uploadedFiles],
                        file_ids: [...existingFileIds, ...uploadedFiles.map((file) => file.id)]
                    }
                })
            }
            setLoading(false)
        } catch (error) {
            enqueueSnackbar({
                message: `Failed to upload file: ${
                    typeof error.response.data === 'object' ? error.response.data.message : error.response.data
                }`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            setLoading(false)
        }
    }

    const detachVectorStore = () => {
        setToolResources({
            ...toolResources,
            file_search: {
                files: [],
                vector_store_object: null,
                vector_store_ids: []
            }
        })
    }

    const onDeleteClick = () => {
        setDeleteDialogProps({
            title: `Delete Assistant`,
            description: `Select delete method for ${assistantName}`,
            cancelButtonName: 'Cancel'
        })
        setDeleteDialogOpen(true)
    }

    const deleteAssistant = async (isDeleteBoth) => {
        setDeleteDialogOpen(false)
        try {
            const delResp = await assistantsApi.deleteAssistant(assistantId, isDeleteBoth)
            if (delResp.data) {
                enqueueSnackbar({
                    message: 'Assistant deleted',
                    options: {
                        key: new Date().getTime() + Math.random(),
                        variant: 'success',
                        action: (key) => (
                            <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                <IconX />
                            </Button>
                        )
                    }
                })
                onConfirm()
            }
        } catch (error) {
            enqueueSnackbar({
                message: `Failed to delete Assistant: ${
                    typeof error.response.data === 'object' ? error.response.data.message : error.response.data
                }`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: true,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            onCancel()
        }
    }

    const onFileDeleteClick = async (fileId, toolType) => {
        if (toolType === 'code_interpreter') {
            setToolResources({
                ...toolResources,
                code_interpreter: {
                    ...toolResources.code_interpreter,
                    files: toolResources.code_interpreter.files.filter((file) => file.id !== fileId),
                    file_ids: toolResources.code_interpreter.file_ids.filter((file_id) => file_id !== fileId)
                }
            })
        } else if (toolType === 'file_search') {
            // Remove from toolResources
            setToolResources({
                ...toolResources,
                file_search: {
                    ...toolResources.file_search,
                    files: toolResources.file_search.files.filter((file) => file.id !== fileId)
                }
            })
            // Remove files from vector store
            try {
                const vectorStoreId = toolResources.file_search?.vector_store_ids?.length
                    ? toolResources.file_search.vector_store_ids[0]
                    : ''
                await assistantsApi.deleteFilesFromAssistantVectorStore(vectorStoreId, assistantCredential, { file_ids: [fileId] })
            } catch (error) {
                console.error(error)
            }
        }
    }

    const component = show ? (
        <Dialog
            fullWidth
            maxWidth='md'
            open={show}
            onClose={onCancel}
            aria-labelledby='alert-dialog-title'
            aria-describedby='alert-dialog-description'
        >
            <DialogTitle sx={{ fontSize: '1rem', p: 3, pb: 0 }} id='alert-dialog-title'>
                {dialogProps.title}
            </DialogTitle>
            <DialogContent
                ref={dialogRef}
                sx={{ display: 'flex', flexDirection: 'column', gap: 2, maxHeight: '75vh', position: 'relative', px: 3, pb: 3 }}
            >
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
                    <Box>
                        <Stack sx={{ position: 'relative' }} direction='row'>
                            <Typography variant='overline'>
                                OpenAI Credential
                                <span style={{ color: 'red' }}>&nbsp;*</span>
                            </Typography>
                        </Stack>
                        <CredentialInputHandler
                            key={assistantCredential}
                            data={assistantCredential ? { credential: assistantCredential } : {}}
                            inputParam={{
                                label: 'Connect Credential',
                                name: 'credential',
                                type: 'credential',
                                credentialNames: ['openAIApi']
                            }}
                            onSelect={(newValue) => setAssistantCredential(newValue)}
                        />
                    </Box>
                    <Box>
                        <Stack sx={{ position: 'relative' }} direction='row'>
                            <Typography variant='overline'>
                                Assistant Model
                                <span style={{ color: 'red' }}>&nbsp;*</span>
                            </Typography>
                        </Stack>
                        <Dropdown
                            key={assistantModel}
                            name={assistantModel}
                            options={assistantAvailableModels}
                            onSelect={(newValue) => setAssistantModel(newValue)}
                            value={assistantModel ?? 'choose an option'}
                        />
                    </Box>
                    <Box>
                        <Stack sx={{ position: 'relative', alignItems: 'center' }} direction='row'>
                            <Typography variant='overline'>Assistant Name</Typography>
                            <TooltipWithParser title={'The name of the assistant. The maximum length is 256 characters.'} />
                        </Stack>
                        <OutlinedInput
                            id='assistantName'
                            type='string'
                            size='small'
                            fullWidth
                            placeholder='My New Assistant'
                            value={assistantName}
                            name='assistantName'
                            onChange={(e) => setAssistantName(e.target.value)}
                        />
                    </Box>
                    <Box>
                        <Stack sx={{ position: 'relative', alignItems: 'center' }} direction='row'>
                            <Typography variant='overline'>Assistant Description</Typography>
                            <TooltipWithParser title={'The description of the assistant. The maximum length is 512 characters.'} />
                        </Stack>
                        <OutlinedInput
                            id='assistantDesc'
                            type='string'
                            size='small'
                            fullWidth
                            placeholder='Description of what the Assistant does'
                            multiline={true}
                            rows={3}
                            value={assistantDesc}
                            name='assistantDesc'
                            onChange={(e) => setAssistantDesc(e.target.value)}
                        />
                    </Box>
                    <Box>
                        <Stack sx={{ position: 'relative' }} direction='row'>
                            <Typography variant='overline'>Assistant Icon Src</Typography>
                        </Stack>
                        <div
                            style={{
                                width: 100,
                                height: 100,
                                borderRadius: '50%',
                                backgroundColor: 'white'
                            }}
                        >
                            <img
                                style={{
                                    width: '100%',
                                    height: '100%',
                                    padding: 5,
                                    borderRadius: '50%',
                                    objectFit: 'contain'
                                }}
                                alt={assistantName}
                                src={sanitizeImageUrl(assistantIcon)}
                            />
                        </div>
                        <OutlinedInput
                            id='assistantIcon'
                            type='string'
                            size='small'
                            fullWidth
                            placeholder={`https://api.dicebear.com/7.x/bottts/svg?seed=${uuidv4()}`}
                            value={assistantIcon}
                            name='assistantIcon'
                            onChange={(e) => setAssistantIcon(e.target.value)}
                        />
                    </Box>
                    <Box>
                        <Stack sx={{ position: 'relative', alignItems: 'center' }} direction='row'>
                            <Typography variant='overline'>Assistant Instruction</Typography>
                            <TooltipWithParser
                                title={'The system instructions that the assistant uses. The maximum length is 32768 characters.'}
                            />
                        </Stack>
                        <OutlinedInput
                            id='assistantInstructions'
                            type='string'
                            size='small'
                            fullWidth
                            placeholder='You are a personal math tutor. When asked a question, write and run Python code to answer the question.'
                            multiline={true}
                            rows={3}
                            value={assistantInstructions}
                            name='assistantInstructions'
                            onChange={(e) => setAssistantInstructions(e.target.value)}
                        />
                    </Box>
                    <Box>
                        <Stack sx={{ position: 'relative', alignItems: 'center' }} direction='row'>
                            <Typography variant='overline'>Assistant Temperature</Typography>
                            <TooltipWithParser
                                title={
                                    'Controls randomness: Lowering results in less random completions. As the temperature approaches zero, the model will become deterministic and repetitive.'
                                }
                            />
                        </Stack>
                        <OutlinedInput
                            id='assistantTemp'
                            type='number'
                            size='small'
                            fullWidth
                            value={temperature}
                            name='assistantTemp'
                            onChange={(e) => setTemperature(e.target.value)}
                        />
                    </Box>
                    <Box>
                        <Stack sx={{ position: 'relative', alignItems: 'center' }} direction='row'>
                            <Typography variant='overline'>Assistant Top P</Typography>
                            <TooltipWithParser
                                title={
                                    'Controls diversity via nucleus sampling: 0.5 means half of all likelihood-weighted options are considered.'
                                }
                            />
                        </Stack>
                        <OutlinedInput
                            id='assistantTopP'
                            type='number'
                            fullWidth
                            size='small'
                            value={topP}
                            name='assistantTopP'
                            min='0'
                            max='1'
                            onChange={(e) => setTopP(e.target.value)}
                        />
                    </Box>
                    {assistantCredential && (
                        <>
                            <Box>
                                <Stack sx={{ position: 'relative', alignItems: 'center' }} direction='row'>
                                    <Typography variant='overline'>Assistant Tools</Typography>
                                    <TooltipWithParser title='A list of tool enabled on the assistant. There can be a maximum of 128 tools per assistant.' />
                                </Stack>
                                <MultiDropdown
                                    key={JSON.stringify(assistantTools)}
                                    name={JSON.stringify(assistantTools)}
                                    options={[
                                        {
                                            label: 'Code Interpreter',
                                            name: 'code_interpreter'
                                        },
                                        {
                                            label: 'File Search',
                                            name: 'file_search'
                                        }
                                    ]}
                                    onSelect={(newValue) => {
                                        newValue ? setAssistantTools(JSON.parse(newValue)) : setAssistantTools([])
                                        setTimeout(() => {
                                            dialogRef?.current?.scrollTo({ top: maxScroll })
                                        }, 100)
                                    }}
                                    value={assistantTools ?? 'choose an option'}
                                />
                            </Box>
                            <Box>
                                {assistantTools?.length > 0 && assistantTools.includes('code_interpreter') && (
                                    <Card sx={{ mb: 2, border: '1px solid #e0e0e0', borderRadius: `${customization.borderRadius}px` }}>
                                        <CardContent>
                                            <Stack sx={{ position: 'relative', alignItems: 'center' }} direction='row'>
                                                <Typography variant='overline'>Code Interpreter Files</Typography>
                                                <TooltipWithParser title='Code Interpreter enables the assistant to write and run code. This tool can process files with diverse data and formatting, and generate files such as graphs' />
                                            </Stack>
                                            {toolResources?.code_interpreter?.files?.length > 0 && (
                                                <div style={{ display: 'flex', flexDirection: 'row', flexWrap: 'wrap' }}>
                                                    {toolResources?.code_interpreter?.files?.map((file, index) => (
                                                        <div
                                                            key={index}
                                                            style={{
                                                                display: 'flex',
                                                                flexDirection: 'row',
                                                                alignItems: 'center',
                                                                width: 'max-content',
                                                                height: 'max-content',
                                                                borderRadius: 15,
                                                                background: 'rgb(254,252,191)',
                                                                paddingLeft: 15,
                                                                paddingRight: 15,
                                                                paddingTop: 5,
                                                                paddingBottom: 5,
                                                                marginRight: 10,
                                                                marginBottom: 10
                                                            }}
                                                        >
                                                            <span style={{ color: 'rgb(116,66,16)', marginRight: 10 }}>
                                                                {file.filename}
                                                            </span>
                                                            <IconButton
                                                                sx={{ height: 15, width: 15, p: 0 }}
                                                                onClick={() => onFileDeleteClick(file.id, 'code_interpreter')}
                                                            >
                                                                <IconX />
                                                            </IconButton>
                                                        </div>
                                                    ))}
                                                </div>
                                            )}
                                            <File
                                                key={uploadCodeInterpreterFiles}
                                                fileType='*'
                                                formDataUpload={true}
                                                value={uploadCodeInterpreterFiles ?? 'Choose a file to upload'}
                                                onChange={(newValue) => setUploadCodeInterpreterFiles(newValue)}
                                                onFormDataChange={(formData) => uploadFormDataToCodeInterpreter(formData)}
                                            />
                                        </CardContent>
                                    </Card>
                                )}
                                {assistantTools?.length > 0 && assistantTools.includes('file_search') && (
                                    <Card sx={{ mb: 2, border: '1px solid #e0e0e0', borderRadius: `${customization.borderRadius}px` }}>
                                        <CardContent>
                                            <Stack sx={{ position: 'relative', alignItems: 'center' }} direction='row'>
                                                <Typography variant='overline'>File Search Files</Typography>
                                                <TooltipWithParser title='File search enables the assistant with knowledge from files that you or your users upload. Once a file is uploaded, the assistant automatically decides when to retrieve content based on user requests' />
                                            </Stack>
                                            {toolResources?.file_search?.vector_store_object && (
                                                <Chip
                                                    label={
                                                        toolResources?.file_search?.vector_store_object?.name
                                                            ? toolResources?.file_search?.vector_store_object?.name
                                                            : toolResources?.file_search?.
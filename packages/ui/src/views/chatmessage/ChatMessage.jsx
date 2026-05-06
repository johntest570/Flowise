import { useState, useRef, useEffect, useCallback, Fragment, useContext, memo } from 'react'
import { useSelector, useDispatch } from 'react-redux'
import PropTypes from 'prop-types'
import { cloneDeep } from 'lodash'
import axios from 'axios'
import { v4 as uuidv4 } from 'uuid'
import { EventStreamContentType, fetchEventSource } from '@microsoft/fetch-event-source'

import {
    Box,
    Button,
    Card,
    CardMedia,
    Chip,
    CircularProgress,
    Divider,
    IconButton,
    InputAdornment,
    OutlinedInput,
    Typography,
    Stack,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    TextField
} from '@mui/material'
import { darken, useTheme } from '@mui/material/styles'
import {
    IconCircleDot,
    IconDownload,
    IconSend,
    IconMicrophone,
    IconPhotoPlus,
    IconTrash,
    IconX,
    IconTool,
    IconSquareFilled,
    IconCheck,
    IconPaperclip,
    IconSparkles,
    IconVolume
} from '@tabler/icons-react'
import robotPNG from '@/assets/images/robot.png'
import userPNG from '@/assets/images/account.png'
import multiagent_supervisorPNG from '@/assets/images/multiagent_supervisor.png'
import multiagent_workerPNG from '@/assets/images/multiagent_worker.png'
import audioUploadSVG from '@/assets/images/wave-sound.jpg'

// project import
import NodeInputHandler from '@/views/canvas/NodeInputHandler'
import { MemoizedReactMarkdown } from '@/ui-component/markdown/MemoizedReactMarkdown'
import { SafeHTML } from '@/ui-component/safe/SafeHTML'
import SourceDocDialog from '@/ui-component/dialog/SourceDocDialog'
import ChatFeedbackContentDialog from '@/ui-component/dialog/ChatFeedbackContentDialog'
import StarterPromptsCard from '@/ui-component/cards/StarterPromptsCard'
import AgentReasoningCard from './AgentReasoningCard'
import AgentExecutedDataCard from './AgentExecutedDataCard'
import ThinkingCard from './ThinkingCard'
import { ImageButton, ImageSrc, ImageBackdrop, ImageMarked } from '@/ui-component/button/ImageButton'
import CopyToClipboardButton from '@/ui-component/button/CopyToClipboardButton'
import ThumbsUpButton from '@/ui-component/button/ThumbsUpButton'
import ThumbsDownButton from '@/ui-component/button/ThumbsDownButton'
import { cancelAudioRecording, startAudioRecording, stopAudioRecording } from './audio-recording'
import './audio-recording.css'
import './ChatMessage.css'

// api
import chatmessageApi from '@/api/chatmessage'
import chatflowsApi from '@/api/chatflows'
import predictionApi from '@/api/prediction'
import vectorstoreApi from '@/api/vectorstore'
import attachmentsApi from '@/api/attachments'
import chatmessagefeedbackApi from '@/api/chatmessagefeedback'
import leadsApi from '@/api/lead'
import executionsApi from '@/api/executions'
import ttsApi from '@/api/tts'

// Hooks
import useApi from '@/hooks/useApi'
import { flowContext } from '@/store/context/ReactFlowContext'

// Const
import { baseURL, maxScroll } from '@/store/constant'
import { enqueueSnackbar as enqueueSnackbarAction, closeSnackbar as closeSnackbarAction } from '@/store/actions'

// Utils
import { isValidURL, removeDuplicateURL, setLocalStorageChatflow, getLocalStorageChatflow } from '@/utils/genericHelper'
import useNotifier from '@/utils/useNotifier'
import FollowUpPromptsCard from '@/ui-component/cards/FollowUpPromptsCard'

// History
import { ChatInputHistory } from './ChatInputHistory'

const messageImageStyle = {
    width: '128px',
    height: '128px',
    objectFit: 'cover'
}

// Extension must match recording MIME so server validation and STT work (audio/webm, audio/mp4, audio/ogg).
const getRecordingExtensionForMime = (mime) => {
    const mimeToExt = {
        'audio/webm': 'webm',
        'audio/mp4': 'm4a',
        'audio/x-m4a': 'm4a',
        'audio/ogg': 'ogg',
        'audio/oga': 'ogg',
        'audio/wav': 'wav',
        'audio/wave': 'wav',
        'audio/x-wav': 'wav'
    }
    const extension = mimeToExt[mime]
    if (extension) {
        return extension
    }
    console.warn(`Unsupported audio MIME type: ${mime}. Defaulting to 'webm'.`)
    return 'webm'
}

// ─── Security Helpers ────────────────────────────────────────────────────────

/**
 * Sanitize LLM output by detecting and stripping dangerous dynamic code execution primitives.
 */
const sanitizeLLMOutput = (text) => {
    if (typeof text !== 'string') return text

    // Detect dangerous patterns
    const dangerousPatterns = [
        /\beval\s*\(/gi,
        /new\s+Function\s*\(/gi,
        /setTimeout\s*\(\s*["'`]/gi,
        /setInterval\s*\(\s*["'`]/gi,
        /document\s*\.\s*write\s*\(/gi,
        /innerHTML\s*=/gi,
        /outerHTML\s*=/gi,
        /insertAdjacentHTML\s*\(/gi,
        /execScript\s*\(/gi,
        /\bimportScripts\s*\(/gi
    ]

    let sanitized = text
    dangerousPatterns.forEach((pattern) => {
        sanitized = sanitized.replace(pattern, (match) => `[BLOCKED:${match.trim()}]`)
    })

    return sanitized
}

/**
 * Sanitize and validate user text input before sending to the LLM.
 */
const sanitizeUserInput = (input) => {
    if (typeof input !== 'string') return input

    // Strip null bytes and control characters (except newlines/tabs)
    let sanitized = input.replace(/\0/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')

    // Limit length to prevent excessively large payloads
    const MAX_INPUT_LENGTH = 32000
    if (sanitized.length > MAX_INPUT_LENGTH) {
        sanitized = sanitized.substring(0, MAX_INPUT_LENGTH)
    }

    return sanitized
}

/**
 * Validate a file upload by checking MIME type, size, and base64 content integrity.
 */
const validateFileUpload = (file, result) => {
    const MAX_FILE_SIZE_MB = 50
    const sizeInMB = file.size / 1024 / 1024
    if (sizeInMB > MAX_FILE_SIZE_MB) {
        alert(`File "${file.name}" exceeds the maximum allowed size of ${MAX_FILE_SIZE_MB} MB.`)
        return false
    }

    // Validate base64 content integrity
    if (result && typeof result === 'string') {
        const base64Part = result.split(',')[1]
        if (base64Part) {
            try {
                atob(base64Part)
            } catch (e) {
                alert(`File "${file.name}" has invalid content and cannot be uploaded.`)
                return false
            }
        }
    }

    return true
}

/**
 * Scan file content for malicious prompt injection patterns.
 */
const scanFileForMaliciousContent = (fileName, mimeType, base64Content) => {
    // Check file name for suspicious patterns
    const suspiciousNamePatterns = [/\.exe$/i, /\.bat$/i, /\.cmd$/i, /\.sh$/i, /\.ps1$/i, /\.vbs$/i, /\.js$/i]
    for (const pattern of suspiciousNamePatterns) {
        if (pattern.test(fileName)) {
            return { isMalicious: true, reason: `Suspicious file type detected: ${fileName}` }
        }
    }

    // For text-based files, decode and scan content
    if (
        mimeType &&
        (mimeType.startsWith('text/') ||
            mimeType === 'application/json' ||
            mimeType === 'application/xml' ||
            mimeType === 'application/csv')
    ) {
        try {
            const decoded = atob(base64Content)

            // Check for invisible Unicode characters used in prompt injection
            if (/[\u200B-\u200D\uFEFF\u2060\u00AD]/.test(decoded)) {
                return { isMalicious: true, reason: 'File contains invisible Unicode characters that may indicate prompt injection.' }
            }

            // Check for prompt injection patterns
            const promptInjectionPatterns = [
                /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/gi,
                /system\s*:\s*(you\s+are|act\s+as|pretend)/gi,
                /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/g,
                /###\s*(instruction|system|human|assistant)/gi,
                /jailbreak/gi,
                /DAN\s+mode/gi,
                /do\s+anything\s+now/gi
            ]
            for (const pattern of promptInjectionPatterns) {
                if (pattern.test(decoded)) {
                    return { isMalicious: true, reason: 'File contains potential prompt injection content.' }
                }
            }

            // Check for shell/binary commands
            const shellPatterns = [/\b(rm\s+-rf|chmod\s+777|wget\s+http|curl\s+http|nc\s+-e|\/bin\/sh|\/bin\/bash)\b/gi]
            for (const pattern of shellPatterns) {
                if (pattern.test(decoded)) {
                    return { isMalicious: true, reason: 'File contains suspicious shell commands.' }
                }
            }

            // Check for base64-encoded prompt injections (nested base64)
            const base64Regex = /[A-Za-z0-9+/]{50,}={0,2}/g
            const base64Matches = decoded.match(base64Regex) || []
            for (const match of base64Matches) {
                try {
                    const innerDecoded = atob(match)
                    if (/ignore\s+(all\s+)?(previous|prior)\s+instructions?/gi.test(innerDecoded)) {
                        return { isMalicious: true, reason: 'File contains base64-encoded prompt injection.' }
                    }
                } catch (e) {
                    // Not valid base64, skip
                }
            }
        } catch (e) {
            // Cannot decode, skip content scan
        }
    }

    return { isMalicious: false }
}

/**
 * Detect and redact common PII patterns from text content.
 */
const redactPIIFromContent = (content) => {
    if (typeof content !== 'string') return content

    let redacted = content

    // SSN (US)
    redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED-SSN]')
    // Credit card numbers
    redacted = redacted.replace(/\b(?:\d[ -]?){13,16}\b/g, '[REDACTED-CC]')
    // Email addresses
    redacted = redacted.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[REDACTED-EMAIL]')
    // Phone numbers (various formats)
    redacted = redacted.replace(/\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[REDACTED-PHONE]')
    // Passport numbers (generic)
    redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, '[REDACTED-PASSPORT]')
    // Medical record numbers (generic pattern)
    redacted = redacted.replace(/\bMRN[-:\s]?\d{6,10}\b/gi, '[REDACTED-MRN]')

    return redacted
}

/**
 * Detect Singapore-specific PII patterns in text content.
 */
const detectSingaporePII = (content) => {
    if (typeof content !== 'string') return { hasPII: false }

    // Singapore NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/gi
    if (nricPattern.test(content)) {
        return { hasPII: true, reason: 'File contains Singapore NRIC/FIN number.' }
    }

    // Singapore passport: starts with E followed by 7 digits
    const passportPattern = /\bE\d{7}[A-Z]?\b/g
    if (passportPattern.test(content)) {
        return { hasPII: true, reason: 'File contains Singapore passport number.' }
    }

    // CPF account numbers (8 digits)
    const cpfPattern = /\bCPF[-:\s]?\d{8}\b/gi
    if (cpfPattern.test(content)) {
        return { hasPII: true, reason: 'File contains CPF account number.' }
    }

    // SingPass identifier patterns
    const singpassPattern = /\bSingPass[-:\s]?ID[-:\s]?[A-Z0-9]+\b/gi
    if (singpassPattern.test(content)) {
        return { hasPII: true, reason: 'File contains SingPass identifier.' }
    }

    return { hasPII: false }
}

/**
 * Process file data URL: redact PII, scan for Singapore PII, and scan for malicious content.
 * Returns { safe: boolean, reason: string, data: string }
 */
const processFileDataURL = (dataURL, fileName, mimeType) => {
    const parts = dataURL.split(',')
    const base64Content = parts[1] || ''

    // Scan for malicious content
    const maliciousCheck = scanFileForMaliciousContent(fileName, mimeType, base64Content)
    if (maliciousCheck.isMalicious) {
        return { safe: false, reason: maliciousCheck.reason, data: dataURL }
    }

    // For text-based content, decode, check Singapore PII, redact PII, re-encode
    if (
        mimeType &&
        (mimeType.startsWith('text/') ||
            mimeType === 'application/json' ||
            mimeType === 'application/xml' ||
            mimeType === 'application/csv')
    ) {
        try {
            const decoded = atob(base64Content)

            // Check for Singapore PII
            const sgPIICheck = detectSingaporePII(decoded)
            if (sgPIICheck.hasPII) {
                return { safe: false, reason: sgPIICheck.reason, data: dataURL }
            }

            // Redact general PII
            const redacted = redactPIIFromContent(decoded)
            const reEncoded = btoa(unescape(encodeURIComponent(redacted)))
            const newDataURL = `${parts[0]},${reEncoded}`
            return { safe: true, reason: '', data: newDataURL }
        } catch (e) {
            // Cannot process, return as-is
            return { safe: true, reason: '', data: dataURL }
        }
    }

    return { safe: true, reason: '', data: dataURL }
}

/**
 * Encrypt a string value using AES-GCM via the Web Crypto API.
 */
const encryptPIIField = async (value) => {
    if (!value || typeof value !== 'string') return value
    try {
        const encoder = new TextEncoder()
        const keyMaterial = await window.crypto.subtle.importKey('raw', encoder.encode('flowise-pii-key-2024'), { name: 'PBKDF2' }, false, [
            'deriveKey'
        ])
        const salt = window.crypto.getRandomValues(new Uint8Array(16))
        const key = await window.crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        )
        const iv = window.crypto.getRandomValues(new Uint8Array(12))
        const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(value))
        const encryptedArray = new Uint8Array(encrypted)
        const combined = new Uint8Array(salt.length + iv.length + encryptedArray.length)
        combined.set(salt, 0)
        combined.set(iv, salt.length)
        combined.set(encryptedArray, salt.length + iv.length)
        return btoa(String.fromCharCode(...combined))
    } catch (e) {
        console.error('PII encryption failed:', e)
        return value
    }
}

/**
 * Mask PII value for display purposes.
 */
const maskName = (name) => {
    if (!name) return ''
    if (name.length <= 2) return '*'.repeat(name.length)
    return name[0] + '*'.repeat(name.length - 2) + name[name.length - 1]
}

const maskEmail = (email) => {
    if (!email) return ''
    const atIndex = email.indexOf('@')
    if (atIndex <= 0) return '***'
    const local = email.substring(0, atIndex)
    const domain = email.substring(atIndex)
    if (local.length <= 2) return '*'.repeat(local.length) + domain
    return local[0] + '*'.repeat(local.length - 2) + local[local.length - 1] + domain
}

const maskPhone = (phone) => {
    if (!phone) return ''
    const digits = phone.replace(/\D/g, '')
    if (digits.length <= 4) return '*'.repeat(digits.length)
    return '*'.repeat(digits.length - 4) + digits.slice(-4)
}

/**
 * Get auth token for inter-agent communication.
 */
const getAuthToken = () => {
    try {
        return localStorage.getItem('token') || localStorage.getItem('authToken') || localStorage.getItem('access_token') || ''
    } catch (e) {
        return ''
    }
}

// ─── End Security Helpers ─────────────────────────────────────────────────────

const CardWithDeleteOverlay = ({ item, disabled, customization, onDelete }) => {
    const [isHovered, setIsHovered] = useState(false)
    const defaultBackgroundColor = customization.isDarkMode ? 'rgba(0, 0, 0, 0.3)' : 'transparent'

    return (
        <div
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            style={{ position: 'relative', display: 'inline-block' }}
        >
            <Card
                sx={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    height: '48px',
                    width: 'max-content',
                    p: 2,
                    mr: 1,
                    flex: '0 0 auto',
                    transition: 'opacity 0.3s',
                    opacity: isHovered ? 1 : 1,
                    backgroundColor: isHovered ? 'rgba(0, 0, 0, 0.3)' : defaultBackgroundColor
                }}
                variant='outlined'
            >
                <IconPaperclip size={20} style={{ transition: 'filter 0.3s', filter: isHovered ? 'blur(2px)' : 'none' }} />
                <span
                    style={{
                        marginLeft: '5px',
                        color: customization.isDarkMode ? 'white' : 'inherit',
                        transition: 'filter 0.3s',
                        filter: isHovered ? 'blur(2px)' : 'none'
                    }}
                >
                    {item.name}
                </span>
            </Card>
            {isHovered && !disabled && (
                <Button
                    disabled={disabled}
                    onClick={() => onDelete(item)}
                    startIcon={<IconTrash color='white' size={22} />}
                    title='Remove attachment'
                    sx={{
                        position: 'absolute',
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        backgroundColor: 'transparent',
                        '&:hover': {
                            backgroundColor: 'transparent'
                        }
                    }}
                ></Button>
            )}
        </div>
    )
}

CardWithDeleteOverlay.propTypes = {
    item: PropTypes.object,
    customization: PropTypes.object,
    disabled: PropTypes.bool,
    onDelete: PropTypes.func
}

const ChatMessage = ({ open, chatflowid, isAgentCanvas, isDialog, previews, setPreviews }) => {
    const theme = useTheme()
    const customization = useSelector((state) => state.customization)

    const ps = useRef()

    const dispatch = useDispatch()
    const { onAgentflowNodeStatusUpdate, clearAgentflowNodeStatus } = useContext(flowContext)

    useNotifier()
    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const [userInput, setUserInput] = useState('')
    const [loading, setLoading] = useState(false)
    const [messages, setMessages] = useState([
        {
            message: 'Hi there! How can I help?',
            type: 'apiMessage'
        }
    ])
    const [isChatFlowAvailableToStream, setIsChatFlowAvailableToStream] = useState(false)
    const [isChatFlowAvailableForSpeech, setIsChatFlowAvailableForSpeech] = useState(false)
    const [sourceDialogOpen, setSourceDialogOpen] = useState(false)
    const [sourceDialogProps, setSourceDialogProps] = useState({})
    const [chatId, setChatId] = useState(uuidv4())
    const [isMessageStopping, setIsMessageStopping] = useState(false)
    const [uploadedFiles, setUploadedFiles] = useState([])
    const [imageUploadAllowedTypes, setImageUploadAllowedTypes] = useState('')
    const [fileUploadAllowedTypes, setFileUploadAllowedTypes] = useState('')
    const [inputHistory] = useState(new ChatInputHistory(10))

    const inputRef = useRef(null)
    const getChatmessageApi = useApi(chatmessageApi.getInternalChatmessageFromChatflow)
    const getAllExecutionsApi = useApi(executionsApi.getAllExecutions)
    const getIsChatflowStreamingApi = useApi(chatflowsApi.getIsChatflowStreaming)
    const getAllowChatFlowUploads = useApi(chatflowsApi.getAllowChatflowUploads)
    const getChatflowConfig = useApi(chatflowsApi.getSpecificChatflow)

    const [starterPrompts, setStarterPrompts] = useState([])

    // full file upload
    const [fullFileUpload, setFullFileUpload] = useState(false)
    const [fullFileUploadAllowedTypes, setFullFileUploadAllowedTypes] = useState('*')

    // feedback
    const [chatFeedbackStatus, setChatFeedbackStatus] = useState(false)
    const [feedbackId, setFeedbackId] = useState('')
    const [showFeedbackContentDialog, setShowFeedbackContentDialog] = useState(false)

    // leads
    const [leadsConfig, setLeadsConfig] = useState(null)
    const [leadName, setLeadName] = useState('')
    const [leadEmail, setLeadEmail] = useState('')
    const [leadPhone, setLeadPhone] = useState('')
    const [isLeadSaving, setIsLeadSaving] = useState(false)
    const [isLeadSaved, setIsLeadSaved] = useState(false)

    // follow-up prompts
    const [followUpPromptsStatus, setFollowUpPromptsStatus] = useState(false)
    const [followUpPrompts, setFollowUpPrompts] = useState([])

    // thinking/reasoning state
    const [isThinking, setIsThinking] = useState(false)

    // drag & drop and file input
    const imgUploadRef = useRef(null)
    const fileUploadRef = useRef(null)
    const [isChatFlowAvailableForImageUploads, setIsChatFlowAvailableForImageUploads] = useState(false)
    const [isChatFlowAvailableForFileUploads, setIsChatFlowAvailableForFileUploads] = useState(false)
    const [isChatFlowAvailableForRAGFileUploads, setIsChatFlowAvailableForRAGFileUploads] = useState(false)
    const [isDragActive, setIsDragActive] = useState(false)

    // recording
    const [isRecording, setIsRecording] = useState(false)
    const [recordingNotSupported, setRecordingNotSupported] = useState(false)
    const [isLoadingRecording, setIsLoadingRecording] = useState(false)

    const [openFeedbackDialog, setOpenFeedbackDialog] = useState(false)
    const [feedback, setFeedback] = useState('')
    const [pendingActionData, setPendingActionData] = useState(null)
    const [feedbackType, setFeedbackType] = useState('')

    // start input type
    const [startInputType, setStartInputType] = useState('')
    const [formTitle, setFormTitle] = useState('')
    const [formDescription, setFormDescription] = useState('')
    const [formInputsData, setFormInputsData] = useState({})
    const [formInputParams, setFormInputParams] = useState([])

    const [isConfigLoading, setIsConfigLoading] = useState(true)

    // TTS state
    const [isTTSLoading, setIsTTSLoading] = useState({})
    const [isTTSPlaying, setIsTTSPlaying] = useState({})
    const [ttsAudio, setTtsAudio] = useState({})
    const [isTTSEnabled, setIsTTSEnabled] = useState(false)

    // TTS streaming state
    const [ttsStreamingState, setTtsStreamingState] = useState({
        mediaSource: null,
        sourceBuffer: null,
        audio: null,
        chunkQueue: [],
        isBuffering: false,
        audioFormat: null,
        abortController: null
    })

    // Ref to prevent auto-scroll during TTS actions (using ref to avoid re-renders)
    const isTTSActionRef = useRef(false)
    const ttsTimeoutRef = useRef(null)

    const isFileAllowedForUpload = (file) => {
        const constraints = getAllowChatFlowUploads.data
        /**
         * {isImageUploadAllowed: boolean, imgUploadSizeAndTypes: Array<{ fileTypes: string[], maxUploadSize: number }>}
         */
        let acceptFile = false

        // Early return if constraints are not available yet
        if (!constraints) {
            console.warn('Upload constraints not loaded yet')
            return false
        }

        if (constraints.isImageUploadAllowed) {
            const fileType = file.type
            const sizeInMB = file.size / 1024 / 1024
            if (constraints.imgUploadSizeAndTypes && Array.isArray(constraints.imgUploadSizeAndTypes)) {
                constraints.imgUploadSizeAndTypes.forEach((allowed) => {
                    if (allowed.fileTypes && allowed.fileTypes.includes(fileType) && sizeInMB <= allowed.maxUploadSize) {
                        acceptFile = true
                    }
                })
            }
        }

        if (fullFileUpload) {
            return true
        } else if (constraints.isRAGFileUploadAllowed) {
            const fileExt = file.name.split('.').pop()
            if (fileExt && constraints.fileUploadSizeAndTypes && Array.isArray(constraints.fileUploadSizeAndTypes)) {
                constraints.fileUploadSizeAndTypes.forEach((allowed) => {
                    if (allowed.fileTypes && allowed.fileTypes.length === 1 && allowed.fileTypes[0] === '*') {
                        acceptFile = true
                    } else if (allowed.fileTypes && allowed.fileTypes.includes(`.${fileExt}`)) {
                        acceptFile = true
                    }
                })
            }
        }
        if (!acceptFile) {
            alert(`Cannot upload file. Kindly check the allowed file types and maximum allowed size.`)
        }
        return acceptFile
    }

    const handleDrop = async (e) => {
        if (!isChatFlowAvailableForImageUploads && !isChatFlowAvailableForFileUploads) {
            return
        }
        e.preventDefault()
        setIsDragActive(false)
        let files = []
        let uploadedFiles = []

        if (e.dataTransfer.files.length > 0) {
            for (const file of e.dataTransfer.files) {
                if (isFileAllowedForUpload(file) === false) {
                    return
                }
                const reader = new FileReader()
                const { name } = file
                // Only add files
                if (!file.type || !imageUploadAllowedTypes.includes(file.type)) {
                    uploadedFiles.push({ file, type: fullFileUpload ? 'file:full' : 'file:rag' })
                }
                files.push(
                    new Promise((resolve) => {
                        reader.onload = (evt) => {
                            if (!evt?.target?.result) {
                                return
                            }
                            const { result } = evt.target

                            // Validate file upload
                            if (!validateFileUpload(file, result)) {
                                resolve(null)
                                return
                            }

                            // Process file: scan for malicious content, Singapore PII, and redact PII
                            const base64Part = result.split(',')[1] || ''
                            const processResult = processFileDataURL(result, name, file.type)
                            if (!processResult.safe) {
                                alert(`File "${name}" was rejected: ${processResult.reason}`)
                                resolve(null)
                                return
                            }

                            let previewUrl
                            if (file.type.startsWith('audio/')) {
                                previewUrl = audioUploadSVG
                            } else {
                                previewUrl = URL.createObjectURL(file)
                            }
                            resolve({
                                data: processResult.data,
                                preview: previewUrl,
                                type: 'file',
                                name: name,
                                mime: file.type
                            })
                        }
                        reader.readAsDataURL(file)
                    })
                )
            }

            const newFiles = (await Promise.all(files)).filter(Boolean)
            setUploadedFiles(uploadedFiles)
            setPreviews((prevPreviews) => [...prevPreviews, ...newFiles])
        }

        if (e.dataTransfer.items) {
            //TODO set files
            for (const item of e.dataTransfer.items) {
                if (item.kind === 'string' && item.type.match('^text/uri-list')) {
                    item.getAsString((s) => {
                        let upload = {
                            data: s,
                            preview: s,
                            type: 'url',
                            name: s ? s.substring(s.lastIndexOf('/') + 1) : ''
                        }
                        setPreviews((prevPreviews) => [...prevPreviews, upload])
                    })
                } else if (item.kind === 'string' && item.type.match('^text/html')) {
                    item.getAsString((s) => {
                        if (s.indexOf('href') === -1) return
                        //extract href
                        let start = s ? s.substring(s.indexOf('href') + 6) : ''
                        let hrefStr = start.substring(0, start.indexOf('"'))

                        let upload = {
                            data: hrefStr,
                            preview: hrefStr,
                            type: 'url',
                            name: hrefStr ? hrefStr.substring(hrefStr.lastIndexOf('/') + 1) : ''
                        }
                        setPreviews((prevPreviews) => [...prevPreviews, upload])
                    })
                }
            }
        }
    }

    const handleFileChange = async (event) => {
        const fileObj = event.target.files && event.target.files[0]
        if (!fileObj) {
            return
        }
        let files = []
        let uploadedFiles = []
        for (const file of event.target.files) {
            if (isFileAllowedForUpload(file) === false) {
                return
            }
            // Only add files
            if (!file.type || !imageUploadAllowedTypes.includes(file.type)) {
                uploadedFiles.push({ file, type: fullFileUpload ? 'file:full' : 'file:rag' })
            }
            const reader = new FileReader()
            const { name } = file
            files.push(
                new Promise((resolve) => {
                    reader.onload = (evt) => {
                        if (!evt?.target?.result) {
                            return
                        }
                        const { result } = evt.target

                        // Validate file upload
                        if (!validateFileUpload(file, result)) {
                            resolve(null)
                            return
                        }

                        // Process file: scan for malicious content, Singapore PII, and redact PII
                        const processResult = processFileDataURL(result, name, file.type)
                        if (!processResult.safe) {
                            alert(`File "${name}" was rejected: ${processResult.reason}`)
                            resolve(null)
                            return
                        }

                        resolve({
                            data: processResult.data,
                            preview: URL.createObjectURL(file),
                            type: 'file',
                            name: name,
                            mime: file.type
                        })
                    }
                    reader.readAsDataURL(file)
                })
            )
        }

        const newFiles = (await Promise.all(files)).filter(Boolean)
        setUploadedFiles(uploadedFiles)
        setPreviews((prevPreviews) => [...prevPreviews, ...newFiles])
        // 👇️ reset file input
        event.target.value = null
    }

    const addRecordingToPreviews = (blob) => {
        let mimeType = ''
        const pos = blob.type.indexOf(';')
        if (pos === -1) {
            mimeType = blob.type
        } else {
            mimeType = blob.type ? blob.type.substring(0, pos) : ''
        }
        const ext = getRecordingExtensionForMime(mimeType)
        // read blob and add to previews
        const reader = new FileReader()
        reader.readAsDataURL(blob)
        reader.onloadend = () => {
            const base64data = reader.result
            const upload = {
                data: base64data,
                preview: audioUploadSVG,
                type: 'audio',
                name: `audio_${Date.now()}.${ext}`,
                mime: mimeType
            }
            setPreviews((prevPreviews) => [...prevPreviews, upload])
        }
    }

    const handleDrag = (e) => {
        if (isChatFlowAvailableForImageUploads || isChatFlowAvailableForFileUploads) {
            e.preventDefault()
            e.stopPropagation()
            if (e.type === 'dragenter' || e.type === 'dragover') {
                setIsDragActive(true)
            } else if (e.type === 'dragleave') {
                setIsDragActive(false)
            }
        }
    }

    const handleAbort = async () => {
        setIsMessageStopping(true)
        try {
            // Stop all TTS streams first
            await handleTTSAbortAll()
            stopAllTTS()

            await chatmessageApi.abortMessage(chatflowid, chatId)
            setIsMessageStopping(false)
        } catch (error) {
            setIsMessageStopping(false)
            enqueueSnackbar({
                message: typeof error.response.data === 'object' ? error.response.data.message : error.response.data,
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
    }

    const handleDeletePreview = (itemToDelete) => {
        if (itemToDelete.type === 'file') {
            URL.revokeObjectURL(itemToDelete.preview) // Clean up for file
        }
        setPreviews(previews.filter((item) => item !== itemToDelete))
    }

    const handleFileUploadClick = () => {
        // 👇️ open file input box on click of another element
        fileUploadRef.current.click()
    }

    const handleImageUploadClick = () => {
        // 👇️ open file input box on click of another element
        imgUploadRef.current.click()
    }

    const clearPreviews = () => {
        // Revoke the data uris to avoid memory leaks
        previews.forEach((file) => URL.revokeObjectURL(file.preview))
        setPreviews([])
    }

    const onMicrophonePressed = () => {
        setIsRecording(true)
        startAudioRecording(setIsRecording, setRecordingNotSupported)
    }

    const onRecordingCancelled = () => {
        if (!recordingNotSupported) cancelAudioRecording()
        setIsRecording(false)
        setRecordingNotSupported(false)
    }

    const onRecordingStopped = async () => {
        setIsLoadingRecording(true)
        stopAudioRecording(addRecordingToPreviews)
    }

    const onSourceDialogClick = (data, title) => {
        setSourceDialogProps({ data, title })
        setSourceDialogOpen(true)
    }

    const onURLClick = (data) => {
        window.open(data, '_blank')
    }

    const scrollToBottom = () => {
        if (ps.current) {
            ps.current.scrollTo({ top: maxScroll })
        }
    }

    // Helper function to manage TTS action flag
    const setTTSAction = (isActive) => {
        isTTSActionRef.current = isActive
        if (ttsTimeoutRef.current) {
            clearTimeout(ttsTimeoutRef.current)
            ttsTimeoutRef.current = null
        }
        if (isActive) {
            // Reset the flag after a longer delay to ensure all state changes are complete
            ttsTimeoutRef.current = setTimeout(() => {
                isTTSActionRef.current = false
                ttsTimeoutRef.current = null
            }, 300)
        }
    }

    const onChange = useCallback((e) => setUserInput(e.target.value), [setUserInput])

    const updateLastMessage = (text) => {
        const sanitizedText = sanitizeLLMOutput(text)
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].message += sanitizedText
            allMessages[allMessages.length - 1].feedback = null
            return allMessages
        })
    }

    const updateErrorMessage = (errorMessage) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            allMessages.push({ message: errorMessage, type: 'apiMessage' })
            return allMessages
        })
    }

    const updateLastMessageSourceDocuments = (sourceDocuments) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].sourceDocuments = sourceDocuments
            return allMessages
        })
    }

    const updateLastMessageAgentReasoning = (agentReasoning) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].agentReasoning = agentReasoning
            return allMessages
        })
    }

    const handleThinkingEvent = (data, duration) => {
        if (data && duration === undefined) {
            // Still thinking - append content
            setIsThinking(true)
            setMessages((prevMessages) => {
                let allMessages = [...cloneDeep(prevMessages)]
                if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
                const lastMessage = allMessages[allMessages.length - 1]
                lastMessage.thinking = (lastMessage.thinking || '') + data
                lastMessage.isThinking = true
                return allMessages
            })
        } else if (data === '' && duration !== undefined) {
            // Thinking finished - set duration
            setIsThinking(false)
            setMessages((prevMessages) => {
                let allMessages = [...cloneDeep(prevMessages)]
                if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
                const lastMessage = allMessages[allMessages.length - 1]
                lastMessage.thinkingDuration = duration
                lastMessage.isThinking = false
                return allMessages
            })
        }
    }

    const finalizeThinking = () => {
        // Clean up thinking state if stream ends unexpectedly
        if (isThinking) {
            setIsThinking(false)
            setMessages((prevMessages) => {
                let allMessages = [...cloneDeep(prevMessages)]
                if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
                allMessages[allMessages.length - 1].isThinking = false
                return allMessages
            })
        }
    }

    const updateAgentFlowEvent = (event) => {
        if (event === 'INPROGRESS') {
            setMessages((prevMessages) => [...prevMessages, { message: '', type: 'apiMessage', agentFlowEventStatus: event }])
        } else {
            setMessages((prevMessages) => {
                let allMessages = [...cloneDeep(prevMessages)]
                if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
                allMessages[allMessages.length - 1].agentFlowEventStatus = event
                return allMessages
            })
        }
    }

    const updateAgentFlowExecutedData = (agentFlowExecutedData) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].agentFlowExecutedData = agentFlowExecutedData
            return allMessages
        })
    }

    const updateLastMessageAction = (action) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].action = action
            return allMessages
        })
    }

    const updateLastMessageArtifacts = (artifacts) => {
        artifacts.forEach((artifact) => {
            if (artifact.type === 'png' || artifact.type === 'jpeg') {
                artifact.data = `${baseURL}/api/v1/get-upload-file?chatflowId=${chatflowid}&chatId=${chatId}&fileName=${artifact.data.replace(
                    'FILE-STORAGE::',
                    ''
                )}`
            }
        })
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].artifacts = artifacts
            return allMessages
        })
    }

    const updateLastMessageNextAgent = (nextAgent) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            const lastAgentReasoning = allMessages[allMessages.length - 1].agentReasoning
            if (lastAgentReasoning && lastAgentReasoning.length > 0) {
                lastAgentReasoning.push({ nextAgent })
            }
            allMessages[allMessages.length - 1].agentReasoning = lastAgentReasoning
            return allMessages
        })
    }

    const updateLastMessageNextAgentFlow = (nextAgentFlow) => {
        onAgentflowNodeStatusUpdate(nextAgentFlow)
    }

    const updateLastMessageUsedTools = (usedTools) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages

            // When usedTools are received, check if there are matching calledTools to replace
            const lastMessage = allMessages[allMessages.length - 1]
            if (lastMessage.calledTools && lastMessage.calledTools.length > 0) {
                // Replace calledTools with usedTools for matching tool names
                const updatedCalledTools = lastMessage.calledTools.map((calledTool) => {
                    const matchingUsedTool = usedTools.find((usedTool) => usedTool.tool === calledTool.tool)
                    return matchingUsedTool || calledTool
                })

                // Remove calledTools that have been replaced by usedTools
                const remainingCalledTools = updatedCalledTools.filter(
                    (calledTool) => !usedTools.some((usedTool) => usedTool.tool === calledTool.tool)
                )

                allMessages[allMessages.length - 1].calledTools = remainingCalledTools.length > 0 ? remainingCalledTools : undefined
            }

            allMessages[allMessages.length - 1].usedTools = usedTools
            return allMessages
        })
    }

    const updateLastMessageCalledTools = (calledTools) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].calledTools = calledTools
            return allMessages
        })
    }

    const cleanupCalledTools = () => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages

            // Remove any remaining calledTools when the stream ends
            const lastMessage = allMessages[allMessages.length - 1]
            if (lastMessage && lastMessage.calledTools && lastMessage.calledTools.length > 0) {
                // Only remove if there are still calledTools and no matching usedTools
                const hasUsedTools = lastMessage.usedTools && lastMessage.usedTools.length > 0
                if (!hasUsedTools) {
                    allMessages[allMessages.length - 1].calledTools = undefined
                }
            }

            return allMessages
        })
    }

    const updateLastMessageFileAnnotations = (fileAnnotations) => {
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].fileAnnotations = fileAnnotations
            return allMessages
        })
    }

    const abortMessage = () => {
        setIsMessageStopping(false)
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            const lastAgentReasoning = allMessages[allMessages.length - 1].agentReasoning
            if (lastAgentReasoning && lastAgentReasoning.length > 0) {
                allMessages[allMessages.length - 1].agentReasoning = lastAgentReasoning.filter((reasoning) => !reasoning.nextAgent)
            }
            allMessages[allMessages.length - 1].calledTools = undefined
            return allMessages
        })
        setTimeout(() => {
            inputRef.current?.focus()
        }, 100)
        enqueueSnackbar({
            message: 'Message stopped',
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

    const handleError = (message = 'Oops! There seems to be an error. Please try again.') => {
        message = message.replace(`Unable to parse JSON response from chat agent.\n\n`, '')
        setMessages((prevMessages) => [...prevMessages, { message, type: 'apiMessage' }])
        setLoading(false)
        setUserInput('')
        setUploadedFiles([])
        setTimeout(() => {
            inputRef.current?.focus()
        }, 100)
    }

    const handlePromptClick = async (promptStarterInput) => {
        setUserInput(promptStarterInput)
        handleSubmit(undefined, promptStarterInput)
    }

    const handleFollowUpPromptClick = async (promptStarterInput) => {
        setUserInput(promptStarterInput)
        setFollowUpPrompts([])
        handleSubmit(undefined, promptStarterInput)
    }

    const onSubmitResponse = (actionData, feedback = '', type = '') => {
        let fbType = feedbackType
        if (type) {
            fbType = type
        }
        const question = feedback ? feedback : fbType.charAt(0).toUpperCase() + fbType.slice(1)
        handleSubmit(undefined, question, undefined, {
            type: fbType,
            startNodeId: actionData?.nodeId,
            feedback
        })
    }

    const handleSubmitFeedback = () => {
        if (pendingActionData) {
            onSubmitResponse(pendingActionData, feedback)
            setOpenFeedbackDialog(false)
            setFeedback('')
            setPendingActionData(null)
            setFeedbackType('')
        }
    }

    const handleActionClick = async (elem, action) => {
        setUserInput(elem.label)
        setMessages((prevMessages) => {
            let allMessages = [...cloneDeep(prevMessages)]
            if (allMessages[allMessages.length - 1].type === 'userMessage') return allMessages
            allMessages[allMessages.length - 1].action = null
            return allMessages
        })
        if (elem.type.includes('agentflowv2')) {
            const type = elem.type.includes('approve') ? 'proceed' : 'reject'
            setFeedbackType(type)

            if (action.data && action.data.input && action.data.input.humanInputEnableFeedback) {
                setPendingActionData(action.data)
                setOpenFeedbackDialog(true)
            } else {
                onSubmitResponse(action.data, '', type)
            }
        } else {
            handleSubmit(undefined, elem.label, action)
        }
    }

    const updateMetadata = (data, input) => {
        // set message id that is needed for feedback
        if (data.chatMessageId) {
            setMessages((prevMessages) => {
                let allMessages = [...cloneDeep(prevMessages)]
                if (allMessages[allMessages.length - 1].type === 'apiMessage') {
                    allMessages[allMessages.length - 1].id = data.chatMessageId
                }
                return allMessages
            })
        }

        if (data.chatId) {
            setChatId(data.chatId)
        }

        if (input === '' && data.question) {
            // the response contains the question even if it was in an audio format
            // so if input is empty but the response contains the question, update the user message to show the question
            setMessages((prevMessages) => {
                let allMessages = [...cloneDeep(prevMessages)]
                if (allMessages[allMessages.length - 2].type === 'apiMessage') return allMessages
                allMessages[allMessages.length - 2].message = data.question
                return allMessages
            })
        }

        if (data.followUpPrompts) {
            const followUpPrompts = JSON.parse(data.followUpPrompts)
            if (typeof followUpPrompts === 'string') {
                setFollowUpPrompts(JSON.parse(followUpPrompts))
            } else {
                setFollowUpPrompts(followUpPrompts)
            }
        }
    }

    const handleFileUploads = async (uploads) => {
        if (!uploadedFiles.length) return uploads

        if (fullFileUpload) {
            const filesWithFullUploadType = uploadedFiles.filter((file) => file.type === 'file:full')
            if (filesWithFullUploadType.length > 0) {
                const formData = new FormData()
                for (const file of filesWithFullUploadType) {
                    formData.append('files', file.file)
                }
                formData.append('chatId', chatId)

                const response = await attachmentsApi.createAttachment(chatflowid, chatId, formData)
                const data = response.data

                for (const extractedFileData of data) {
                    const content = extractedFileData.content
                    const fileName = extractedFileData.name

                    // find matching name in previews and replace data with content
                    const uploadIndex = uploads.findIndex((upload) => upload.name === fileName)

                    if (uploadIndex !== -1) {
                        uploads[uploadIndex] = {
                            ...uploads[uploadIndex],
                            data: content,
                            name: fileName,
                            type: 'file:full'
                        }
                    }
                }
            }
        } else if (isChatFlowAvailableForRAGFileUploads) {
            const filesWithRAGUploadType = uploadedFiles.filter((file) => file.type === 'file:rag')

            if (filesWithRAGUploadType.length > 0) {
                const formData = new FormData()
                for (const file of filesWithRAGUploadType) {
                    formData.append('files', file.file)
                }
                formData.append('chatId', chatId)

                await vectorstoreApi.upsertVectorStoreWithFormData(chatflowid, formData)

                // delay for vector store to be updated
                const delay = (delayInms) => {
                    return new Promise((resolve) => setTimeout(resolve, delayInms))
                }
                await delay(2500) //TODO: check if embeddings can be retrieved using file name as metadata filter

                uploads = uploads.map((upload) => {
                    return {
                        ...upload,
                        type: 'file:rag'
                    }
                })
            }
        }
        return uploads
    }

    // Handle form submission
    const handleSubmit = async (e, selectedInput, action, humanInput) => {
        if (e) e.preventDefault()

        if (!selectedInput && userInput.trim() === '') {
            const containsFile = previews.filter((item) => !item.mime.startsWith('image') && item.type !== 'audio').length > 0
            if (!previews.length || (previews.length && containsFile)) {
                return
            }
        }

        let input = userInput

        if (typeof selectedInput === 'string') {
            if (selectedInput !== undefined && selectedInput.trim() !== '') input = selectedInput

            if (input.trim()) {
                inputHistory.addToHistory(input)
            }
        } else if (typeof selectedInput === 'object') {
            input = Object.entries(selectedInput)
                .map(([key, value]) => `${key}: ${value}`)
                .join('\n')
        }

        // Sanitize user input before sending to LLM
        input = sanitizeUserInput(input)

        setLoading(true)
        clearAgentflowNodeStatus()

        let uploads = previews.map((item) => {
            return {
                data: item.data,
                type: item.type,
                name: item.name,
                mime: item.mime
            }
        })

        try {
            uploads = await handleFileUploads(uploads)
        } catch (error) {
            handleError('Unable to upload documents')
            return
        }

        clearPreviews()
        setMessages((prevMessages) => [...prevMessages, { message: input, type: 'userMessage', fileUploads: uploads }])

        // Send user question to Prediction Internal API
        try {
            const params = {
                question: input,
                chatId
            }
            if (typeof selectedInput === 'object') {
                params.form = selectedInput
                delete params.question
            }
            if (uploads && uploads.length > 0) params.uploads = uploads
            if (leadEmail) params.leadEmail = leadEmail
            if (action) params.action = action
            if (humanInput) params.humanInput = humanInput

            if (isChatFlowAvailableToStream) {
                // Log LLM request (streaming)
                console.log('[LLM Interaction] Streaming request:', {
                    chatflowid,
                    chatId: params.chatId,
                    question: params.question,
                    hasUploads: !!(params.uploads && params.uploads.length > 0),
                    timestamp: new Date().toISOString()
                })
                fetchResponseFromEventStream(chatflowid, params)
            } else {
                // Log LLM request (non-streaming)
                console.log('[LLM Interaction] Non-streaming request:', {
                    chatflowid,
                    chatId: params.chatId,
                    question: params.question,
                    hasUploads: !!(params.uploads && params.uploads.length > 0),
                    timestamp: new Date().toISOString()
                })
                const response = await predictionApi.sendMessageAndGetPrediction(chatflowid, params)
                if (response.data) {
                    const data = response.data

                    // Log LLM response (non-streaming)
                    console.log('[LLM Interaction] Non-streaming response:', {
                        chatflowid,
                        chatId: data.chatId,
                        chatMessageId: data.chatMessageId,
                        hasText: !!data.text,
                        hasJson: !!data.json,
                        timestamp: new Date().toISOString()
                    })

                    updateMetadata(data, input)

                    let text = ''
                    if (data.text) text = sanitizeLLMOutput(data.text)
                    else if (data.json) text = sanitizeLLMOutput('```json\n' + JSON.stringify(data.json, null, 2))
                    else text = sanitizeLLMOutput(JSON.stringify(data, null, 2))

                    setMessages((prevMessages) => [
                        ...prevMessages,
                        {
                            message: text,
                            id: data?.chatMessageId,
                            sourceDocuments: data?.sourceDocuments,
                            usedTools: data?.usedTools,
                            calledTools: data?.calledTools,
                            fileAnnotations: data?.fileAnnotations,
                            agentReasoning: data?.agentReasoning,
                            agentFlowExecutedData: data?.agentFlowExecutedData,
                            action: data?.action,
                            artifacts: data?.artifacts,
                            type: 'apiMessage',
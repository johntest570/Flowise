import PropTypes from 'prop-types'
import { useNavigate } from 'react-router-dom'
import { useSelector, useDispatch } from 'react-redux'
import { useEffect, useMemo, useRef, useState } from 'react'

// material-ui
import { useTheme, styled, alpha } from '@mui/material/styles'
import { Avatar, Box, ButtonBase, Typography, Stack, Switch, TextField, Button, Tooltip } from '@mui/material'

// icons
import {
    IconSettings,
    IconChevronLeft,
    IconDeviceFloppy,
    IconPencil,
    IconCheck,
    IconX,
    IconCode,
    IconAlertTriangleFilled
} from '@tabler/icons-react'

// project imports
import Settings from '@/views/settings'
import SaveChatflowDialog from '@/ui-component/dialog/SaveChatflowDialog'
import APICodeDialog from '@/views/chatflows/APICodeDialog'
import ViewMessagesDialog from '@/ui-component/dialog/ViewMessagesDialog'
import ChatflowConfigurationDialog from '@/ui-component/dialog/ChatflowConfigurationDialog'
import UpsertHistoryDialog from '@/views/vectorstore/UpsertHistoryDialog'
import ViewLeadsDialog from '@/ui-component/dialog/ViewLeadsDialog'
import ExportAsTemplateDialog from '@/ui-component/dialog/ExportAsTemplateDialog'
import { Available } from '@/ui-component/rbac/available'

// API
import chatflowsApi from '@/api/chatflows'

// Hooks
import useApi from '@/hooks/useApi'

// utils
import { generateExportFlowData } from '@/utils/genericHelper'
import { uiBaseURL } from '@/store/constant'
import { closeSnackbar as closeSnackbarAction, enqueueSnackbar as enqueueSnackbarAction, SET_CHATFLOW } from '@/store/actions'

// Clock icon (unchecked) and calendar-check icon (checked), mirroring MaterialUISwitch style
const clockIcon = `url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" height="20" width="20" viewBox="0 0 20 20"><path fill="${encodeURIComponent(
    '#fff'
)}" d="M10 2a8 8 0 108 8 8 8 0 00-8-8zm0 14.5A6.5 6.5 0 1116.5 10 6.5 6.5 0 0110 16.5zM10.75 5.5h-1.5v5l4 2.4.75-1.23-3.25-1.92z"/></svg>')`
const clockCheckIcon = `url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="${encodeURIComponent(
    '#fff'
)}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.942 13.021a9 9 0 1 0 -9.407 7.967"/><path d="M12 7v5l3 3"/><path d="M15 19l2 2l4 -4"/></svg>')`

const ScheduleSwitch = styled(Switch, { shouldForwardProp: (prop) => prop !== 'isDark' })(({ theme, isDark }) => {
    const offTrack = isDark ? alpha(theme.palette.success.main, 0.1) : alpha(theme.palette.success.main, 0.12)
    const offThumb = isDark ? '#4a5662' : alpha(theme.palette.success.main, 0.25)
    return {
        width: 62,
        height: 34,
        padding: 7,
        '& .MuiSwitch-switchBase': {
            margin: 1,
            padding: 0,
            transform: 'translateX(6px)',
            '&.Mui-checked': {
                color: '#fff',
                transform: 'translateX(22px)',
                '& .MuiSwitch-thumb': {
                    backgroundColor: theme.palette.success.dark
                },
                '& .MuiSwitch-thumb:before': {
                    backgroundImage: clockCheckIcon
                },
                '& + .MuiSwitch-track': {
                    opacity: 1,
                    backgroundColor: theme.palette.success.light
                }
            }
        },
        '& .MuiSwitch-thumb': {
            backgroundColor: offThumb,
            width: 32,
            height: 32,
            '&:before': {
                content: "''",
                position: 'absolute',
                width: '100%',
                height: '100%',
                left: 0,
                top: 0,
                backgroundRepeat: 'no-repeat',
                backgroundPosition: 'center',
                backgroundImage: clockIcon,
                opacity: 0.9
            }
        },
        '& .MuiSwitch-track': {
            opacity: 1,
            backgroundColor: offTrack,
            borderRadius: 20 / 2
        },
        '&.Mui-disabled .MuiSwitch-thumb, & .Mui-disabled .MuiSwitch-thumb': {
            backgroundColor: offThumb
        },
        '&.Mui-disabled + .MuiSwitch-track, & .Mui-disabled + .MuiSwitch-track': {
            backgroundColor: offTrack,
            opacity: 1
        }
    }
})

const LockedScheduleSwitch = styled(ScheduleSwitch, { shouldForwardProp: (prop) => prop !== 'isDark' })(({ theme, isDark }) => ({
    '& .MuiSwitch-track, &.Mui-disabled + .MuiSwitch-track, & .Mui-disabled + .MuiSwitch-track': {
        backgroundColor: isDark ? alpha(theme.palette.warning.main, 0.2) : alpha(theme.palette.warning.main, 0.15),
        border: `1px solid ${alpha(theme.palette.warning.main, isDark ? 0.6 : 0.5)}`,
        opacity: 1
    },
    '&.Mui-disabled .MuiSwitch-thumb, & .Mui-disabled .MuiSwitch-thumb': {
        backgroundColor: isDark ? '#4a3e1f' : '#f5e6b8'
    }
}))

// ==============================|| FILE SECURITY UTILITIES ||============================== //

/**
 * Checks uploaded file content for suspicious/malicious patterns (prompt injection,
 * hidden characters, base64-encoded prompts, shell commands, binary signatures, etc.)
 * Returns true if suspicious content is detected.
 */
const containsMaliciousContent = (text) => {
    // Hidden/invisible unicode characters used for prompt injection
    const invisibleCharsPattern = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/
    if (invisibleCharsPattern.test(text)) return true

    // Base64-encoded content that could hide prompts (long base64 strings)
    const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/
    if (base64Pattern.test(text)) {
        try {
            const matches = text.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []
            for (const match of matches) {
                const decoded = atob(match)
                // Check if decoded content looks like a prompt injection
                if (/ignore\s+(previous|above|prior)\s+instructions/i.test(decoded)) return true
                if (/you\s+are\s+(now|a|an)\s+/i.test(decoded)) return true
            }
        } catch {
            // Not valid base64, ignore
        }
    }

    // Prompt injection patterns
    const promptInjectionPatterns = [
        /ignore\s+(previous|above|prior|all)\s+instructions/i,
        /disregard\s+(previous|above|prior|all)\s+instructions/i,
        /forget\s+(previous|above|prior|all)\s+instructions/i,
        /you\s+are\s+now\s+/i,
        /act\s+as\s+(if\s+you\s+are|a|an)\s+/i,
        /new\s+instructions?\s*:/i,
        /system\s*:\s*(you|ignore|forget)/i,
        /\[system\]/i,
        /<\s*system\s*>/i,
        /###\s*instruction/i,
        /override\s+(previous|prior|all)\s+(instructions?|commands?|prompts?)/i,
        /jailbreak/i,
        /prompt\s+injection/i,
        /do\s+anything\s+now/i,
        /DAN\s+mode/i
    ]
    for (const pattern of promptInjectionPatterns) {
        if (pattern.test(text)) return true
    }

    // Leetspeak patterns for common injection phrases
    const leetspeakPatterns = [
        /1gn0r3\s+(pr3v10us|4ll)\s+1nstruct10ns/i,
        /y0u\s+4r3\s+n0w/i,
        /f0rg3t\s+(4ll|pr3v10us)/i
    ]
    for (const pattern of leetspeakPatterns) {
        if (pattern.test(text)) return true
    }

    // Shell command patterns
    const shellCommandPatterns = [
        /\$\s*\(\s*(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|exec)\s/i,
        /`\s*(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|exec)\s/i,
        /;\s*(cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|exec)\s/i,
        /\|\s*(bash|sh|python|perl|ruby)\s/i,
        /\/etc\/passwd/i,
        /\/etc\/shadow/i,
        /rm\s+-rf\s+/i,
        /wget\s+http/i,
        /curl\s+http/i
    ]
    for (const pattern of shellCommandPatterns) {
        if (pattern.test(text)) return true
    }

    return false
}

/**
 * Checks for binary/executable file signatures in the first bytes of a file.
 * Returns true if the file appears to be a binary/executable.
 */
const hasBinarySignature = (arrayBuffer) => {
    const bytes = new Uint8Array(arrayBuffer.slice(0, 8))
    // ELF (Linux executable)
    if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) return true
    // PE (Windows executable)
    if (bytes[0] === 0x4d && bytes[1] === 0x5a) return true
    // Mach-O (macOS executable)
    if (
        (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xce) ||
        (bytes[0] === 0xce && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe) ||
        (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
    )
        return true
    // ZIP (could contain executables)
    // We allow ZIP as it may be legitimate, skip
    return false
}

/**
 * PII redaction patterns for zero-tolerance categories (global).
 */
const PII_REDACTION_PATTERNS = [
    // SSN (US): 123-45-6789 or 123456789
    { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED-SSN]' },
    { pattern: /\b\d{9}\b(?=\s|$)/g, replacement: '[REDACTED-SSN]' },
    // Credit card numbers (Visa, MC, Amex, Discover)
    { pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, replacement: '[REDACTED-CC]' },
    { pattern: /\b\d{4}[\s-]\d{4}[\s-]\d{4}[\s-]\d{4}\b/g, replacement: '[REDACTED-CC]' },
    // Passport numbers (generic: letter(s) followed by digits)
    { pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g, replacement: '[REDACTED-PASSPORT]' },
    // Driver's license (US generic patterns)
    { pattern: /\b[A-Z]\d{7}\b/g, replacement: '[REDACTED-DL]' },
    { pattern: /\b\d{3}-\d{3}-\d{4}\b/g, replacement: '[REDACTED-DL]' },
    // Bank account numbers (generic 8-17 digit sequences not already matched)
    { pattern: /\b\d{8,17}\b/g, replacement: '[REDACTED-BANK]' },
    // Biometric data references
    { pattern: /\bfingerprint\s*(?:id|data|hash|template)?\s*:\s*[A-Za-z0-9+/=]{10,}/gi, replacement: '[REDACTED-BIOMETRIC]' },
    { pattern: /\bretina\s*(?:scan|data|hash)?\s*:\s*[A-Za-z0-9+/=]{10,}/gi, replacement: '[REDACTED-BIOMETRIC]' }
]

/**
 * Singapore-specific PII patterns.
 */
const SINGAPORE_PII_PATTERNS = [
    // NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    /\b[STFG]\d{7}[A-Z]\b/i,
    // Singapore passport: E followed by 7 digits
    /\bE\d{7}\b/i,
    // Common full name patterns (Title + Name)
    /\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b/
]

/**
 * Redacts PII from text content using zero-tolerance category patterns.
 */
const redactPIIFromText = (text) => {
    let redacted = text
    for (const { pattern, replacement } of PII_REDACTION_PATTERNS) {
        redacted = redacted.replace(pattern, replacement)
    }
    return redacted
}

/**
 * Checks for Singapore-specific PII in text content.
 * Returns true if Singapore PII is detected.
 */
const containsSingaporePII = (text) => {
    for (const pattern of SINGAPORE_PII_PATTERNS) {
        if (pattern.test(text)) return true
    }
    return false
}

/**
 * Reads a File object as text (returns a Promise).
 */
const readFileAsText = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = (e) => resolve(e.target.result)
        reader.onerror = (e) => reject(e)
        reader.readAsText(file)
    })
}

/**
 * Reads a File object as ArrayBuffer (returns a Promise).
 */
const readFileAsArrayBuffer = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = (e) => resolve(e.target.result)
        reader.onerror = (e) => reject(e)
        reader.readAsArrayBuffer(file)
    })
}

/**
 * Creates a sanitized wrapper around the onUploadFile handler.
 * Performs:
 * 1. Binary/executable signature check (reject)
 * 2. Malicious content / prompt injection check (reject)
 * 3. Singapore PII check (reject with alert)
 * 4. Global PII redaction (redact before forwarding)
 */
const createSanitizedUploadHandler = (originalHandler, enqueueSnackbar, closeSnackbar) => {
    return async (file) => {
        try {
            // Step 1: Check for binary/executable signatures
            const arrayBuffer = await readFileAsArrayBuffer(file)
            if (hasBinarySignature(arrayBuffer)) {
                enqueueSnackbar({
                    message: 'File upload rejected: binary or executable files are not allowed.',
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

            // Step 2: Read file as text for content analysis
            let textContent
            try {
                textContent = await readFileAsText(file)
            } catch {
                // If we can't read as text, pass through to original handler
                originalHandler(file)
                return
            }

            // Step 3: Check for malicious content / prompt injection
            if (containsMaliciousContent(textContent)) {
                enqueueSnackbar({
                    message: 'File upload rejected: suspicious or potentially malicious content detected.',
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

            // Step 4: Check for Singapore-specific PII
            if (containsSingaporePII(textContent)) {
                alert(
                    'File upload rejected: the file contains Singapore personal data (NRIC/FIN, passport number, or personal name). Please remove this information before uploading.'
                )
                return
            }

            // Step 5: Redact global PII from file content
            const redactedText = redactPIIFromText(textContent)
            const sanitizedFile = new File([redactedText], file.name, { type: file.type, lastModified: file.lastModified })

            // Step 6: Forward sanitized file to original handler
            originalHandler(sanitizedFile)
        } catch (e) {
            console.error('File sanitization error:', e)
            // On unexpected error, reject the upload to be safe
            enqueueSnackbar({
                message: 'File upload rejected: an error occurred while scanning the file.',
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
}

// ==============================|| CANVAS HEADER ||============================== //

const CanvasHeader = ({ chatflow, isAgentCanvas, isAgentflowV2, handleSaveFlow, handleDeleteFlow, handleLoadFlow }) => {
    const theme = useTheme()
    const dispatch = useDispatch()
    const navigate = useNavigate()
    const flowNameRef = useRef()
    const settingsRef = useRef()

    const [isEditingFlowName, setEditingFlowName] = useState(null)
    const [flowName, setFlowName] = useState('')
    const [isSettingsOpen, setSettingsOpen] = useState(false)
    const [flowDialogOpen, setFlowDialogOpen] = useState(false)
    const [apiDialogOpen, setAPIDialogOpen] = useState(false)
    const [apiDialogProps, setAPIDialogProps] = useState({})
    const [viewMessagesDialogOpen, setViewMessagesDialogOpen] = useState(false)
    const [viewMessagesDialogProps, setViewMessagesDialogProps] = useState({})
    const [viewLeadsDialogOpen, setViewLeadsDialogOpen] = useState(false)
    const [viewLeadsDialogProps, setViewLeadsDialogProps] = useState({})
    const [upsertHistoryDialogOpen, setUpsertHistoryDialogOpen] = useState(false)
    const [upsertHistoryDialogProps, setUpsertHistoryDialogProps] = useState({})
    const [chatflowConfigurationDialogOpen, setChatflowConfigurationDialogOpen] = useState(false)
    const [chatflowConfigurationDialogProps, setChatflowConfigurationDialogProps] = useState({})

    const [exportAsTemplateDialogOpen, setExportAsTemplateDialogOpen] = useState(false)
    const [exportAsTemplateDialogProps, setExportAsTemplateDialogProps] = useState({})
    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const [savePermission, setSavePermission] = useState(isAgentCanvas ? 'agentflows:create' : 'chatflows:create')

    const title = isAgentCanvas ? 'Agents' : 'Chatflow'

    const updateChatflowApi = useApi(chatflowsApi.updateChatflow)
    const getScheduleStatusApi = useApi(chatflowsApi.getScheduleStatus)
    const toggleScheduleEnabledApi = useApi(chatflowsApi.toggleScheduleEnabled)
    const canvas = useSelector((state) => state.canvas)
    const isDark = useSelector((state) => state.customization.isDarkMode)

    const [scheduleEnabled, setScheduleEnabled] = useState(false)
    const [scheduleCanEnable, setScheduleCanEnable] = useState(false)
    const [scheduleCanEnableReason, setScheduleCanEnableReason] = useState('')
    const [scheduleStatusLoaded, setScheduleStatusLoaded] = useState(false)

    const isScheduleFlow = useMemo(() => {
        if (!chatflow?.flowData || !isAgentflowV2) return false
        try {
            const parsed = JSON.parse(chatflow.flowData)
            const startNode = (parsed.nodes || []).find((n) => n.data?.name === 'startAgentflow')
            return startNode?.data?.inputs?.startInputType === 'scheduleInput'
        } catch {
            return false
        }
    }, [chatflow?.flowData, isAgentflowV2])

    const onSettingsItemClick = (setting) => {
        setSettingsOpen(false)

        if (setting === 'deleteChatflow') {
            handleDeleteFlow()
        } else if (setting === 'viewMessages') {
            setViewMessagesDialogProps({
                title: 'View Messages',
                chatflow: chatflow,
                isChatflow: isAgentflowV2 ? false : true
            })
            setViewMessagesDialogOpen(true)
        } else if (setting === 'viewLeads') {
            setViewLeadsDialogProps({
                title: 'View Leads',
                chatflow: chatflow
            })
            setViewLeadsDialogOpen(true)
        } else if (setting === 'saveAsTemplate') {
            if (canvas.isDirty) {
                enqueueSnackbar({
                    message: 'Please save the flow before exporting as template',
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
            setExportAsTemplateDialogProps({
                title: 'Export As Template',
                chatflow: chatflow
            })
            setExportAsTemplateDialogOpen(true)
        } else if (setting === 'viewUpsertHistory') {
            setUpsertHistoryDialogProps({
                title: 'View Upsert History',
                chatflow: chatflow
            })
            setUpsertHistoryDialogOpen(true)
        } else if (setting === 'chatflowConfiguration') {
            setChatflowConfigurationDialogProps({
                title: `${title} Configuration`,
                chatflow: chatflow
            })
            setChatflowConfigurationDialogOpen(true)
        } else if (setting === 'duplicateChatflow') {
            try {
                let flowData = chatflow.flowData
                const parsedFlowData = JSON.parse(flowData)
                flowData = JSON.stringify(parsedFlowData)
                localStorage.setItem('duplicatedFlowData', flowData)
                if (isAgentflowV2) {
                    window.open(`${uiBaseURL}/v2/agentcanvas`, '_blank')
                } else if (isAgentCanvas) {
                    window.open(`${uiBaseURL}/agentcanvas`, '_blank')
                } else {
                    window.open(`${uiBaseURL}/canvas`, '_blank')
                }
            } catch (e) {
                console.error(e)
            }
        } else if (setting === 'exportChatflow') {
            try {
                const flowData = JSON.parse(chatflow.flowData)
                let dataStr = JSON.stringify(generateExportFlowData(flowData), null, 2)
                //let dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr)
                const blob = new Blob([dataStr], { type: 'application/json' })
                const dataUri = URL.createObjectURL(blob)

                let exportFileDefaultName = `${chatflow.name} ${title}.json`

                let linkElement = document.createElement('a')
                linkElement.setAttribute('href', dataUri)
                linkElement.setAttribute('download', exportFileDefaultName)
                linkElement.click()
            } catch (e) {
                console.error(e)
            }
        }
    }

    const onUploadFile = (file) => {
        setSettingsOpen(false)
        handleLoadFlow(file)
    }

    const sanitizedOnUploadFile = createSanitizedUploadHandler(onUploadFile, enqueueSnackbar, closeSnackbar)

    const submitFlowName = () => {
        if (chatflow.id) {
            const updateBody = {
                name: flowNameRef.current.value
            }
            updateChatflowApi.request(chatflow.id, updateBody)
        }
    }

    const onAPIDialogClick = () => {
        // If file type is file, isFormDataRequired = true
        let isFormDataRequired = false
        try {
            const flowData = JSON.parse(chatflow.flowData)
            const nodes = flowData.nodes
            for (const node of nodes) {
                if (node.data.inputParams.find((param) => param.type === 'file')) {
                    isFormDataRequired = true
                    break
                }
            }
        } catch (e) {
            console.error(e)
        }

        // If sessionId memory, isSessionMemory = true
        let isSessionMemory = false
        try {
            const flowData = JSON.parse(chatflow.flowData)
            const nodes = flowData.nodes
            for (const node of nodes) {
                if (node.data.inputParams.find((param) => param.name === 'sessionId')) {
                    isSessionMemory = true
                    break
                }
            }
        } catch (e) {
            console.error(e)
        }

        setAPIDialogProps({
            title: 'Embed in website or use as API',
            chatflowid: chatflow.id,
            chatflowApiKeyId: chatflow.apikeyid,
            isFormDataRequired,
            isSessionMemory,
            isAgentCanvas,
            isAgentflowV2
        })
        setAPIDialogOpen(true)
    }

    const onSaveChatflowClick = () => {
        if (chatflow.id) handleSaveFlow(flowName)
        else setFlowDialogOpen(true)
    }

    const onConfirmSaveName = (flowName) => {
        setFlowDialogOpen(false)
        setSavePermission(isAgentCanvas ? 'agentflows:update' : 'chatflows:update')
        handleSaveFlow(flowName)
    }

    useEffect(() => {
        if (updateChatflowApi.data) {
            setFlowName(updateChatflowApi.data.name)
            setSavePermission(isAgentCanvas ? 'agentflows:update' : 'chatflows:update')
            dispatch({ type: SET_CHATFLOW, chatflow: updateChatflowApi.data })
        }
        setEditingFlowName(false)

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [updateChatflowApi.data])

    useEffect(() => {
        if (chatflow) {
            setFlowName(chatflow.name)
            // if configuration dialog is open, update its data
            if (chatflowConfigurationDialogOpen) {
                setChatflowConfigurationDialogProps({
                    title: `${title} Configuration`,
                    chatflow
                })
            }
        }
    }, [chatflow, title, chatflowConfigurationDialogOpen])

    useEffect(() => {
        if (chatflow?.id && isScheduleFlow) {
            setScheduleStatusLoaded(false)
            getScheduleStatusApi.request(chatflow.id)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [chatflow?.id, chatflow?.updatedDate, isScheduleFlow])

    useEffect(() => {
        if (getScheduleStatusApi.data) {
            setScheduleEnabled(getScheduleStatusApi.data.enabled ?? false)
            setScheduleCanEnable(getScheduleStatusApi.data.canEnable ?? false)
            setScheduleCanEnableReason(getScheduleStatusApi.data.reason || '')
            setScheduleStatusLoaded(true)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [getScheduleStatusApi.data])

    useEffect(() => {
        if (toggleScheduleEnabledApi.data) {
            setScheduleEnabled(toggleScheduleEnabledApi.data.enabled ?? false)
            enqueueSnackbar({
                message: `Schedule ${toggleScheduleEnabledApi.data.enabled ? 'enabled' : 'disabled'} successfully`,
                options: { variant: 'success' }
            })
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [toggleScheduleEnabledApi.data])

    useEffect(() => {
        if (toggleScheduleEnabledApi.error) {
            enqueueSnackbar({
                message: String(toggleScheduleEnabledApi.error?.message || toggleScheduleEnabledApi.error || 'Failed to toggle schedule'),
                options: { variant: 'error' }
            })
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [toggleScheduleEnabledApi.error])

    const handleToggleSchedule = (newEnabled) => {
        toggleScheduleEnabledApi.request(chatflow.id, newEnabled)
    }

    return (
        <>
            <Stack flexDirection='row' justifyContent='space-between' sx={{ width: '100%' }}>
                <Stack flexDirection='row' sx={{ width: '100%', maxWidth: '50%' }}>
                    <Box>
                        <ButtonBase title='Back' sx={{ borderRadius: '50%' }}>
                            <Avatar
                                variant='rounded'
                                sx={{
                                    ...theme.typography.commonAvatar,
                                    ...theme.typography.mediumAvatar,
                                    transition: 'all .2s ease-in-out',
                                    background: theme.palette.secondary.light,
                                    color: theme.palette.secondary.dark,
                                    '&:hover': {
                                        background: theme.palette.secondary.dark,
                                        color: theme.palette.secondary.light
                                    }
                                }}
                                color='inherit'
                                onClick={() => {
                                    if (window.history.state && window.history.state.idx > 0) {
                                        navigate(-1)
                                    } else {
                                        navigate('/', { replace: true })
                                    }
                                }}
                            >
                                <IconChevronLeft stroke={1.5} size='1.3rem' />
                            </Avatar>
                        </ButtonBase>
                    </Box>
                    <Box sx={{ width: '100%' }}>
                        {!isEditingFlowName ? (
                            <Stack flexDirection='row'>
                                <Typography
                                    sx={{
                                        fontSize: '1.5rem',
                                        fontWeight: 600,
                                        ml: 2,
                                        textOverflow: 'ellipsis',
                                        overflow: 'hidden',
                                        whiteSpace: 'nowrap'
                                    }}
                                >
                                    {canvas.isDirty && <strong style={{ color: theme.palette.orange.main }}>*</strong>} {flowName}
                                </Typography>
                                {chatflow?.id && (
                                    <Available permission={savePermission}>
                                        <ButtonBase title='Edit Name' sx={{ borderRadius: '50%' }}>
                                            <Avatar
                                                variant='rounded'
                                                sx={{
                                                    ...theme.typography.commonAvatar,
                                                    ...theme.typography.mediumAvatar,
                                                    transition: 'all .2s ease-in-out',
                                                    ml: 1,
                                                    background: theme.palette.secondary.light,
                                                    color: theme.palette.secondary.dark,
                                                    '&:hover': {
                                                        background: theme.palette.secondary.dark,
                                                        color: theme.palette.secondary.light
                                                    }
                                                }}
                                                color='inherit'
                                                onClick={() => setEditingFlowName(true)}
                                            >
                                                <IconPencil stroke={1.5} size='1.3rem' />
                                            </Avatar>
                                        </ButtonBase>
                                    </Available>
                                )}
                            </Stack>
                        ) : (
                            <Stack flexDirection='row' sx={{ width: '100%' }}>
                                <TextField
                                    //eslint-disable-next-line jsx-a11y/no-autofocus
                                    autoFocus
                                    size='small'
                                    inputRef={flowNameRef}
                                    sx={{
                                        width: '100%',
                                        ml: 2
                                    }}
                                    defaultValue={flowName}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter') {
                                            submitFlowName()
                                        } else if (e.key === 'Escape') {
                                            setEditingFlowName(false)
                                        }
                                    }}
                                />
                                <ButtonBase title='Save Name' sx={{ borderRadius: '50%' }}>
                                    <Avatar
                                        variant='rounded'
                                        sx={{
                                            ...theme.typography.commonAvatar,
                                            ...theme.typography.mediumAvatar,
                                            transition: 'all .2s ease-in-out',
                                            background: theme.palette.success.light,
                                            color: theme.palette.success.dark,
                                            ml: 1,
                                            '&:hover': {
                                                background: theme.palette.success.dark,
                                                color: theme.palette.success.light
                                            }
                                        }}
                                        color='inherit'
                                        onClick={submitFlowName}
                                    >
                                        <IconCheck stroke={1.5} size='1.3rem' />
                                    </Avatar>
                                </ButtonBase>
                                <ButtonBase title='Cancel' sx={{ borderRadius: '50%' }}>
                                    <Avatar
                                        variant='rounded'
                                        sx={{
                                            ...theme.typography.commonAvatar,
                                            ...theme.typography.mediumAvatar,
                                            transition: 'all .2s ease-in-out',
                                            background: theme.palette.error.light,
                                            color: theme.palette.error.dark,
                                            ml: 1,
                                            '&:hover': {
                                                background: theme.palette.error.dark,
                                                color: theme.palette.error.light
                                            }
                                        }}
                                        color='inherit'
                                        onClick={() => setEditingFlowName(false)}
                                    >
                                        <IconX stroke={1.5} size='1.3rem' />
                                    </Avatar>
                                </ButtonBase>
                            </Stack>
                        )}
                    </Box>
                </Stack>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    {chatflow?.id && isAgentflowV2 && isScheduleFlow && scheduleStatusLoaded && (
                        <Tooltip
                            title={
                                scheduleEnabled
                                    ? 'Schedule active — click to disable'
                                    : scheduleCanEnable
                                    ? 'Schedule inactive — click to enable'
                                    : scheduleCanEnableReason || 'Fix the schedule configuration to enable'
                            }
                        >
                            <Box
                                sx={{
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    verticalAlign: 'middle',
                                    mr: 2,
                                    gap: 0.5
                                }}
                            >
                                {!scheduleCanEnable && !scheduleEnabled ? (
                                    <>
                                        <IconAlertTriangleFilled size={16} color={theme.palette.warning.main} style={{ marginRight: 4 }} />
                                        <LockedScheduleSwitch checked={false} disabled isDark={isDark} />
                                    </>
                                ) : (
                                    <ScheduleSwitch
                                        checked={scheduleEnabled}
                                        onChange={(e) => handleToggleSchedule(e.target.checked)}
                                        isDark={isDark}
                                    />
                                )}
                            </Box>
                        </Tooltip>
                    )}
                    {chatflow?.id && (
                        <ButtonBase title='API Endpoint' sx={{ borderRadius: '50%', mr: 2 }}>
                            <Avatar
                                variant='rounded'
                                sx={{
                                    ...theme.typography.commonAvatar,
                                    ...theme.typography.mediumAvatar,
                                    transition: 'all .2s ease-in-out',
                                    background: theme.palette.canvasHeader.deployLight,
                                    color: theme.palette.canvasHeader.deployDark,
                                    '&:hover': {
                                        background: theme.palette.canvasHeader.deployDark,
                                        color: theme.palette.canvasHeader.deployLight
                                    }
                                }}
                                color='inherit'
                                onClick={onAPIDialogClick}
                            >
                                <IconCode stroke={1.5} size='1.3rem' />
                            </Avatar>
                        </ButtonBase>
                    )}
                    <Available permission={savePermission}>
                        <ButtonBase title={`Save ${title}`} sx={{ borderRadius: '50%', mr: 2 }}>
                            <Avatar
                                variant='rounded'
                                sx={{
                                    ...theme.typography.commonAvatar,
                                    ...theme.typography.mediumAvatar,
                                    transition: 'all .2s ease-in-out',
                                    background: theme.palette.canvasHeader.saveLight,
                                    color: theme.palette.canvasHeader.saveDark,
                                    '&:hover': {
                                        background: theme.palette.canvasHeader.saveDark,
                                        color: theme.palette.canvasHeader.saveLight
                                    }
                                }}
                                color='inherit'
                                onClick={onSaveChatflowClick}
                            >
                                <IconDeviceFloppy stroke={1.5} size='1.3rem' />
                            </Avatar>
                        </ButtonBase>
                    </Available>
                    <ButtonBase ref={settingsRef} title='Settings' sx={{ borderRadius: '50%' }}>
                        <Avatar
                            variant='rounded'
                            sx={{
                                ...theme.typography.commonAvatar,
                                ...theme.typography.mediumAvatar,
                                transition: 'all .2s ease-in-out',
                                background: theme.palette.canvasHeader.settingsLight,
                                color: theme.palette.canvasHeader.settingsDark,
                                '&:hover': {
                                    background: theme.palette.canvasHeader.settingsDark,
                                    color: theme.palette.canvasHeader.settingsLight
                                }
                            }}
                            onClick={() => setSettingsOpen(!isSettingsOpen)}
                        >
                            <IconSettings stroke={1.5} size='1.3rem' />
                        </Avatar>
                    </ButtonBase>
                </Box>
            </Stack>
            <Settings
                chatflow={chatflow}
                isSettingsOpen={isSettingsOpen}
                anchorEl={settingsRef.current}
                onClose={() => setSettingsOpen(false)}
                onSettingsItemClick={onSettingsItemClick}
                onUploadFile={sanitizedOnUploadFile}
                isAgentCanvas={isAgentCanvas}
            />
            <SaveChatflowDialog
                show={flowDialogOpen}
                dialogProps={{
                    title: `Save New ${title}`,
                    confirmButtonName: 'Save',
                    cancelButtonName: 'Cancel'
                }}
                onCancel={() => setFlowDialogOpen(false)}
                onConfirm={onConfirmSaveName}
            />
            {apiDialogOpen && <APICodeDialog show={apiDialogOpen} dialogProps={apiDialogProps} onCancel={() => setAPIDialogOpen(false)} />}
            <ViewMessagesDialog
                show={viewMessagesDialogOpen}
                dialogProps={viewMessagesDialogProps}
                onCancel={() => setViewMessagesDialogOpen(false)}
            />
            <ViewLeadsDialog show={viewLeadsDialogOpen} dialogProps={viewLeadsDialogProps} onCancel={() => setViewLeadsDialogOpen(false)} />
            {exportAsTemplateDialogOpen && (
                <ExportAsTemplateDialog
                    show={exportAsTemplateDialogOpen}
                    dialogProps={exportAsTemplateDialogProps}
                    onCancel={() => setExportAsTemplateDialogOpen(false)}
                />
            )}
            <UpsertHistoryDialog
                show={upsertHistoryDialogOpen}
                dialogProps={upsertHistoryDialogProps}
                onCancel={() => setUpsertHistoryDialogOpen(false)}
            />
            <ChatflowConfigurationDialog
                key='chatflowConfiguration'
                show={chatflowConfigurationDialogOpen}
                dialogProps={chatflowConfigurationDialogProps}
                onCancel={() => setChatflowConfigurationDialogOpen(false)}
                isAgentCanvas={isAgentCanvas}
            />
        </>
    )
}

CanvasHeader.propTypes = {
    chatflow: PropTypes.object,
    handleSaveFlow: PropTypes.func,
    handleDeleteFlow: PropTypes.func,
    handleLoadFlow: PropTypes.func,
    isAgentCanvas: PropTypes.bool,
    isAgentflowV2: PropTypes.bool
}

export default CanvasHeader
import PropTypes from 'prop-types'
import { useState, useMemo, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useSelector } from 'react-redux'
import { Box, Dialog, DialogContent, DialogTitle, Typography, IconButton, Snackbar, Alert } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import {
    IconX,
    IconShieldLock,
    IconWorldWww,
    IconUserPlus,
    IconMessageChatbot,
    IconArrowForwardUp,
    IconThumbUp,
    IconMicrophone,
    IconVolume,
    IconUpload,
    IconChartBar,
    IconCode,
    IconServer,
    IconAdjustments
} from '@tabler/icons-react'
import PerfectScrollbar from 'react-perfect-scrollbar'

// Section components
import SpeechToText from '@/ui-component/extended/SpeechToText'
import TextToSpeech from '@/ui-component/extended/TextToSpeech'
import RateLimit from '@/ui-component/extended/RateLimit'
import AllowedDomains from '@/ui-component/extended/AllowedDomains'
import OverrideConfig from '@/ui-component/extended/OverrideConfig'
import ChatFeedback from '@/ui-component/extended/ChatFeedback'
import AnalyseFlow from '@/ui-component/extended/AnalyseFlow'
import StarterPrompts from '@/ui-component/extended/StarterPrompts'
import Leads from '@/ui-component/extended/Leads'
import FollowUpPrompts from '@/ui-component/extended/FollowUpPrompts'
import FileUpload from '@/ui-component/extended/FileUpload'
import PostProcessing from '@/ui-component/extended/PostProcessing'
import McpServer from '@/ui-component/extended/McpServer'

// ---------------------------------------------------------------------------
// PII detection & redaction utilities
// ---------------------------------------------------------------------------

/**
 * General PII patterns (global)
 */
const GENERAL_PII_PATTERNS = [
    // Email addresses
    { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, label: 'email' },
    // Phone numbers (various formats)
    { pattern: /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}/g, label: 'phone' },
    // US SSN
    { pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, label: 'ssn' },
    // Credit card numbers (Visa, MC, Amex, Discover)
    { pattern: /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/g, label: 'credit_card' },
    // Generic 16-digit card numbers with optional separators
    { pattern: /\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g, label: 'card_number' },
    // IPv4 addresses
    { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, label: 'ipv4' },
    // Dates of birth (common formats)
    { pattern: /\b(?:0?[1-9]|[12]\d|3[01])[\/\-.](?:0?[1-9]|1[0-2])[\/\-.](?:19|20)\d{2}\b/g, label: 'dob' },
    // Passport numbers (generic alphanumeric)
    { pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, label: 'passport' }
]

/**
 * Singapore-specific PII patterns (PDPA / MAS compliance)
 */
const SINGAPORE_PII_PATTERNS = [
    // NRIC / FIN: S/T/F/G followed by 7 digits and a letter
    { pattern: /\b[STFG]\d{7}[A-Z]\b/gi, label: 'NRIC/FIN' },
    // SingPass ID (same format as NRIC but explicitly labelled)
    { pattern: /\b[STFG]\d{7}[A-Z]\b/gi, label: 'SingPass' },
    // CPF account numbers (typically 9 digits)
    { pattern: /\b\d{9}\b/g, label: 'CPF' },
    // Singapore phone numbers (+65 followed by 8 digits)
    { pattern: /(?:\+65[\s\-]?)?\b[689]\d{7}\b/g, label: 'SG_phone' },
    // Singapore postal codes (6 digits starting with valid prefix)
    { pattern: /\b(?:0[1-9]|[1-7]\d|8[0-8])\d{4}\b/g, label: 'SG_postal' },
    // Singapore bank account numbers (various formats, 10-16 digits)
    { pattern: /\b\d{10,16}\b/g, label: 'SG_bank_account' }
]

/**
 * Detect Singapore-specific PII in text.
 * Returns an array of detected PII labels.
 */
function detectSingaporePII(text) {
    const detected = []
    for (const { pattern, label } of SINGAPORE_PII_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags)
        if (regex.test(text)) {
            detected.push(label)
        }
    }
    return detected
}

/**
 * Redact general PII from text by replacing matches with a placeholder.
 */
function redactGeneralPII(text) {
    let redacted = text
    for (const { pattern, label } of GENERAL_PII_PATTERNS) {
        const regex = new RegExp(pattern.source, pattern.flags)
        redacted = redacted.replace(regex, `[REDACTED_${label.toUpperCase()}]`)
    }
    return redacted
}

/**
 * Read a File object as text (returns a Promise<string>).
 */
function readFileAsText(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = (e) => resolve(e.target.result)
        reader.onerror = (e) => reject(e)
        reader.readAsText(file)
    })
}

/**
 * Process a list of File objects:
 *  1. Read each file as text.
 *  2. Detect Singapore PII — if found, block and return an error.
 *  3. Redact general PII from the content.
 *  4. Return sanitized File objects (or an error descriptor).
 *
 * Returns: { sanitizedFiles: File[], blockedFiles: { file: File, reasons: string[] }[] }
 */
async function processFilesForPII(files) {
    const sanitizedFiles = []
    const blockedFiles = []

    for (const file of files) {
        // Only attempt text-based PII scanning for text-like MIME types
        const isTextLike =
            file.type.startsWith('text/') ||
            file.type === 'application/json' ||
            file.type === 'application/xml' ||
            file.type === 'application/csv' ||
            file.name.match(/\.(txt|csv|json|xml|md|log|yaml|yml)$/i)

        if (!isTextLike) {
            // Non-text files pass through without scanning
            sanitizedFiles.push(file)
            continue
        }

        let text
        try {
            text = await readFileAsText(file)
        } catch {
            // If we cannot read the file, pass it through
            sanitizedFiles.push(file)
            continue
        }

        // Step 1: Check for Singapore PII — block if found
        const sgPII = detectSingaporePII(text)
        if (sgPII.length > 0) {
            blockedFiles.push({ file, reasons: sgPII })
            continue
        }

        // Step 2: Redact general PII
        const redactedText = redactGeneralPII(text)

        // Step 3: Rebuild the File with sanitized content
        const sanitizedBlob = new Blob([redactedText], { type: file.type || 'text/plain' })
        const sanitizedFile = new File([sanitizedBlob], file.name, {
            type: file.type,
            lastModified: file.lastModified
        })
        sanitizedFiles.push(sanitizedFile)
    }

    return { sanitizedFiles, blockedFiles }
}

// ---------------------------------------------------------------------------

const CONFIGURATION_GROUPS = [
    {
        label: 'General',
        sections: [
            {
                label: 'Rate Limit',
                id: 'rateLimit',
                icon: IconShieldLock,
                description: 'Limit API requests per time window'
            },
            {
                label: 'Allowed Domains',
                id: 'allowedDomains',
                icon: IconWorldWww,
                description: 'Restrict chatbot to specific domains'
            },
            {
                label: 'Leads',
                id: 'leads',
                icon: IconUserPlus,
                description: 'Capture visitor contact information'
            }
        ]
    },
    {
        label: 'Chat',
        sections: [
            {
                label: 'Starter Prompts',
                id: 'conversationStarters',
                icon: IconMessageChatbot,
                description: 'Suggested prompts for new conversations'
            },
            {
                label: 'Follow-up Prompts',
                id: 'followUpPrompts',
                icon: IconArrowForwardUp,
                description: 'Auto-generate follow-up questions'
            },
            {
                label: 'Chat Feedback',
                id: 'chatFeedback',
                icon: IconThumbUp,
                description: 'Allow users to rate responses'
            }
        ]
    },
    {
        label: 'Media & Files',
        sections: [
            {
                label: 'Speech to Text',
                id: 'speechToText',
                icon: IconMicrophone,
                description: 'Voice input transcription'
            },
            {
                label: 'Text to Speech',
                id: 'textToSpeech',
                icon: IconVolume,
                description: 'Audio response playback'
            },
            {
                label: 'File Upload',
                id: 'fileUpload',
                icon: IconUpload,
                description: 'Allow file uploads in chat'
            }
        ]
    },
    {
        label: 'Advanced',
        sections: [
            {
                label: 'Analytics',
                id: 'analyseChatflow',
                icon: IconChartBar,
                description: 'Connect analytics providers'
            },
            {
                label: 'Post Processing',
                id: 'postProcessing',
                icon: IconCode,
                description: 'Custom JavaScript post-processing'
            },
            {
                label: 'MCP Server',
                id: 'mcpServer',
                icon: IconServer,
                description: 'Model Context Protocol server'
            },
            {
                label: 'Override Config',
                id: 'overrideConfig',
                icon: IconAdjustments,
                description: 'Override flow configuration via API'
            }
        ]
    }
]

function getSectionStatus(sectionId, chatflow) {
    if (!chatflow) return false

    let chatbotConfig = {}
    let apiConfig = {}
    try {
        chatbotConfig = chatflow.chatbotConfig ? JSON.parse(chatflow.chatbotConfig) : {}
        apiConfig = chatflow.apiConfig ? JSON.parse(chatflow.apiConfig) : {}
    } catch {
        return false
    }

    switch (sectionId) {
        case 'rateLimit':
            return apiConfig?.rateLimit?.status === true
        case 'allowedDomains':
            return Array.isArray(chatbotConfig?.allowedOrigins) && chatbotConfig.allowedOrigins.some((o) => o && o.trim() !== '')
        case 'leads':
            return chatbotConfig?.leads?.status === true
        case 'conversationStarters': {
            const sp = chatbotConfig?.starterPrompts
            if (!sp) return false
            return Object.values(sp).some((entry) => entry?.prompt && entry.prompt.trim() !== '')
        }
        case 'followUpPrompts':
            return chatbotConfig?.followUpPrompts?.status === true
        case 'chatFeedback':
            return chatbotConfig?.chatFeedback?.status === true
        case 'speechToText': {
            if (!chatflow.speechToText) return false
            try {
                const stt = JSON.parse(chatflow.speechToText)
                // "none" with status:true means disabled — ignore it
                return Object.entries(stt).some(([key, provider]) => key !== 'none' && provider?.status === true)
            } catch {
                return false
            }
        }
        case 'textToSpeech': {
            if (!chatflow.textToSpeech) return false
            try {
                const tts = JSON.parse(chatflow.textToSpeech)
                return Object.entries(tts).some(([key, provider]) => key !== 'none' && provider?.status === true)
            } catch {
                return false
            }
        }
        case 'fileUpload':
            return chatbotConfig?.fullFileUpload?.status === true
        case 'analyseChatflow': {
            if (!chatflow.analytic) return false
            try {
                const ap = JSON.parse(chatflow.analytic)
                return Object.values(ap).some((provider) => provider?.status === true)
            } catch {
                return false
            }
        }
        case 'postProcessing':
            return chatbotConfig?.postProcessing?.enabled === true
        case 'mcpServer': {
            if (!chatflow.mcpServerConfig) return false
            try {
                const mcp = typeof chatflow.mcpServerConfig === 'string' ? JSON.parse(chatflow.mcpServerConfig) : chatflow.mcpServerConfig
                return mcp?.enabled === true
            } catch {
                return false
            }
        }
        case 'overrideConfig':
            return apiConfig?.overrideConfig?.status === true
        default:
            return false
    }
}

// Flatten all sections for quick lookup
const ALL_SECTIONS = CONFIGURATION_GROUPS.flatMap((g) => g.sections)

const SIDEBAR_WIDTH = 220

const ChatflowConfigurationDialog = ({ show, isAgentCanvas, dialogProps, onCancel }) => {
    const portalElement = document.getElementById('portal')
    const theme = useTheme()
    const chatflow = useSelector((state) => state.canvas.chatflow)
    const customization = useSelector((state) => state.customization)

    const [activeSection, setActiveSection] = useState('rateLimit')
    const [piiError, setPiiError] = useState(null)
    const [piiErrorOpen, setPiiErrorOpen] = useState(false)

    const isDark = theme.palette.mode === 'dark' || customization?.isDarkMode

    // Filter groups/sections based on agent canvas
    const filteredGroups = useMemo(() => {
        return CONFIGURATION_GROUPS.map((group) => ({
            ...group,
            sections: group.sections.filter((section) => !isAgentCanvas || !section.hideInAgentFlow)
        })).filter((group) => group.sections.length > 0)
    }, [isAgentCanvas])

    // Get all section IDs for validation
    const allSectionIds = useMemo(() => {
        return filteredGroups.flatMap((g) => g.sections.map((s) => s.id))
    }, [filteredGroups])

    // Reset activeSection if current one is filtered out
    const currentSection = allSectionIds.includes(activeSection) ? activeSection : allSectionIds[0] || 'rateLimit'
    const currentSectionData = ALL_SECTIONS.find((s) => s.id === currentSection)

    /**
     * Wraps the FileUpload component's onUpload callback.
     * Scans files for Singapore PII (blocks) and redacts general PII before forwarding.
     */
    const handleFileUploadWithPIICheck = useCallback(
        async (files, originalOnUpload) => {
            if (!files || files.length === 0) {
                if (originalOnUpload) originalOnUpload(files)
                return
            }

            const fileArray = Array.from(files)
            const { sanitizedFiles, blockedFiles } = await processFilesForPII(fileArray)

            if (blockedFiles.length > 0) {
                const blockedNames = blockedFiles
                    .map(({ file, reasons }) => `"${file.name}" (detected: ${reasons.join(', ')})`)
                    .join('; ')
                setPiiError(
                    `Upload blocked: The following file(s) contain Singapore PII and cannot be uploaded: ${blockedNames}. Please remove sensitive information before uploading.`
                )
                setPiiErrorOpen(true)
                // Do not forward any files if any are blocked
                return
            }

            if (originalOnUpload) {
                // Convert sanitized File array back to a FileList-like structure if needed
                originalOnUpload(sanitizedFiles)
            }
        },
        []
    )

    const handlePiiErrorClose = useCallback(() => {
        setPiiErrorOpen(false)
    }, [])

    const renderContent = () => {
        const props = { dialogProps }
        switch (currentSection) {
            case 'rateLimit':
                return <RateLimit {...props} hideTitle />
            case 'allowedDomains':
                return <AllowedDomains {...props} hideTitle />
            case 'leads':
                return <Leads {...props} />
            case 'conversationStarters':
                return <StarterPrompts {...props} />
            case 'followUpPrompts':
                return <FollowUpPrompts {...props} />
            case 'chatFeedback':
                return <ChatFeedback {...props} />
            case 'speechToText':
                return <SpeechToText {...props} />
            case 'textToSpeech':
                return <TextToSpeech {...props} />
            case 'fileUpload':
                return (
                    <FileUpload
                        {...props}
                        onUpload={(files) => handleFileUploadWithPIICheck(files, props.dialogProps?.onUpload)}
                    />
                )
            case 'analyseChatflow':
                return <AnalyseFlow {...props} />
            case 'postProcessing':
                return <PostProcessing {...props} />
            case 'mcpServer':
                return <McpServer {...props} />
            case 'overrideConfig':
                return <OverrideConfig {...props} hideTitle />
            default:
                return null
        }
    }

    const component = show ? (
        <>
            <Dialog
                onClose={onCancel}
                open={show}
                fullWidth
                maxWidth={false}
                PaperProps={{
                    sx: {
                        width: 960,
                        maxWidth: '95vw',
                        height: '82vh',
                        maxHeight: '82vh',
                        display: 'flex',
                        flexDirection: 'column',
                        borderRadius: '12px',
                        overflow: 'hidden'
                    }
                }}
                aria-labelledby='chatflow-config-dialog-title'
            >
                {/* Header */}
                <DialogTitle
                    id='chatflow-config-dialog-title'
                    sx={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        py: 2,
                        px: 3,
                        borderBottom: '1px solid',
                        borderColor: 'divider',
                        minHeight: 'auto',
                        bgcolor: isDark ? 'background.paper' : '#fff'
                    }}
                >
                    <Typography sx={{ fontSize: '1.125rem', fontWeight: 600, color: 'text.primary' }}>{dialogProps.title}</Typography>
                    <IconButton
                        size='small'
                        onClick={onCancel}
                        sx={{
                            color: 'text.secondary',
                            '&:hover': { bgcolor: isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.04)' }
                        }}
                    >
                        <IconX size={18} />
                    </IconButton>
                </DialogTitle>

                {/* Body: Sidebar + Content */}
                <DialogContent sx={{ display: 'flex', p: 0, overflow: 'hidden', flex: 1 }}>
                    {/* Sidebar */}
                    <Box
                        sx={{
                            width: SIDEBAR_WIDTH,
                            minWidth: SIDEBAR_WIDTH,
                            borderRight: '1px solid',
                            borderColor: 'divider',
                            bgcolor: isDark ? 'rgba(0,0,0,0.15)' : theme.palette.grey[50],
                            display: 'flex',
                            flexDirection: 'column'
                        }}
                    >
                        <PerfectScrollbar style={{ height: '100%', overflowX: 'hidden' }}>
                            <Box sx={{ py: 2, px: 1 }}>
                                {filteredGroups.map((group, groupIndex) => (
                                    <Box key={group.label} sx={{ mb: 0.5 }}>
                                        {/* Group label */}
                                        <Typography
                                            sx={{
                                                fontSize: '0.6875rem',
                                                fontWeight: 600,
                                                textTransform: 'uppercase',
                                                letterSpacing: '0.05em',
                                                color: isDark ? 'grey.500' : 'grey.500',
                                                px: 1.5,
                                                pt: groupIndex > 0 ? 2 : 0.5,
                                                pb: 0.75
                                            }}
                                        >
                                            {group.label}
                                        </Typography>

                                        {/* Section items */}
                                        {group.sections.map((section) => {
                                            const isActive = currentSection === section.id
                                            const isEnabled = getSectionStatus(section.id, chatflow)
                                            const SectionIcon = section.icon

                                            return (
                                                <Box
                                                    key={section.id}
                                                    onClick={() => setActiveSection(section.id)}
                                                    sx={{
                                                        display: 'flex',
                                                        alignItems: 'center',
                                                        gap: 1.25,
                                                        px: 1.5,
                                                        py: 0.875,
                                                        borderRadius: '8px',
                                                        cursor: 'pointer',
                                                        position: 'relative',
                                                        color: isActive ? 'primary.main' : isDark ? 'grey.300' : 'grey.700',
                                                        bgcolor: isActive
                                                            ? isDark
                                                                ? 'rgba(33, 150, 243, 0.12)'
                                                                : 'rgba(33, 150, 243, 0.06)'
                                                            : 'transparent',
                                                        transition: 'all 0.15s ease',
                                                        '&:hover': {
                                                            bgcolor: isActive
                                                                ? isDark
                                                                    ? 'rgba(33, 150, 243, 0.16)'
                                                                    : 'rgba(33, 150, 243, 0.08)'
                                                                : isDark
                                                                ? 'rgba(255,255,255,0.04)'
                                                                : 'rgba(0,0,0,0.03)'
                                                        },
                                                        userSelect: 'none'
                                                    }}
                                                >
                                                    {/* Icon */}
                                                    <SectionIcon
                                                        size={17}
                                                        stroke={1.5}
                                                        style={{
                                                            flexShrink: 0,
                                                            opacity: isActive ? 1 : 0.7
                                                        }}
                                                    />

                                                    {/* Label */}
                                                    <Typography
                                                        sx={{
                                                            fontSize: '0.8125rem',
                                                            fontWeight: isActive ? 600 : 400,
                                                            color: 'inherit',
                                                            lineHeight: 1.3,
                                                            flex: 1,
                                                            whiteSpace: 'nowrap',
                                                            overflow: 'hidden',
                                                            textOverflow: 'ellipsis'
                                                        }}
                                                    >
                                                        {section.label}
                                                    </Typography>

                                                    {/* Status badge - only show when enabled */}
                                                    {isEnabled && (
                                                        <Box
                                                            sx={{
                                                                px: 0.875,
                                                                py: 0.125,
                                                                borderRadius: '4px',
                                                                fontSize: '0.625rem',
                                                                fontWeight: 600,
                                                                lineHeight: 1.6,
                                                                letterSpacing: '0.02em',
                                                                flexShrink: 0,
                                                                bgcolor: isDark ? 'rgba(34,197,94,0.15)' : 'rgba(34,197,94,0.1)',
                                                                color: isDark ? '#4ade80' : '#16a34a'
                                                            }}
                                                        >
                                                            ON
                                                        </Box>
                                                    )}
                                                </Box>
                                            )
                                        })}
                                    </Box>
                                ))}
                            </Box>
                        </PerfectScrollbar>
                    </Box>

                    {/* Content area */}
                    <Box
                        sx={{
                            flex: 1,
                            display: 'flex',
                            flexDirection: 'column',
                            overflow: 'hidden',
                            bgcolor: isDark ? 'background.paper' : '#fff'
                        }}
                    >
                        <PerfectScrollbar style={{ height: '100%' }}>
                            <Box sx={{ px: 3.5, py: 3 }}>
                                {/* Section header */}
                                <Box sx={{ mb: 2.5 }}>
                                    <Typography
                                        sx={{
                                            fontSize: '1rem',
                                            fontWeight: 600,
                                            color: 'text.primary',
                                            mb: 0.25
                                        }}
                                    >
                                        {currentSectionData?.label || ''}
                                    </Typography>
                                    {currentSectionData?.description && (
                                        <Typography
                                            sx={{
                                                fontSize: '0.8rem',
                                                color: 'text.secondary',
                                                lineHeight: 1.5,
                                                opacity: isDark ? 0.8 : 1
                                            }}
                                        >
                                            {currentSectionData.description}
                                        </Typography>
                                    )}
                                </Box>

                                {/* Section content */}
                                {renderContent()}
                            </Box>
                        </PerfectScrollbar>
                    </Box>
                </DialogContent>
            </Dialog>

            {/* PII error notification */}
            <Snackbar
                open={piiErrorOpen}
                autoHideDuration={8000}
                onClose={handlePiiErrorClose}
                anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
            >
                <Alert onClose={handlePiiErrorClose} severity='error' sx={{ width: '100%' }}>
                    {piiError}
                </Alert>
            </Snackbar>
        </>
    ) : null

    return createPortal(component, portalElement)
}

ChatflowConfigurationDialog.propTypes = {
    show: PropTypes.bool,
    isAgentCanvas: PropTypes.bool,
    dialogProps: PropTypes.object,
    onCancel: PropTypes.func
}

export default ChatflowConfigurationDialog
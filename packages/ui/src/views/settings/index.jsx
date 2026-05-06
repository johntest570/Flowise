import { useState, useEffect, useRef } from 'react'
import PropTypes from 'prop-types'
import { useSelector } from 'react-redux'

// material-ui
import { useTheme } from '@mui/material/styles'
import { ListItemButton, ListItemIcon, ListItemText, Typography, Box, List, Paper, Popper, ClickAwayListener } from '@mui/material'
import FiberManualRecordIcon from '@mui/icons-material/FiberManualRecord'

// third-party
import PerfectScrollbar from 'react-perfect-scrollbar'

// project imports
import MainCard from '@/ui-component/cards/MainCard'
import Transitions from '@/ui-component/extended/Transitions'
import settings from '@/menu-items/settings'
import agentsettings from '@/menu-items/agentsettings'
import customAssistantSettings from '@/menu-items/customassistant'
import { useAuth } from '@/hooks/useAuth'

// ==============================|| SETTINGS ||============================== //

const containsHiddenUnicode = (str) => {
    // Check for hidden/invisible Unicode characters
    const hiddenUnicodePattern = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\u206A-\u206F\uFEFF\u00A0]/
    return hiddenUnicodePattern.test(str)
}

const containsBase64 = (str) => {
    // Detect base64-encoded content (long base64 strings)
    const base64Pattern = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/
    return base64Pattern.test(str)
}

const containsLeetspeak = (str) => {
    // Detect common leetspeak patterns
    const leetspeakPattern = /(\b\w*[013@$!][013@$!]\w*\b.*){3,}/i
    // More targeted: words with multiple leet substitutions
    const leetspeakWords = /\b(?:[a-z]*[0-9@$!|][a-z0-9@$!|]*){2,}\b/gi
    const matches = str.match(leetspeakWords)
    return matches && matches.length > 5
}

const containsShellCommands = (str) => {
    // Detect shell commands or executable signatures
    const shellPattern = /(\b(bash|sh|zsh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|rm\s+-rf|chmod|chown|wget|curl\s+.*http|nc\s+|netcat|nmap|sudo|su\s+root)\b)/i
    const execSignatures = /^(#!\/bin\/|MZ|ELF|\x7fELF|PK\x03\x04)/
    return shellPattern.test(str) || execSignatures.test(str)
}

const containsPromptInjection = (str) => {
    // Detect suspicious prompt injection keywords
    const injectionPattern = /(\bignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)\b|\bsystem\s*prompt\b|\byou\s+are\s+now\b|\bact\s+as\b|\bpretend\s+(you\s+are|to\s+be)\b|\bforget\s+(everything|all|your)\b|\bnew\s+instructions?\b|\boverride\s+(instructions?|rules?|constraints?)\b|\bjailbreak\b|\bDAN\b|\bdo\s+anything\s+now\b)/i
    return injectionPattern.test(str)
}

const redactPII = (str) => {
    // Redact SSN
    let redacted = str.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED-SSN]')
    // Redact email addresses
    redacted = redacted.replace(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, '[REDACTED-EMAIL]')
    // Redact credit card numbers (basic patterns)
    redacted = redacted.replace(/\b(?:\d{4}[\s\-]?){3}\d{4}\b/g, '[REDACTED-CC]')
    // Redact passport numbers (generic: letter(s) followed by digits)
    redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, '[REDACTED-PASSPORT]')
    // Redact phone numbers
    redacted = redacted.replace(/\b(?:\+?1?\s?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4}\b/g, '[REDACTED-PHONE]')
    return redacted
}

const detectSingaporePII = (str) => {
    // Singapore NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/i
    // Singapore passport: E followed by 7 digits or similar
    const sgPassportPattern = /\bE\d{7}[A-Z]?\b/i
    // Singapore bank account numbers (DBS/POSB/OCBC/UOB patterns)
    const sgBankPattern = /\b\d{3}-\d{5,6}-\d{1,3}\b/
    // Personal email (already covered by general PII but check again)
    const emailPattern = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/
    // Full names (heuristic: 2-4 capitalized words in sequence)
    const fullNamePattern = /\b([A-Z][a-z]+\s){1,3}[A-Z][a-z]+\b/

    if (nricPattern.test(str)) return 'Singapore NRIC/FIN number'
    if (sgPassportPattern.test(str)) return 'Singapore passport number'
    if (sgBankPattern.test(str)) return 'Singapore bank account number'
    if (emailPattern.test(str)) return 'personal email address'
    if (fullNamePattern.test(str)) return 'full name'
    return null
}

const Settings = ({ chatflow, isSettingsOpen, isCustomAssistant, anchorEl, isAgentCanvas, onSettingsItemClick, onUploadFile, onClose }) => {
    const theme = useTheme()
    const [settingsMenu, setSettingsMenu] = useState([])
    const customization = useSelector((state) => state.customization)
    const inputFile = useRef(null)
    const [open, setOpen] = useState(false)
    const { hasPermission } = useAuth()

    const handleFileUpload = (e) => {
        if (!e.target.files) return

        const file = e.target.files[0]

        const reader = new FileReader()
        reader.onload = (evt) => {
            if (!evt?.target?.result) {
                return
            }
            const { result } = evt.target

            // (1) Ensure it is valid JSON
            try {
                JSON.parse(result)
            } catch (err) {
                alert('Invalid file: The uploaded file does not contain valid JSON.')
                return
            }

            // (2) Scan for hidden/invisible Unicode characters
            if (containsHiddenUnicode(result)) {
                alert('Invalid file: The uploaded file contains hidden or invisible Unicode characters, which may indicate malicious content.')
                return
            }

            // (3) Detect base64-encoded content
            if (containsBase64(result)) {
                alert('Invalid file: The uploaded file contains base64-encoded content, which is not allowed.')
                return
            }

            // (4) Detect leetspeak patterns
            if (containsLeetspeak(result)) {
                alert('Invalid file: The uploaded file contains leetspeak patterns, which may indicate obfuscated malicious content.')
                return
            }

            // (5) Detect shell commands or executable signatures
            if (containsShellCommands(result)) {
                alert('Invalid file: The uploaded file contains shell commands or executable signatures, which are not allowed.')
                return
            }

            // (6) Detect suspicious prompt injection keywords
            if (containsPromptInjection(result)) {
                alert('Invalid file: The uploaded file contains suspicious prompt injection keywords, which are not allowed.')
                return
            }

            // Singapore PII detection — abort if found
            const sgPiiType = detectSingaporePII(result)
            if (sgPiiType) {
                alert(`Upload aborted: The uploaded file contains Singapore PII (${sgPiiType}). Please remove this information before uploading.`)
                return
            }

            // Redact common PII before passing to onUploadFile
            const sanitizedResult = redactPII(result)

            onUploadFile(sanitizedResult)
        }
        reader.readAsText(file)
    }

    useEffect(() => {
        if (chatflow && !chatflow.id) {
            const menus = isAgentCanvas ? agentsettings : settings
            const settingsMenu = menus.children.filter((menu) => menu.id === 'loadChatflow')
            setSettingsMenu(settingsMenu)
        } else if (chatflow && chatflow.id) {
            if (isCustomAssistant) {
                const menus = customAssistantSettings
                setSettingsMenu(menus.children)
            } else {
                const menus = isAgentCanvas ? agentsettings : settings
                setSettingsMenu(menus.children)
            }
        }
    }, [chatflow, isAgentCanvas, isCustomAssistant])

    useEffect(() => {
        setOpen(isSettingsOpen)
    }, [isSettingsOpen])

    // settings list items
    const items = settingsMenu.map((menu) => {
        if (menu.permission && !hasPermission(menu.permission)) {
            return null
        }
        const Icon = menu.icon
        const itemIcon = menu?.icon ? (
            <Icon stroke={1.5} size='1.3rem' />
        ) : (
            <FiberManualRecordIcon
                sx={{
                    width: customization.isOpen.findIndex((id) => id === menu?.id) > -1 ? 8 : 6,
                    height: customization.isOpen.findIndex((id) => id === menu?.id) > -1 ? 8 : 6
                }}
                fontSize={'inherit'}
            />
        )
        return (
            <ListItemButton
                key={menu.id}
                sx={{
                    borderRadius: `${customization.borderRadius}px`,
                    mb: 0.5,
                    alignItems: 'flex-start',
                    py: 1.25,
                    pl: `24px`
                }}
                onClick={() => {
                    if (menu.id === 'loadChatflow' && inputFile) {
                        inputFile?.current.click()
                    } else {
                        onSettingsItemClick(menu.id)
                    }
                }}
            >
                <ListItemIcon sx={{ my: 'auto', minWidth: !menu?.icon ? 18 : 36 }}>{itemIcon}</ListItemIcon>
                <ListItemText primary={<Typography color='inherit'>{menu.title}</Typography>} />
            </ListItemButton>
        )
    })

    return (
        <>
            <Popper
                placement='bottom-end'
                open={open}
                anchorEl={anchorEl}
                role={undefined}
                transition
                disablePortal
                popperOptions={{
                    modifiers: [
                        {
                            name: 'offset',
                            options: {
                                offset: [170, 20]
                            }
                        }
                    ]
                }}
                sx={{ zIndex: 1000 }}
            >
                {({ TransitionProps }) => (
                    <Transitions in={open} {...TransitionProps}>
                        <Paper>
                            <ClickAwayListener onClickAway={onClose}>
                                <MainCard border={false} elevation={16} content={false} boxShadow shadow={theme.shadows[16]}>
                                    <PerfectScrollbar style={{ height: '100%', maxHeight: 'calc(100vh - 250px)', overflowX: 'hidden' }}>
                                        <Box sx={{ p: 2 }}>
                                            <List>{items}</List>
                                        </Box>
                                    </PerfectScrollbar>
                                    <input
                                        type='file'
                                        hidden
                                        accept='.json'
                                        ref={inputFile}
                                        style={{ display: 'none' }}
                                        onChange={(e) => handleFileUpload(e)}
                                    />
                                </MainCard>
                            </ClickAwayListener>
                        </Paper>
                    </Transitions>
                )}
            </Popper>
        </>
    )
}

Settings.propTypes = {
    chatflow: PropTypes.object,
    isSettingsOpen: PropTypes.bool,
    isCustomAssistant: PropTypes.bool,
    anchorEl: PropTypes.any,
    onSettingsItemClick: PropTypes.func,
    onUploadFile: PropTypes.func,
    onClose: PropTypes.func,
    isAgentCanvas: PropTypes.bool
}

export default Settings
import PropTypes from 'prop-types'
import { forwardRef, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useDispatch, useSelector } from 'react-redux'

// material-ui
import { useTheme } from '@mui/material/styles'
import { Avatar, Chip, ListItemButton, ListItemIcon, ListItemText, Typography, useMediaQuery } from '@mui/material'

// project imports
import { MENU_OPEN, SET_MENU } from '@/store/actions'
import config from '@/config'

// assets
import FiberManualRecordIcon from '@mui/icons-material/FiberManualRecord'

// ==============================|| SIDEBAR MENU LIST ITEMS ||============================== //

const MAX_FILE_SIZE = 5 * 1024 * 1024 // 5MB

const ALLOWED_KEYS = [
    'id', 'name', 'flowData', 'deployed', 'isPublic', 'apikeyid', 'chatbotConfig',
    'apiConfig', 'analytic', 'category', 'createdDate', 'updatedDate', 'type',
    'nodes', 'edges', 'viewport', 'description', 'badge', 'speechToText',
    'followUpPrompts', 'followUpPromptsConfig', 'chatHistory'
]

const containsPromptInjection = (str) => {
    // Check for hidden/invisible characters
    const invisibleCharsPattern = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/
    if (invisibleCharsPattern.test(str)) return true

    // Check for base64-encoded suspicious payloads
    const base64Pattern = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/
    if (base64Pattern.test(str)) {
        try {
            const decoded = atob(str.match(base64Pattern)[0])
            const suspiciousDecoded = /ignore|prompt|system|assistant|instruction|jailbreak|bypass|override/i
            if (suspiciousDecoded.test(decoded)) return true
        } catch (e) {
            // not valid base64, ignore
        }
    }

    // Check for leetspeak patterns targeting prompt injection
    const leetspeakPattern = /1gnor3|pr0mpt|syst3m|4ssistant|1nstruction|j41lbr34k|byp4ss|0verride/i
    if (leetspeakPattern.test(str)) return true

    // Check for shell/binary commands
    const shellCommandPattern = /(\b)(rm\s+-rf|chmod\s+|chown\s+|sudo\s+|curl\s+|wget\s+|bash\s+|sh\s+|exec\s+|eval\s+|system\s*\(|popen\s*\(|subprocess|os\.system|__import__|import\s+os|import\s+sys)(\b)/i
    if (shellCommandPattern.test(str)) return true

    // Check for common prompt injection indicators
    const promptInjectionPattern = /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context|directions?)|forget\s+(everything|all|previous)|you\s+are\s+now|new\s+instructions?|system\s*:\s*|<\s*system\s*>|<\s*\/\s*system\s*>|\[INST\]|\[\/INST\]|###\s*instruction|###\s*system|act\s+as\s+(a\s+)?(different|new|another)|pretend\s+(you\s+are|to\s+be)|roleplay\s+as|jailbreak|DAN\s+mode|developer\s+mode/i
    if (promptInjectionPattern.test(str)) return true

    return false
}

const redactPII = (str) => {
    // Redact SSN (US)
    let result = str.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')

    // Redact email addresses
    result = result.replace(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]')

    // Redact phone numbers (various formats)
    result = result.replace(/(\+?\d[\s\-.]?)?(\(?\d{3}\)?[\s\-.]?)(\d{3}[\s\-.]?\d{4})/g, '[REDACTED_PHONE]')

    // Redact credit card numbers
    result = result.replace(/\b(?:\d[ \-]?){13,16}\b/g, '[REDACTED_CC]')

    // Redact dates of birth (common formats)
    result = result.replace(/\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])[\/\-](\d{2}|\d{4})\b/g, '[REDACTED_DOB]')

    // Redact zip codes (US)
    result = result.replace(/\b\d{5}(?:-\d{4})?\b/g, '[REDACTED_ZIP]')

    return result
}

const containsSingaporePII = (str) => {
    // Singapore NRIC/FIN Number (e.g., S1234567A, T0123456B, F1234567C, G1234567D)
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/i
    if (nricPattern.test(str)) return true

    // Singapore Passport Number (e.g., E1234567A)
    const passportPattern = /\b[A-Z]\d{7}[A-Z]\b/i
    if (passportPattern.test(str)) return true

    // Singapore Phone Number (+65 XXXX XXXX or 8/9 XXXXXXX)
    const sgPhonePattern = /(\+65[\s\-]?)?[89]\d{3}[\s\-]?\d{4}\b/
    if (sgPhonePattern.test(str)) return true

    // Email addresses (personal)
    const emailPattern = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/
    if (emailPattern.test(str)) return true

    // Date of Birth patterns
    const dobPattern = /\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](\d{2}|\d{4})\b/
    if (dobPattern.test(str)) return true

    // Full Name patterns (simple heuristic: two or more capitalized words)
    const fullNamePattern = /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,}\b/
    if (fullNamePattern.test(str)) return true

    return false
}

const sanitizeObject = (obj) => {
    if (Array.isArray(obj)) {
        return obj.map(sanitizeObject)
    }
    if (obj !== null && typeof obj === 'object') {
        const sanitized = {}
        for (const key of Object.keys(obj)) {
            sanitized[key] = sanitizeObject(obj[key])
        }
        return sanitized
    }
    if (typeof obj === 'string') {
        return redactPII(obj)
    }
    return obj
}

const NavItem = ({ item, level, navType, onClick, onUploadFile }) => {
    const theme = useTheme()
    const dispatch = useDispatch()
    const customization = useSelector((state) => state.customization)
    const matchesSM = useMediaQuery(theme.breakpoints.down('lg'))

    const Icon = item.icon
    const itemIcon = item?.icon ? (
        <Icon stroke={1.5} size='1.3rem' />
    ) : (
        <FiberManualRecordIcon
            sx={{
                width: customization.isOpen.findIndex((id) => id === item?.id) > -1 ? 8 : 6,
                height: customization.isOpen.findIndex((id) => id === item?.id) > -1 ? 8 : 6
            }}
            fontSize={level > 0 ? 'inherit' : 'medium'}
        />
    )

    let itemTarget = '_self'
    if (item.target) {
        itemTarget = '_blank'
    }

    let listItemProps = {
        component: forwardRef(function ListItemPropsComponent(props, ref) {
            return <Link ref={ref} {...props} to={`${config.basename}${item.url}`} target={itemTarget} />
        })
    }
    if (item?.external) {
        listItemProps = { component: 'a', href: item.url, target: itemTarget }
    }
    if (item?.id === 'loadChatflow') {
        listItemProps.component = 'label'
    }

    const handleFileUpload = (e) => {
        if (!e.target.files) return

        const file = e.target.files[0]

        // Enforce maximum file size limit
        if (file.size > MAX_FILE_SIZE) {
            alert('File is too large. Maximum allowed size is 5MB.')
            return
        }

        const reader = new FileReader()
        reader.onload = (evt) => {
            if (!evt?.target?.result) {
                return
            }
            const { result } = evt.target

            // Verify the file content is valid JSON
            let parsed
            try {
                parsed = JSON.parse(result)
            } catch (err) {
                alert('Invalid file: the uploaded file does not contain valid JSON.')
                return
            }

            // Sanitize the parsed object (redact PII from string values)
            const sanitized = sanitizeObject(parsed)

            // Re-serialize to strip any unexpected properties or dangerous content
            const sanitizedString = JSON.stringify(sanitized)

            // Check for prompt injection in the sanitized content
            if (containsPromptInjection(sanitizedString)) {
                alert('The uploaded file contains potentially malicious content and cannot be processed.')
                return
            }

            // Check for Singapore PII in the sanitized content
            if (containsSingaporePII(sanitizedString)) {
                alert('The uploaded file contains personal information (PII) that is not allowed. Please remove any personal data before uploading.')
                return
            }

            onUploadFile(sanitizedString)
        }
        reader.readAsText(file)
    }

    const itemHandler = (id) => {
        if (navType === 'SETTINGS' && id !== 'loadChatflow') {
            onClick(id)
        } else {
            dispatch({ type: MENU_OPEN, id })
            if (matchesSM) dispatch({ type: SET_MENU, opened: false })
        }
    }

    // active menu item on page load
    useEffect(() => {
        if (navType === 'MENU') {
            const currentIndex = document.location.pathname
                .toString()
                .split('/')
                .findIndex((id) => id === item.id)
            if (currentIndex > -1) {
                dispatch({ type: MENU_OPEN, id: item.id })
            }
            if (!document.location.pathname.toString().split('/')[1]) {
                itemHandler('chatflows')
            }
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [navType])

    return (
        <ListItemButton
            {...listItemProps}
            disabled={item.disabled}
            sx={{
                borderRadius: `${customization.borderRadius}px`,
                alignItems: 'flex-start',
                backgroundColor: level > 1 ? 'transparent !important' : 'inherit',
                py: level > 1 ? 1 : 1.25,
                pl: `${level * 24}px`
            }}
            selected={customization.isOpen.findIndex((id) => id === item.id) > -1}
            onClick={() => itemHandler(item.id)}
        >
            {item.id === 'loadChatflow' && <input type='file' hidden accept='.json' onChange={(e) => handleFileUpload(e)} />}
            <ListItemIcon sx={{ my: 'auto', minWidth: !item?.icon ? 18 : 36 }}>{itemIcon}</ListItemIcon>
            <ListItemText
                primary={
                    <Typography
                        variant={customization.isOpen.findIndex((id) => id === item.id) > -1 ? 'h5' : 'body1'}
                        color='inherit'
                        sx={{ my: 0.5 }}
                    >
                        {item.title}
                    </Typography>
                }
                secondary={
                    item.caption && (
                        <Typography variant='caption' sx={{ ...theme.typography.subMenuCaption, mt: -0.6 }} display='block' gutterBottom>
                            {item.caption}
                        </Typography>
                    )
                }
                sx={{ my: 'auto' }}
            />
            {item.chip && (
                <Chip
                    color={item.chip.color}
                    variant={item.chip.variant}
                    size={item.chip.size}
                    label={item.chip.label}
                    avatar={item.chip.avatar && <Avatar>{item.chip.avatar}</Avatar>}
                />
            )}
            {item.isBeta && (
                <Chip
                    sx={{
                        my: 'auto',
                        width: 'max-content',
                        fontWeight: 700,
                        fontSize: '0.65rem',
                        background: theme.palette.teal.main,
                        color: 'white'
                    }}
                    label={'BETA'}
                />
            )}
        </ListItemButton>
    )
}

NavItem.propTypes = {
    item: PropTypes.object,
    level: PropTypes.number,
    navType: PropTypes.string,
    onClick: PropTypes.func,
    onUploadFile: PropTypes.func
}

export default NavItem
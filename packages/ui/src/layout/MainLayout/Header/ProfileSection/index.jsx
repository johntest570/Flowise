import PropTypes from 'prop-types'
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useDispatch, useSelector } from 'react-redux'
import { useNavigate } from 'react-router-dom'

import { closeSnackbar as closeSnackbarAction, enqueueSnackbar as enqueueSnackbarAction, REMOVE_DIRTY } from '@/store/actions'
import { exportData, stringify } from '@/utils/exportImport'
import useNotifier from '@/utils/useNotifier'

// material-ui
import {
    Avatar,
    Box,
    Button,
    ButtonBase,
    Checkbox,
    ClickAwayListener,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Divider,
    FormControlLabel,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Paper,
    Popper,
    Stack,
    Typography
} from '@mui/material'
import { useTheme } from '@mui/material/styles'

// third-party
import PerfectScrollbar from 'react-perfect-scrollbar'

// project imports
import { PermissionListItemButton } from '@/ui-component/button/RBACButtons'
import MainCard from '@/ui-component/cards/MainCard'
import AboutDialog from '@/ui-component/dialog/AboutDialog'
import Transitions from '@/ui-component/extended/Transitions'

// assets
import ExportingGIF from '@/assets/images/Exporting.gif'
import { IconFileExport, IconFileUpload, IconInfoCircle, IconLogout, IconSettings, IconUserEdit, IconX } from '@tabler/icons-react'
import './index.css'

// API
import exportImportApi from '@/api/exportimport'

// Hooks
import useApi from '@/hooks/useApi'
import { getErrorMessage } from '@/utils/errorHandler'

// ==============================|| PII Scanning Utilities ||============================== //

/**
 * Scans text for common PII patterns (global) and Singapore-specific PII.
 * Returns an array of detected PII type labels.
 */
const PII_PATTERNS = {
    email: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    phone: /(?:\+?\d[\d\s\-().]{7,}\d)/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    creditCard: /\b(?:\d[ \-]?){13,16}\b/g,
    // Singapore NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    singaporeNRIC: /\b[STFG]\d{7}[A-Z]\b/gi,
    // Singapore phone numbers: +65 followed by 8 digits
    singaporePhone: /(?:\+65[\s\-]?)?\b[689]\d{7}\b/g,
    // SingPass identifiers (NRIC-like patterns used in SingPass context)
    singpass: /\bSingPass\s*[A-Z0-9]+/gi
}

/**
 * Redacts PII from a string by replacing matched patterns with redacted placeholders.
 */
const redactPII = (text) => {
    let redacted = text
    redacted = redacted.replace(PII_PATTERNS.singaporeNRIC, '[REDACTED_NRIC/FIN]')
    redacted = redacted.replace(PII_PATTERNS.singpass, '[REDACTED_SINGPASS]')
    redacted = redacted.replace(PII_PATTERNS.email, '[REDACTED_EMAIL]')
    redacted = redacted.replace(PII_PATTERNS.ssn, '[REDACTED_SSN]')
    redacted = redacted.replace(PII_PATTERNS.creditCard, '[REDACTED_CARD]')
    redacted = redacted.replace(PII_PATTERNS.singaporePhone, '[REDACTED_PHONE]')
    redacted = redacted.replace(PII_PATTERNS.phone, '[REDACTED_PHONE]')
    return redacted
}

/**
 * Detects PII in a string and returns a list of detected PII type labels.
 */
const detectPII = (text) => {
    const detected = []
    if (PII_PATTERNS.singaporeNRIC.test(text)) detected.push('Singapore NRIC/FIN')
    PII_PATTERNS.singaporeNRIC.lastIndex = 0
    if (PII_PATTERNS.singpass.test(text)) detected.push('SingPass identifier')
    PII_PATTERNS.singpass.lastIndex = 0
    if (PII_PATTERNS.email.test(text)) detected.push('email address')
    PII_PATTERNS.email.lastIndex = 0
    if (PII_PATTERNS.ssn.test(text)) detected.push('SSN')
    PII_PATTERNS.ssn.lastIndex = 0
    if (PII_PATTERNS.creditCard.test(text)) detected.push('credit card number')
    PII_PATTERNS.creditCard.lastIndex = 0
    if (PII_PATTERNS.singaporePhone.test(text)) detected.push('Singapore phone number')
    PII_PATTERNS.singaporePhone.lastIndex = 0
    if (PII_PATTERNS.phone.test(text)) detected.push('phone number')
    PII_PATTERNS.phone.lastIndex = 0
    return detected
}

const dataToExport = [
    'Agentflows',
    'Agentflows V2',
    'Assistants Custom',
    'Assistants OpenAI',
    'Assistants Azure',
    'Chatflows',
    'Chat Messages',
    'Chat Feedbacks',
    'Custom Templates',
    'Document Stores',
    'Executions',
    'Tools',
    'Variables'
]

const ExportDialog = ({ show, onCancel, onExport }) => {
    const portalElement = document.getElementById('portal')

    const [selectedData, setSelectedData] = useState(dataToExport)
    const [isExporting, setIsExporting] = useState(false)

    useEffect(() => {
        if (show) setIsExporting(false)

        return () => {
            setIsExporting(false)
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [show])

    const component = show ? (
        <Dialog
            onClose={!isExporting ? onCancel : undefined}
            open={show}
            fullWidth
            maxWidth='sm'
            aria-labelledby='export-dialog-title'
            aria-describedby='export-dialog-description'
        >
            <DialogTitle sx={{ fontSize: '1rem' }} id='export-dialog-title'>
                {!isExporting ? 'Select Data to Export' : 'Exporting..'}
            </DialogTitle>
            <DialogContent>
                {!isExporting && (
                    <Stack
                        direction='row'
                        sx={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(2, 1fr)',
                            gap: 1
                        }}
                    >
                        {dataToExport.map((data, index) => (
                            <FormControlLabel
                                key={index}
                                size='small'
                                control={
                                    <Checkbox
                                        color='success'
                                        checked={selectedData.includes(data)}
                                        onChange={(event) => {
                                            setSelectedData(
                                                event.target.checked
                                                    ? [...selectedData, data]
                                                    : selectedData.filter((item) => item !== data)
                                            )
                                        }}
                                    />
                                }
                                label={data}
                            />
                        ))}
                    </Stack>
                )}
                {isExporting && (
                    <Box sx={{ height: 'auto', display: 'flex', justifyContent: 'center', mb: 3 }}>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                            <img
                                style={{
                                    objectFit: 'cover',
                                    height: 'auto',
                                    width: 'auto'
                                }}
                                src={ExportingGIF}
                                alt='ExportingGIF'
                            />
                            <span>Exporting data might takes a while</span>
                        </div>
                    </Box>
                )}
            </DialogContent>
            {!isExporting && (
                <DialogActions>
                    <Button onClick={onCancel}>Cancel</Button>
                    <Button
                        disabled={selectedData.length === 0}
                        variant='contained'
                        onClick={() => {
                            setIsExporting(true)
                            onExport(selectedData)
                        }}
                    >
                        Export
                    </Button>
                </DialogActions>
            )}
        </Dialog>
    ) : null

    return createPortal(component, portalElement)
}

ExportDialog.propTypes = {
    show: PropTypes.bool,
    onCancel: PropTypes.func,
    onExport: PropTypes.func
}

const ImportDialog = ({ show, onBeforeImport }) => {
    const portalElement = document.getElementById('portal')

    const component = show ? (
        <Dialog open={show} fullWidth maxWidth='sm' aria-labelledby='import-dialog-title' aria-describedby='import-dialog-description'>
            <DialogTitle sx={{ fontSize: '1rem' }} id='import-dialog-title'>
                Importing...
            </DialogTitle>
            <DialogContent>
                <Box sx={{ height: 'auto', display: 'flex', justifyContent: 'center', mb: 3 }}>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                        <img
                            style={{
                                objectFit: 'cover',
                                height: 'auto',
                                width: 'auto'
                            }}
                            src={ExportingGIF}
                            alt='ImportingGIF'
                        />
                        <span>Importing data might takes a while</span>
                    </div>
                </Box>
            </DialogContent>
        </Dialog>
    ) : null

    return createPortal(component, portalElement)
}

ImportDialog.propTypes = {
    show: PropTypes.bool,
    onBeforeImport: PropTypes.func
}

// ==============================|| PROFILE MENU ||============================== //

const ProfileSection = ({ handleLogout }) => {
    const theme = useTheme()

    const customization = useSelector((state) => state.customization)

    const [open, setOpen] = useState(false)
    const [aboutDialogOpen, setAboutDialogOpen] = useState(false)

    const [exportDialogOpen, setExportDialogOpen] = useState(false)
    const [importDialogOpen, setImportDialogOpen] = useState(false)

    const anchorRef = useRef(null)
    const inputRef = useRef()

    const navigate = useNavigate()
    const currentUser = useSelector((state) => state.auth.user)
    const isAuthenticated = useSelector((state) => state.auth.isAuthenticated)

    const importAllApi = useApi(exportImportApi.importData)
    const exportAllApi = useApi(exportImportApi.exportData)
    const prevOpen = useRef(open)

    // ==============================|| Snackbar ||============================== //

    useNotifier()
    const dispatch = useDispatch()
    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const handleClose = (event) => {
        if (anchorRef.current && anchorRef.current.contains(event.target)) {
            return
        }
        setOpen(false)
    }

    const handleToggle = () => {
        setOpen((prevOpen) => !prevOpen)
    }

    const errorFailed = (message) => {
        enqueueSnackbar({
            message: message,
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

    /**
     * onBeforeImport callback: scans file content for Singapore-specific and common PII.
     * If Singapore PII is detected, blocks the import and alerts the user.
     * Otherwise, redacts common PII from the content before returning the parsed body.
     * Returns the (possibly redacted) parsed JSON body, or null if import should be blocked.
     */
    const handleBeforeImport = (rawText) => {
        // Detect Singapore-specific PII — block import if found
        const singaporePIIPatterns = [PII_PATTERNS.singaporeNRIC, PII_PATTERNS.singpass, PII_PATTERNS.singaporePhone]
        const singaporePIILabels = []

        if (PII_PATTERNS.singaporeNRIC.test(rawText)) singaporePIILabels.push('Singapore NRIC/FIN')
        PII_PATTERNS.singaporeNRIC.lastIndex = 0

        if (PII_PATTERNS.singpass.test(rawText)) singaporePIILabels.push('SingPass identifier')
        PII_PATTERNS.singpass.lastIndex = 0

        if (PII_PATTERNS.singaporePhone.test(rawText)) singaporePIILabels.push('Singapore phone number')
        PII_PATTERNS.singaporePhone.lastIndex = 0

        if (singaporePIILabels.length > 0) {
            alert(
                `Import blocked: The uploaded file contains Singapore PII (${singaporePIILabels.join(', ')}). ` +
                    `Please remove all personal identifiable information before importing.`
            )
            return null
        }

        // Redact common PII from the content before processing
        const redactedText = redactPII(rawText)

        try {
            return JSON.parse(redactedText)
        } catch (e) {
            return JSON.parse(rawText)
        }
    }

    const fileChange = (e) => {
        if (!e.target.files) return

        const file = e.target.files[0]

        const reader = new FileReader()
        reader.onload = (evt) => {
            if (!evt?.target?.result) {
                return
            }
            const rawText = evt.target.result

            // Run PII scanning and redaction before import
            const body = handleBeforeImport(rawText)
            if (body === null) {
                // Import blocked due to PII detection
                if (inputRef.current) inputRef.current.value = ''
                return
            }

            setImportDialogOpen(true)
            importAllApi.request(body)
        }
        reader.readAsText(file)
    }

    const importAllSuccess = () => {
        setImportDialogOpen(false)
        dispatch({ type: REMOVE_DIRTY })
        enqueueSnackbar({
            message: `Import All successful`,
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

    const importAll = () => {
        inputRef.current.click()
    }

    const onExport = (data) => {
        const body = {}
        if (data.includes('Agentflows')) body.agentflow = true
        if (data.includes('Agentflows V2')) body.agentflowv2 = true
        if (data.includes('Assistants Custom')) body.assistantCustom = true
        if (data.includes('Assistants OpenAI')) body.assistantOpenAI = true
        if (data.includes('Assistants Azure')) body.assistantAzure = true
        if (data.includes('Chatflows')) body.chatflow = true
        if (data.includes('Chat Messages')) body.chat_message = true
        if (data.includes('Chat Feedbacks')) body.chat_feedback = true
        if (data.includes('Custom Templates')) body.custom_template = true
        if (data.includes('Document Stores')) body.document_store = true
        if (data.includes('Executions')) body.execution = true
        if (data.includes('Tools')) body.tool = true
        if (data.includes('Variables')) body.variable = true

        exportAllApi.request(body)
    }

    useEffect(() => {
        if (importAllApi.data) {
            importAllSuccess()
            navigate(0)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [importAllApi.data])

    useEffect(() => {
        if (importAllApi.error) {
            setImportDialogOpen(false)
            let errMsg = 'Invalid Imported File'
            let error = importAllApi.error
            if (error?.response?.data) {
                errMsg = typeof error.response.data === 'object' ? error.response.data.message : error.response.data
            }
            errorFailed(`Failed to import: ${errMsg}`)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [importAllApi.error])

    useEffect(() => {
        if (exportAllApi.data) {
            setExportDialogOpen(false)
            try {
                const dataStr = stringify(exportData(exportAllApi.data))
                //const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr)
                const blob = new Blob([dataStr], { type: 'application/json' })
                const dataUri = URL.createObjectURL(blob)

                const linkElement = document.createElement('a')
                linkElement.setAttribute('href', dataUri)
                linkElement.setAttribute('download', exportAllApi.data.FileDefaultName)
                linkElement.click()
            } catch (error) {
                errorFailed(`Failed to export all: ${getErrorMessage(error)}`)
            }
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [exportAllApi.data])

    useEffect(() => {
        if (exportAllApi.error) {
            setExportDialogOpen(false)
            let errMsg = 'Internal Server Error'
            let error = exportAllApi.error
            if (error?.response?.data) {
                errMsg = typeof error.response.data === 'object' ? error.response.data.message : error.response.data
            }
            errorFailed(`Failed to export: ${errMsg}`)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [exportAllApi.error])

    useEffect(() => {
        if (prevOpen.current === true && open === false) {
            anchorRef.current.focus()
        }
        prevOpen.current = open
    }, [open])

    return (
        <>
            <ButtonBase ref={anchorRef} sx={{ borderRadius: '12px', overflow: 'hidden' }}>
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
                    onClick={handleToggle}
                    color='inherit'
                >
                    <IconSettings stroke={1.5} size='1.3rem' />
                </Avatar>
            </ButtonBase>
            <Popper
                placement='bottom-end'
                open={open}
                anchorEl={anchorRef.current}
                role={undefined}
                transition
                disablePortal
                popperOptions={{
                    modifiers: [
                        {
                            name: 'offset',
                            options: {
                                offset: [0, 14]
                            }
                        }
                    ]
                }}
            >
                {({ TransitionProps }) => (
                    <Transitions in={open} {...TransitionProps}>
                        <Paper>
                            <ClickAwayListener onClickAway={handleClose}>
                                <MainCard border={false} elevation={16} content={false} boxShadow shadow={theme.shadows[16]}>
                                    {isAuthenticated && currentUser ? (
                                        <Box sx={{ p: 2 }}>
                                            <Typography component='span' variant='h4'>
                                                {currentUser.name}
                                            </Typography>
                                        </Box>
                                    ) : (
                                        <Box sx={{ p: 2 }}>
                                            <Typography component='span' variant='h4'>
                                                User
                                            </Typography>
                                        </Box>
                                    )}
                                    <PerfectScrollbar style={{ height: '100%', maxHeight: 'calc(100vh - 250px)', overflowX: 'hidden' }}>
                                        <Box sx={{ p: 2 }}>
                                            <Divider />
                                            <List
                                                component='nav'
                                                sx={{
                                                    width: '100%',
                                                    maxWidth: 250,
                                                    minWidth: 200,
                                                    backgroundColor: theme.palette.background.paper,
                                                    borderRadius: '10px',
                                                    [theme.breakpoints.down('md')]: {
                                                        minWidth: '100%'
                                                    },
                                                    '& .MuiListItemButton-root': {
                                                        mt: 0.5
                                                    }
                                                }}
                                            >
                                                <PermissionListItemButton
                                                    permissionId='workspace:export'
                                                    sx={{ borderRadius: `${customization.borderRadius}px` }}
                                                    onClick={() => {
                                                        setExportDialogOpen(true)
                                                    }}
                                                >
                                                    <ListItemIcon>
                                                        <IconFileExport stroke={1.5} size='1.3rem' />
                                                    </ListItemIcon>
                                                    <ListItemText primary={<Typography variant='body2'>Export</Typography>} />
                                                </PermissionListItemButton>
                                                <PermissionListItemButton
                                                    permissionId='workspace:import'
                                                    sx={{ borderRadius: `${customization.borderRadius}px` }}
                                                    onClick={() => {
                                                        importAll()
                                                    }}
                                                >
                                                    <ListItemIcon>
                                                        <IconFileUpload stroke={1.5} size='1.3rem' />
                                                    </ListItemIcon>
                                                    <ListItemText primary={<Typography variant='body2'>Import</Typography>} />
                                                </PermissionListItemButton>
                                                <input ref={inputRef} type='file' hidden onChange={fileChange} accept='.json' />
                                                <ListItemButton
                                                    sx={{ borderRadius: `${customization.borderRadius}px` }}
                                                    onClick={() => {
                                                        setOpen(false)
                                                        setAboutDialogOpen(true)
                                                    }}
                                                >
                                                    <ListItemIcon>
                                                        <IconInfoCircle stroke={1.5} size='1.3rem' />
                                                    </ListItemIcon>
                                                    <ListItemText primary={<Typography variant='body2'>Version</Typography>} />
                                                </ListItemButton>
                                                {isAuthenticated && !currentUser.isSSO && (
                                                    <ListItemButton
                                                        sx={{ borderRadius: `${customization.borderRadius}px` }}
                                                        onClick={() => {
                                                            setOpen(false)
                                                            navigate('/account')
                                                        }}
                                                    >
                                                        <ListItemIcon>
                                                            <IconUserEdit stroke={1.5} size='1.3rem' />
                                                        </ListItemIcon>
                                                        <ListItemText primary={<Typography variant='body2'>Account Settings</Typography>} />
                                                    </ListItemButton>
                                                )}
                                                <ListItemButton
                                                    sx={{ borderRadius: `${customization.borderRadius}px` }}
                                                    onClick={handleLogout}
                                                >
                                                    <ListItemIcon>
                                                        <IconLogout stroke={1.5} size='1.3rem' />
                                                    </ListItemIcon>
                                                    <ListItemText primary={<Typography variant='body2'>Logout</Typography>} />
                                                </ListItemButton>
                                            </List>
                                        </Box>
                                    </PerfectScrollbar>
                                </MainCard>
                            </ClickAwayListener>
                        </Paper>
                    </Transitions>
                )}
            </Popper>
            <AboutDialog show={aboutDialogOpen} onCancel={() => setAboutDialogOpen(false)} />
            <ExportDialog show={exportDialogOpen} onCancel={() => setExportDialogOpen(false)} onExport={(data) => onExport(data)} />
            <ImportDialog show={importDialogOpen} onBeforeImport={handleBeforeImport} />
        </>
    )
}

ProfileSection.propTypes = {
    handleLogout: PropTypes.func
}

export default ProfileSection
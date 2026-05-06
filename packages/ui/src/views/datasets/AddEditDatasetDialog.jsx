import { createPortal } from 'react-dom'
import PropTypes from 'prop-types'
import { useState, useEffect } from 'react'
import { useDispatch } from 'react-redux'
import { enqueueSnackbar as enqueueSnackbarAction, closeSnackbar as closeSnackbarAction } from '@/store/actions'

// Material
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Box, Typography, OutlinedInput } from '@mui/material'

// Project imports
import { StyledButton } from '@/ui-component/button/StyledButton'
import ConfirmDialog from '@/ui-component/dialog/ConfirmDialog'
import { File } from '@/ui-component/file/File'
import { SwitchInput } from '@/ui-component/switch/Switch'
import { TooltipWithParser } from '@/ui-component/tooltip/TooltipWithParser'

// Icons
import { IconX, IconDatabase } from '@tabler/icons-react'

// API
import datasetApi from '@/api/dataset'

// Hooks

// utils
import useNotifier from '@/utils/useNotifier'

// const
import { HIDE_CANVAS_DIALOG, SHOW_CANVAS_DIALOG } from '@/store/actions'
const CSVFORMAT = `Only the first 2 columns will be considered:
----------------------------
| Input      | Output      |
----------------------------
| test input | test output |
----------------------------
`

// ==============================|| CSV Security & PII Utilities ||============================== //

const containsMaliciousContent = (content) => {
    // Check for invisible/hidden characters
    const invisibleCharsPattern = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/
    if (invisibleCharsPattern.test(content)) return true

    // Check for base64-encoded content that might be prompts
    const base64Pattern = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/
    if (base64Pattern.test(content)) {
        try {
            const decoded = atob(content.match(base64Pattern)[0])
            const suspiciousDecoded = /ignore|prompt|system|instruction|jailbreak|override|forget|disregard/i
            if (suspiciousDecoded.test(decoded)) return true
        } catch (e) {
            // not valid base64, ignore
        }
    }

    // Check for suspicious instruction patterns / prompt injection
    const promptInjectionPatterns = [
        /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
        /forget\s+(everything|all|previous|prior|above)/i,
        /disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
        /you\s+are\s+now\s+(a|an)\s+/i,
        /act\s+as\s+(a|an)\s+/i,
        /pretend\s+(you\s+are|to\s+be)\s+/i,
        /override\s+(system|previous|prior)\s+(prompt|instruction|context)/i,
        /system\s*:\s*(you|your|ignore|forget)/i,
        /\[system\]/i,
        /\[user\]/i,
        /\[assistant\]/i,
        /<\s*system\s*>/i,
        /<\s*prompt\s*>/i,
        /###\s*(instruction|system|prompt)/i,
        /new\s+instructions?\s*:/i,
        /jailbreak/i,
        /DAN\s+mode/i,
        /developer\s+mode/i
    ]
    for (const pattern of promptInjectionPatterns) {
        if (pattern.test(content)) return true
    }

    // Check for leetspeak suspicious patterns
    const leetspeakPattern = /[1!][gG9][nN][0oO][rR][3eE]/  // "ignor3" style
    if (leetspeakPattern.test(content)) return true

    // Check for binary/shell content
    const binaryShellPatterns = [
        /\x00/,
        /\\x[0-9a-fA-F]{2}/,
        /\/bin\/(sh|bash|zsh|dash)/,
        /exec\s*\(/,
        /eval\s*\(/,
        /system\s*\(/,
        /subprocess/,
        /os\.system/,
        /shell_exec/,
        /passthru/,
        /`[^`]+`/
    ]
    for (const pattern of binaryShellPatterns) {
        if (pattern.test(content)) return true
    }

    return false
}

const containsSingaporePII = (content) => {
    // NRIC/FIN numbers (e.g., S1234567A, T0123456B, F1234567C, G1234567D)
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/i
    if (nricPattern.test(content)) return { found: true, type: 'NRIC/FIN number' }

    // SingPass identifiers (typically NRIC-based, but also check for SingPass keyword)
    const singpassPattern = /singpass/i
    if (singpassPattern.test(content)) return { found: true, type: 'SingPass identifier' }

    // CPF account numbers (typically 9 digits)
    const cpfPattern = /\bCPF[\s\-]?\d{9}\b/i
    if (cpfPattern.test(content)) return { found: true, type: 'CPF account number' }

    // Singapore phone numbers (+65 XXXX XXXX or 8/9 XXXXXXX)
    const sgPhonePattern = /(\+65[\s\-]?[689]\d{3}[\s\-]?\d{4}|\b[689]\d{7}\b)/
    if (sgPhonePattern.test(content)) return { found: true, type: 'Singapore phone number' }

    // Singapore postal codes (6 digits, often preceded by "Singapore" or "S(")
    const sgPostalPattern = /\b(Singapore\s+\d{6}|S\(\d{6}\)|\bPostal\s+Code[\s:]+\d{6})\b/i
    if (sgPostalPattern.test(content)) return { found: true, type: 'Singapore postal code' }

    return { found: false }
}

const redactPII = (content) => {
    let redacted = content

    // Redact email addresses
    redacted = redacted.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')

    // Redact phone numbers (general patterns)
    redacted = redacted.replace(/(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})/g, '[REDACTED_PHONE]')

    // Redact SSNs (XXX-XX-XXXX)
    redacted = redacted.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, '[REDACTED_SSN]')

    // Redact credit card numbers (16 digits, with or without spaces/dashes)
    redacted = redacted.replace(/\b(?:\d{4}[\s\-]?){3}\d{4}\b/g, '[REDACTED_CC]')

    // Redact Singapore NRIC/FIN
    redacted = redacted.replace(/\b[STFG]\d{7}[A-Z]\b/gi, '[REDACTED_NRIC]')

    // Redact Singapore phone numbers
    redacted = redacted.replace(/\+65[\s\-]?[689]\d{3}[\s\-]?\d{4}/g, '[REDACTED_SG_PHONE]')
    redacted = redacted.replace(/\b[689]\d{7}\b/g, '[REDACTED_SG_PHONE]')

    // Redact CPF account numbers
    redacted = redacted.replace(/\bCPF[\s\-]?\d{9}\b/gi, '[REDACTED_CPF]')

    return redacted
}

const readFileAsText = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = (e) => resolve(e.target.result)
        reader.onerror = (e) => reject(e)
        reader.readAsText(file)
    })
}

const AddEditDatasetDialog = ({ show, dialogProps, onCancel, onConfirm }) => {
    const portalElement = document.getElementById('portal')

    const dispatch = useDispatch()

    // ==============================|| Snackbar ||============================== //

    useNotifier()

    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const [datasetName, setDatasetName] = useState('')
    const [datasetDescription, setDatasetDescription] = useState('')
    const [dialogType, setDialogType] = useState('ADD')
    const [dataset, setDataset] = useState({})
    const [firstRowHeaders, setFirstRowHeaders] = useState(false)
    const [selectedFile, setSelectedFile] = useState()
    const [fileBlocked, setFileBlocked] = useState(false)

    useEffect(() => {
        if (dialogProps.type === 'EDIT' && dialogProps.data) {
            setDatasetName(dialogProps.data.name)
            setDatasetDescription(dialogProps.data.description)
            setDialogType('EDIT')
            setDataset(dialogProps.data)
        } else if (dialogProps.type === 'ADD') {
            setDatasetName('')
            setDatasetDescription('')
            setDialogType('ADD')
            setDataset({})
        }

        return () => {
            setDatasetName('')
            setDatasetDescription('')
            setDialogType('ADD')
            setDataset({})
        }
    }, [dialogProps])

    useEffect(() => {
        if (show) dispatch({ type: SHOW_CANVAS_DIALOG })
        else dispatch({ type: HIDE_CANVAS_DIALOG })
        return () => dispatch({ type: HIDE_CANVAS_DIALOG })
    }, [show, dispatch])

    const handleFileChange = async (newValue) => {
        setFileBlocked(false)

        if (!newValue) {
            setSelectedFile(newValue)
            return
        }

        // newValue may be a File object or a base64/data URL string depending on the File component
        // We need to handle both cases
        let fileObj = newValue
        let fileContent = null

        try {
            if (fileObj instanceof Blob || fileObj instanceof File) {
                fileContent = await readFileAsText(fileObj)
            } else if (typeof fileObj === 'string' && fileObj.startsWith('data:')) {
                // base64 data URL
                const base64Content = fileObj.split(',')[1]
                if (base64Content) {
                    fileContent = atob(base64Content)
                }
            } else if (typeof fileObj === 'string') {
                fileContent = fileObj
            }
        } catch (e) {
            // Could not read file content, proceed with caution
            fileContent = null
        }

        if (fileContent !== null) {
            // Check for malicious content
            if (containsMaliciousContent(fileContent)) {
                setFileBlocked(true)
                enqueueSnackbar({
                    message: 'The uploaded CSV file contains potentially malicious content and has been blocked.',
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

            // Check for Singapore PII
            const sgPiiResult = containsSingaporePII(fileContent)
            if (sgPiiResult.found) {
                setFileBlocked(true)
                enqueueSnackbar({
                    message: `The uploaded CSV file contains Singapore PII (${sgPiiResult.type}). Upload has been blocked.`,
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
        }

        setSelectedFile(newValue)
    }

    const addNewDataset = async () => {
        try {
            const obj = {
                name: datasetName,
                description: datasetDescription
            }
            if (selectedFile) {
                if (fileBlocked) {
                    enqueueSnackbar({
                        message: 'Cannot submit: the selected file has been blocked due to security or PII policy violations.',
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

                obj.firstRowHeaders = firstRowHeaders

                // Read file content, redact PII, and reconstruct file
                let processedFile = selectedFile
                try {
                    let fileContent = null
                    let fileName = 'upload.csv'
                    let fileType = 'text/csv'

                    if (selectedFile instanceof File) {
                        fileContent = await readFileAsText(selectedFile)
                        fileName = selectedFile.name
                        fileType = selectedFile.type || 'text/csv'
                    } else if (typeof selectedFile === 'string' && selectedFile.startsWith('data:')) {
                        const base64Content = selectedFile.split(',')[1]
                        if (base64Content) {
                            fileContent = atob(base64Content)
                        }
                    } else if (typeof selectedFile === 'string') {
                        fileContent = selectedFile
                    }

                    if (fileContent !== null) {
                        const redactedContent = redactPII(fileContent)
                        if (selectedFile instanceof File) {
                            processedFile = new File([redactedContent], fileName, { type: fileType })
                        } else if (typeof selectedFile === 'string' && selectedFile.startsWith('data:')) {
                            const encoder = new TextEncoder()
                            const bytes = encoder.encode(redactedContent)
                            let binary = ''
                            bytes.forEach((b) => (binary += String.fromCharCode(b)))
                            processedFile = `data:${fileType};base64,` + btoa(binary)
                        } else {
                            processedFile = redactedContent
                        }
                    }
                } catch (e) {
                    // If redaction fails, use original file
                    processedFile = selectedFile
                }

                obj.csvFile = processedFile
            }
            const createResp = await datasetApi.createDataset(obj)
            if (createResp.data) {
                enqueueSnackbar({
                    message: 'New Dataset added',
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
        } catch (error) {
            enqueueSnackbar({
                message: `Failed to add new Dataset: ${
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

    const saveDataset = async () => {
        try {
            const saveObj = {
                name: datasetName,
                description: datasetDescription
            }

            const saveResp = await datasetApi.updateDataset(dataset.id, saveObj)
            if (saveResp.data) {
                enqueueSnackbar({
                    message: 'Dataset saved',
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
        } catch (error) {
            enqueueSnackbar({
                message: `Failed to save Dataset: ${
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

    const component = show ? (
        <Dialog
            fullWidth
            maxWidth='sm'
            open={show}
            onClose={onCancel}
            aria-labelledby='alert-dialog-title'
            aria-describedby='alert-dialog-description'
        >
            <DialogTitle sx={{ fontSize: '1rem' }} id='alert-dialog-title'>
                <div style={{ display: 'flex', flexDirection: 'row', alignItems: 'center' }}>
                    <IconDatabase style={{ marginRight: '10px' }} />
                    {dialogProps.type === 'ADD' ? 'Add Dataset' : 'Edit Dataset'}
                </div>
            </DialogTitle>
            <DialogContent>
                <Box sx={{ p: 2 }}>
                    <div style={{ display: 'flex', flexDirection: 'row' }}>
                        <Typography>
                            Name<span style={{ color: 'red' }}>&nbsp;*</span>
                        </Typography>
                        <div style={{ flexGrow: 1 }}></div>
                    </div>
                    <OutlinedInput
                        size='small'
                        sx={{ mt: 1 }}
                        type='string'
                        fullWidth
                        key='datasetName'
                        onChange={(e) => setDatasetName(e.target.value)}
                        value={datasetName ?? ''}
                    />
                </Box>
                <Box sx={{ p: 2 }}>
                    <div style={{ display: 'flex', flexDirection: 'row' }}>
                        <Typography>Description</Typography>
                        <div style={{ flexGrow: 1 }}></div>
                    </div>
                    <OutlinedInput
                        size='small'
                        sx={{ mt: 1 }}
                        type='string'
                        fullWidth
                        multiline={true}
                        rows={4}
                        key='datasetDescription'
                        onChange={(e) => setDatasetDescription(e.target.value)}
                        value={datasetDescription ?? ''}
                    />
                </Box>
                {dialogType === 'ADD' && (
                    <Box sx={{ p: 2 }}>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                            <Typography>
                                Upload CSV
                                <TooltipWithParser style={{ mb: 1, mt: 2 }} title={`<pre>${CSVFORMAT}</pre>`} />
                            </Typography>
                            <div style={{ flexGrow: 1 }}></div>
                        </div>
                        <File
                            disabled={false}
                            fileType='.csv'
                            onChange={handleFileChange}
                            value={selectedFile ?? 'Choose a file to upload'}
                        />
                        <SwitchInput
                            value={firstRowHeaders}
                            onChange={setFirstRowHeaders}
                            label={'Treat First Row as headers in the upload file?'}
                        />
                    </Box>
                )}
            </DialogContent>
            <DialogActions>
                <Button onClick={() => onCancel()}>{dialogProps.cancelButtonName}</Button>
                <StyledButton
                    disabled={!datasetName || fileBlocked}
                    variant='contained'
                    onClick={() => (dialogType === 'ADD' ? addNewDataset() : saveDataset())}
                >
                    {dialogProps.confirmButtonName}
                </StyledButton>
            </DialogActions>
            <ConfirmDialog />
        </Dialog>
    ) : null

    return createPortal(component, portalElement)
}

AddEditDatasetDialog.propTypes = {
    show: PropTypes.bool,
    dialogProps: PropTypes.object,
    onCancel: PropTypes.func,
    onConfirm: PropTypes.func
}

export default AddEditDatasetDialog
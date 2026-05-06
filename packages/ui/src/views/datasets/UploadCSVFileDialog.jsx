import { createPortal } from 'react-dom'
import PropTypes from 'prop-types'
import { useState, useEffect } from 'react'
import { useDispatch } from 'react-redux'
import { enqueueSnackbar as enqueueSnackbarAction, closeSnackbar as closeSnackbarAction } from '@/store/actions'

// Material
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Box, Typography } from '@mui/material'

// Project imports
import { StyledButton } from '@/ui-component/button/StyledButton'
import ConfirmDialog from '@/ui-component/dialog/ConfirmDialog'
import { SwitchInput } from '@/ui-component/switch/Switch'
import { File } from '@/ui-component/file/File'
import { TooltipWithParser } from '@/ui-component/tooltip/TooltipWithParser'

// Icons
import { IconX, IconDatabase } from '@tabler/icons-react'

// API
import datasetApi from '@/api/dataset'

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

// ==============================|| Security Utilities ||============================== //

const inspectCSVForMaliciousContent = (text) => {
    const suspiciousPatterns = [
        // Hidden/invisible prompt injection characters
        /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/,
        // Base64-encoded content (long base64 strings)
        /(?:[A-Za-z0-9+/]{40,}={0,2})/,
        // Leetspeak prompt injection attempts
        /(?:1gnor3|1gnore|pr0mpt|syst3m|[il1][gq][n][o0][r][e3])\s/i,
        // Shell/binary command payloads
        /(?:\/bin\/|\/etc\/passwd|\/etc\/shadow|cmd\.exe|powershell|bash\s+-[ci]|sh\s+-[ci]|\beval\s*\(|\bexec\s*\()/i,
        // Prompt injection keywords
        /(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?|disregard\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?|forget\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?)/i,
        // System prompt override attempts
        /(?:you\s+are\s+now|act\s+as\s+(?:a\s+)?(?:dan|jailbreak|unrestricted)|new\s+persona|system\s*:\s*you)/i,
        // Script injection
        /<\s*script[\s>]/i,
        // SQL injection patterns
        /(?:'\s*(?:or|and)\s*'?\d|union\s+(?:all\s+)?select|drop\s+table|insert\s+into|delete\s+from)/i,
        // Null bytes and control characters (excluding normal whitespace)
        /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/
    ]

    for (const pattern of suspiciousPatterns) {
        if (pattern.test(text)) {
            return true
        }
    }
    return false
}

const redactPIIFromText = (text) => {
    let redacted = text

    // SSN (US)
    redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')

    // Email addresses
    redacted = redacted.replace(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]')

    // Passport numbers (generic alphanumeric 6-9 chars)
    redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,8}\b/g, '[REDACTED_PASSPORT]')

    // Phone numbers (various formats)
    redacted = redacted.replace(/(?:\+?\d{1,3}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b/g, '[REDACTED_PHONE]')

    // Credit card numbers (13-19 digits, optionally separated by spaces or dashes)
    redacted = redacted.replace(/\b(?:\d{4}[\s\-]?){3}\d{1,4}\b/g, '[REDACTED_CC]')

    // Singapore NRIC/FIN numbers (S/T/F/G followed by 7 digits and a letter)
    redacted = redacted.replace(/\b[STFG]\d{7}[A-Z]\b/gi, '[REDACTED_NRIC]')

    return redacted
}

const scanForSingaporePII = (text) => {
    const detectedCategories = []

    // Singapore NRIC/FIN
    if (/\b[STFG]\d{7}[A-Z]\b/i.test(text)) {
        detectedCategories.push('NRIC/FIN numbers')
    }

    // Singapore passport numbers (E followed by 7-8 digits)
    if (/\bE\d{7,8}\b/i.test(text)) {
        detectedCategories.push('Passport numbers')
    }

    // Personal email addresses
    if (/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/.test(text)) {
        detectedCategories.push('Personal email addresses')
    }

    // Common full name patterns (two or more capitalized words)
    if (/\b[A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20})?\b/.test(text)) {
        detectedCategories.push('Full names')
    }

    return detectedCategories
}

const readFileAsText = (file) => {
    return new Promise((resolve, reject) => {
        // Handle base64 data URLs
        if (typeof file === 'string' && file.startsWith('data:')) {
            try {
                const base64Data = file.split(',')[1]
                const decoded = atob(base64Data)
                resolve(decoded)
            } catch (e) {
                reject(e)
            }
            return
        }
        if (file instanceof Blob || file instanceof File) {
            const reader = new FileReader()
            reader.onload = (e) => resolve(e.target.result)
            reader.onerror = (e) => reject(e)
            reader.readAsText(file)
            return
        }
        // If it's already a string
        if (typeof file === 'string') {
            resolve(file)
            return
        }
        reject(new Error('Unsupported file type'))
    })
}

const createSanitizedFile = (text, originalFile) => {
    const blob = new Blob([text], { type: 'text/csv' })
    const fileName = (originalFile instanceof File) ? originalFile.name : 'upload.csv'
    return new File([blob], fileName, { type: 'text/csv' })
}

// ==============================|| UploadCSVFileDialog ||============================== //

const UploadCSVFileDialog = ({ show, dialogProps, onCancel, onConfirm }) => {
    const portalElement = document.getElementById('portal')

    const dispatch = useDispatch()

    // ==============================|| Snackbar ||============================== //

    useNotifier()

    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const [datasetId, setDatasetId] = useState('')
    const [datasetName, setDatasetName] = useState('')
    const [firstRowHeaders, setFirstRowHeaders] = useState(false)
    const [selectedFile, setSelectedFile] = useState()
    const [dialogType, setDialogType] = useState('ADD')

    useEffect(() => {
        setDatasetId(dialogProps.data.datasetId)
        setDatasetName(dialogProps.data.datasetName)
        setDialogType('ADD')

        return () => {
            setDialogType('ADD')
            setDatasetId('')
            setDatasetName('')
            setFirstRowHeaders(false)
            setSelectedFile()
        }
    }, [dialogProps])

    useEffect(() => {
        if (show) dispatch({ type: SHOW_CANVAS_DIALOG })
        else dispatch({ type: HIDE_CANVAS_DIALOG })
        return () => dispatch({ type: HIDE_CANVAS_DIALOG })
    }, [show, dispatch])

    const addNewDatasetRow = async () => {
        try {
            // Read file content for security and PII checks
            let fileText
            try {
                fileText = await readFileAsText(selectedFile)
            } catch (readError) {
                enqueueSnackbar({
                    message: 'Failed to read the uploaded file for security inspection.',
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

            // Check for malicious content
            if (inspectCSVForMaliciousContent(fileText)) {
                enqueueSnackbar({
                    message: 'Upload aborted: The file contains suspicious or potentially malicious content.',
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
            const singaporePIICategories = scanForSingaporePII(fileText)
            if (singaporePIICategories.length > 0) {
                enqueueSnackbar({
                    message: `Upload aborted: The file contains Singapore PII data (${singaporePIICategories.join(', ')}). Please remove this information before uploading.`,
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

            // Redact PII from file content
            const redactedText = redactPIIFromText(fileText)

            // Create sanitized file object
            let sanitizedFile = selectedFile
            try {
                sanitizedFile = createSanitizedFile(redactedText, selectedFile)
            } catch (sanitizeError) {
                // If we can't create a File object (e.g., selectedFile is a data URL string), use redacted text as base64
                const encoder = new TextEncoder()
                const uint8Array = encoder.encode(redactedText)
                let binary = ''
                uint8Array.forEach((byte) => { binary += String.fromCharCode(byte) })
                sanitizedFile = 'data:text/csv;base64,' + btoa(binary)
            }

            const obj = {
                datasetId: datasetId,
                firstRowHeaders: firstRowHeaders,
                csvFile: sanitizedFile
            }
            const createResp = await datasetApi.createDatasetRow(obj)
            if (createResp.data) {
                enqueueSnackbar({
                    message: 'New Row added for the given Dataset',
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
                message: `Failed to add new row in the Dataset: ${
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
                    <div
                        style={{
                            width: 50,
                            height: 50,
                            marginRight: 10,
                            borderRadius: '50%',
                            backgroundColor: 'white'
                        }}
                    >
                        <IconDatabase
                            style={{
                                width: '100%',
                                height: '100%',
                                padding: 7,
                                borderRadius: '50%',
                                objectFit: 'contain'
                            }}
                        />
                    </div>
                    {'Upload Items to [' + datasetName + '] Dataset'}
                </div>
            </DialogTitle>
            <DialogContent>
                <Box sx={{ p: 2 }}>
                    <div style={{ display: 'flex', flexDirection: 'row' }}>
                        <Typography>
                            Upload CSV
                            <TooltipWithParser style={{ mb: 1, mt: 2 }} title={`<pre>${CSVFORMAT}</pre>`} />
                        </Typography>
                        <div style={{ flexGrow: 1 }}></div>
                    </div>
                    <File
                        disabled={false}
                        fileType='.csv'
                        onChange={(newValue) => setSelectedFile(newValue)}
                        value={selectedFile ?? 'Choose a file to upload'}
                    />
                    <SwitchInput
                        value={firstRowHeaders}
                        onChange={setFirstRowHeaders}
                        label={'Treat First Row as headers in the upload file?'}
                    />
                </Box>
            </DialogContent>
            <DialogActions>
                <Button onClick={() => onCancel()}>{dialogProps.cancelButtonName}</Button>
                <StyledButton
                    disabled={!selectedFile}
                    variant='contained'
                    onClick={() => (dialogType === 'ADD' ? addNewDatasetRow() : saveDatasetRow())}
                >
                    {dialogProps.confirmButtonName}
                </StyledButton>
            </DialogActions>
            <ConfirmDialog />
        </Dialog>
    ) : null

    return createPortal(component, portalElement)
}

UploadCSVFileDialog.propTypes = {
    show: PropTypes.bool,
    dialogProps: PropTypes.object,
    onCancel: PropTypes.func,
    onConfirm: PropTypes.func
}

export default UploadCSVFileDialog
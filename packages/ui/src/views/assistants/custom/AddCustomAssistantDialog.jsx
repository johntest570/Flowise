import { createPortal } from 'react-dom'
import PropTypes from 'prop-types'
import { useState, useEffect } from 'react'
import { useDispatch } from 'react-redux'
import {
    HIDE_CANVAS_DIALOG,
    SHOW_CANVAS_DIALOG,
    enqueueSnackbar as enqueueSnackbarAction,
    closeSnackbar as closeSnackbarAction
} from '@/store/actions'
import { v4 as uuidv4 } from 'uuid'

// Material
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Box, Typography, OutlinedInput } from '@mui/material'

// Project imports
import { StyledButton } from '@/ui-component/button/StyledButton'
import ConfirmDialog from '@/ui-component/dialog/ConfirmDialog'

// Icons
import { IconX, IconFiles } from '@tabler/icons-react'

// API
import assistantsApi from '@/api/assistants'

// utils
import useNotifier from '@/utils/useNotifier'

const MAX_ASSISTANT_NAME_LENGTH = 100
const DANGEROUS_CHARS_REGEX = /[<>"'`\\;{}()\[\]]/g

const sanitizeAndValidateAssistantName = (name) => {
    if (typeof name !== 'string') {
        return { valid: false, value: '', error: 'Assistant name must be a string.' }
    }
    const trimmed = name.trim()
    if (trimmed.length === 0) {
        return { valid: false, value: '', error: 'Assistant name cannot be empty.' }
    }
    if (trimmed.length > MAX_ASSISTANT_NAME_LENGTH) {
        return {
            valid: false,
            value: '',
            error: `Assistant name must not exceed ${MAX_ASSISTANT_NAME_LENGTH} characters.`
        }
    }
    const sanitized = trimmed.replace(DANGEROUS_CHARS_REGEX, '')
    if (sanitized.length === 0) {
        return { valid: false, value: '', error: 'Assistant name contains only invalid characters.' }
    }
    return { valid: true, value: sanitized, error: null }
}

const AddCustomAssistantDialog = ({ show, dialogProps, onCancel, onConfirm }) => {
    const portalElement = document.getElementById('portal')

    const dispatch = useDispatch()

    // ==============================|| Snackbar ||============================== //

    useNotifier()

    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const [customAssistantName, setCustomAssistantName] = useState('')
    const [nameValidationError, setNameValidationError] = useState('')

    useEffect(() => {
        if (show) dispatch({ type: SHOW_CANVAS_DIALOG })
        else dispatch({ type: HIDE_CANVAS_DIALOG })
        return () => dispatch({ type: HIDE_CANVAS_DIALOG })
    }, [show, dispatch])

    const createCustomAssistant = async () => {
        const { valid, value: sanitizedName, error: validationError } = sanitizeAndValidateAssistantName(customAssistantName)
        if (!valid) {
            setNameValidationError(validationError)
            enqueueSnackbar({
                message: `Validation error: ${validationError}`,
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    persist: false,
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }
        setNameValidationError('')
        try {
            const obj = {
                details: JSON.stringify({
                    name: sanitizedName
                }),
                credential: uuidv4(),
                type: 'CUSTOM'
            }
            const createResp = await assistantsApi.createNewAssistant(obj)
            if (createResp.data) {
                enqueueSnackbar({
                    message: 'New Custom Assistant created.',
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
        } catch (err) {
            enqueueSnackbar({
                message: `Failed to add new Custom Assistant: ${
                    typeof err.response.data === 'object' ? err.response.data.message : err.response.data
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
            <DialogTitle style={{ fontSize: '1rem' }} id='alert-dialog-title'>
                <div style={{ display: 'flex', flexDirection: 'row', alignItems: 'center' }}>
                    <IconFiles style={{ marginRight: '10px' }} />
                    {dialogProps.title}
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
                        key='customAssistantName'
                        onChange={(e) => {
                            setCustomAssistantName(e.target.value)
                            if (nameValidationError) setNameValidationError('')
                        }}
                        value={customAssistantName ?? ''}
                        error={!!nameValidationError}
                    />
                    {nameValidationError && (
                        <Typography variant='caption' style={{ color: 'red', marginTop: '4px', display: 'block' }}>
                            {nameValidationError}
                        </Typography>
                    )}
                </Box>
            </DialogContent>
            <DialogActions>
                <Button onClick={() => onCancel()}>Cancel</Button>
                <StyledButton disabled={!customAssistantName} variant='contained' onClick={() => createCustomAssistant()}>
                    {dialogProps.confirmButtonName}
                </StyledButton>
            </DialogActions>
            <ConfirmDialog />
        </Dialog>
    ) : null

    return createPortal(component, portalElement)
}

AddCustomAssistantDialog.propTypes = {
    show: PropTypes.bool,
    dialogProps: PropTypes.object,
    onCancel: PropTypes.func,
    onConfirm: PropTypes.func
}

export default AddCustomAssistantDialog
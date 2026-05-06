import { createPortal } from 'react-dom'
import { useState, useEffect } from 'react'
import { useDispatch } from 'react-redux'
import PropTypes from 'prop-types'
import { OutlinedInput, DialogActions, Button, Dialog, DialogContent, DialogTitle } from '@mui/material'
import { StyledButton } from '@/ui-component/button/StyledButton'
import assistantsApi from '@/api/assistants'
import { closeSnackbar as closeSnackbarAction, enqueueSnackbar as enqueueSnackbarAction } from '@/store/actions'
import { IconX, IconWand, IconArrowLeft, IconNotebook, IconLanguage, IconMail, IconCode, IconReport, IconWorld } from '@tabler/icons-react'
import useNotifier from '@/utils/useNotifier'
import { LoadingButton } from '@mui/lab'

const MAX_INSTRUCTION_LENGTH = 2000

const DANGEROUS_PATTERNS = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /new\s+Function\s*\(/i,
    /setTimeout\s*\(\s*['"`]/i,
    /setInterval\s*\(\s*['"`]/i,
    /\bimportScripts\s*\(/i,
    /document\s*\.\s*write\s*\(/i,
    /innerHTML\s*=/i,
    /outerHTML\s*=/i,
    /\bwindow\s*\[\s*['"`]/i,
    /__proto__/i,
    /constructor\s*\[/i,
    /prototype\s*\[/i
]

const sanitizeInput = (input) => {
    if (typeof input !== 'string') return ''
    return input.trim().replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
}

const validateInput = (input) => {
    if (!input || input.trim().length === 0) {
        return { valid: false, reason: 'Instruction cannot be empty.' }
    }
    if (input.length > MAX_INSTRUCTION_LENGTH) {
        return { valid: false, reason: `Instruction exceeds maximum length of ${MAX_INSTRUCTION_LENGTH} characters.` }
    }
    return { valid: true }
}

const sanitizeLLMOutput = (output) => {
    if (typeof output !== 'string') return { safe: false, reason: 'Output is not a string.' }
    for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.test(output)) {
            return { safe: false, reason: 'Generated content contains potentially dangerous code patterns and has been rejected.' }
        }
    }
    return { safe: true }
}

const defaultInstructions = [
    {
        text: 'Summarize a document',
        img: <IconNotebook />
    },
    {
        text: 'Translate the language',
        img: <IconLanguage />
    },
    {
        text: 'Write me an email',
        img: <IconMail />
    },
    {
        text: 'Convert the code to another language',
        img: <IconCode />
    },
    {
        text: 'Research and generate a report',
        img: <IconReport />
    },
    {
        text: 'Plan a trip',
        img: <IconWorld />
    }
]

const AssistantPromptGenerator = ({ show, dialogProps, onCancel, onConfirm }) => {
    const portalElement = document.getElementById('portal')
    const [customAssistantInstruction, setCustomAssistantInstruction] = useState('')
    const [generatedInstruction, setGeneratedInstruction] = useState('')
    const [loading, setLoading] = useState(false)

    // ==============================|| Snackbar ||============================== //
    const dispatch = useDispatch()
    useNotifier()
    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const onGenerate = async () => {
        try {
            const sanitized = sanitizeInput(customAssistantInstruction)
            const validation = validateInput(sanitized)
            if (!validation.valid) {
                enqueueSnackbar({
                    message: validation.reason,
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
            const selectedChatModelObj = {
                name: dialogProps.data.selectedChatModel.name,
                inputs: dialogProps.data.selectedChatModel.inputs
            }

            const requestPayload = {
                selectedChatModel: selectedChatModelObj,
                task: sanitized
            }

            console.log('[PromptGeneratorDialog] LLM request payload:', JSON.stringify(requestPayload))

            const resp = await assistantsApi.generateAssistantInstruction(requestPayload)

            console.log('[PromptGeneratorDialog] LLM response:', JSON.stringify(resp.data))

            if (resp.data) {
                setLoading(false)
                if (resp.data.content) {
                    const outputCheck = sanitizeLLMOutput(resp.data.content)
                    if (!outputCheck.safe) {
                        enqueueSnackbar({
                            message: outputCheck.reason,
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
                    setGeneratedInstruction(resp.data.content)
                }
            }
        } catch (error) {
            setLoading(false)
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

    // clear the state when dialog is closed
    useEffect(() => {
        if (!show) {
            setCustomAssistantInstruction('')
            setGeneratedInstruction('')
        }
    }, [show])

    const component = show ? (
        <>
            <Dialog
                fullWidth
                maxWidth='md'
                open={show}
                onClose={onCancel}
                aria-labelledby='alert-dialog-title'
                aria-describedby='alert-dialog-description'
            >
                <DialogTitle sx={{ fontSize: '1rem' }} id='alert-dialog-title'>
                    {dialogProps.title}
                </DialogTitle>
                <DialogContent>
                    <span>{dialogProps.description}</span>
                    <div
                        style={{
                            display: 'block',
                            flexDirection: 'row',
                            width: '100%',
                            marginTop: '15px'
                        }}
                    >
                        {defaultInstructions.map((instruction, index) => {
                            return (
                                <Button
                                    size='small'
                                    key={index}
                                    sx={{ textTransform: 'none', mr: 1, mb: 1, borderRadius: '16px' }}
                                    variant='outlined'
                                    color='inherit'
                                    onClick={() => {
                                        setCustomAssistantInstruction(instruction.text)
                                        setGeneratedInstruction('')
                                    }}
                                    startIcon={instruction.img}
                                >
                                    {instruction.text}
                                </Button>
                            )
                        })}
                    </div>
                    {!generatedInstruction && (
                        <OutlinedInput
                            sx={{ mt: 2, width: '100%' }}
                            type={'text'}
                            multiline={true}
                            rows={12}
                            disabled={loading}
                            value={customAssistantInstruction}
                            placeholder={'Describe your task here'}
                            onChange={(event) => setCustomAssistantInstruction(event.target.value)}
                        />
                    )}
                    {generatedInstruction && (
                        <OutlinedInput
                            sx={{ mt: 2, width: '100%' }}
                            type={'text'}
                            multiline={true}
                            rows={12}
                            value={generatedInstruction}
                            onChange={(event) => setGeneratedInstruction(event.target.value)}
                        />
                    )}
                </DialogContent>
                <DialogActions sx={{ pb: 3, pr: 3 }}>
                    {!generatedInstruction && (
                        <LoadingButton
                            loading={loading}
                            variant='contained'
                            onClick={() => {
                                onGenerate()
                            }}
                            startIcon={<IconWand size={20} />}
                        >
                            Generate
                        </LoadingButton>
                    )}
                    {generatedInstruction && (
                        <Button
                            variant='outlined'
                            startIcon={<IconArrowLeft size={20} />}
                            onClick={() => {
                                setGeneratedInstruction('')
                            }}
                        >
                            Back
                        </Button>
                    )}
                    {generatedInstruction && (
                        <StyledButton variant='contained' onClick={() => onConfirm(generatedInstruction)}>
                            Apply
                        </StyledButton>
                    )}
                </DialogActions>
            </Dialog>
        </>
    ) : null

    return createPortal(component, portalElement)
}

AssistantPromptGenerator.propTypes = {
    show: PropTypes.bool,
    dialogProps: PropTypes.object,
    onConfirm: PropTypes.func,
    onCancel: PropTypes.func
}

export default AssistantPromptGenerator
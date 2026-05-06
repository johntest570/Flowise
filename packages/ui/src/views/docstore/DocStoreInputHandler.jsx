import PropTypes from 'prop-types'
import { useState, useContext } from 'react'
import { useSelector } from 'react-redux'

// material-ui
import { Box, Typography, IconButton, Button } from '@mui/material'
import { IconArrowsMaximize, IconAlertTriangle, IconRefresh } from '@tabler/icons-react'

// project import
import { Dropdown } from '@/ui-component/dropdown/Dropdown'
import { MultiDropdown } from '@/ui-component/dropdown/MultiDropdown'
import { AsyncDropdown } from '@/ui-component/dropdown/AsyncDropdown'
import { Input } from '@/ui-component/input/Input'
import { DataGrid } from '@/ui-component/grid/DataGrid'
import { File } from '@/ui-component/file/File'
import { SwitchInput } from '@/ui-component/switch/Switch'
import { JsonEditorInput } from '@/ui-component/json/JsonEditor'
import { TooltipWithParser } from '@/ui-component/tooltip/TooltipWithParser'
import { CodeEditor } from '@/ui-component/editor/CodeEditor'
import { ArrayRenderer } from '@/ui-component/array/ArrayRenderer'
import ExpandTextDialog from '@/ui-component/dialog/ExpandTextDialog'
import ManageScrapedLinksDialog from '@/ui-component/dialog/ManageScrapedLinksDialog'
import CredentialInputHandler from '@/views/canvas/CredentialInputHandler'
import { flowContext } from '@/store/context/ReactFlowContext'

// const
import { FLOWISE_CREDENTIAL_ID } from '@/store/constant'

// ===========================|| Security Helpers ||=========================== //

const sanitizeInput = (value) => {
    if (value === null || value === undefined) return value
    if (typeof value === 'boolean' || typeof value === 'number') return value
    if (typeof value === 'string') {
        // Remove null bytes
        let sanitized = value.replace(/\0/g, '')
        // Remove invisible/control Unicode characters that could be used for prompt injection
        sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, '')
        // Trim excessive whitespace
        sanitized = sanitized.trim()
        return sanitized
    }
    if (typeof value === 'object') {
        try {
            const str = JSON.stringify(value)
            return JSON.parse(sanitizeInput(str))
        } catch {
            return value
        }
    }
    return value
}

const sanitizeFileContent = (content) => {
    if (typeof content !== 'string') return { valid: true, content }

    // Check for invisible Unicode characters (hidden prompts)
    if (/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u202A-\u202E]/.test(content)) {
        return { valid: false, reason: 'File contains hidden Unicode characters that may indicate a prompt injection attempt.' }
    }

    // Check for base64-encoded prompt patterns
    const base64Pattern = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g
    const base64Matches = content.match(base64Pattern) || []
    for (const match of base64Matches) {
        try {
            const decoded = atob(match)
            if (/ignore\s+(previous|above|prior)|you\s+are\s+now|new\s+instructions|system\s*:/i.test(decoded)) {
                return { valid: false, reason: 'File contains base64-encoded prompt injection content.' }
            }
        } catch {
            // not valid base64, skip
        }
    }

    // Check for leetspeak prompt patterns
    const leetspeakNormalized = content
        .replace(/4/g, 'a').replace(/3/g, 'e').replace(/1/g, 'i')
        .replace(/0/g, 'o').replace(/5/g, 's').replace(/7/g, 't')
        .toLowerCase()
    if (/ignore\s+(previous|above|prior)\s+instructions|disregard\s+all|you\s+are\s+now\s+a/i.test(leetspeakNormalized)) {
        return { valid: false, reason: 'File contains leetspeak prompt injection patterns.' }
    }

    // Check for suspicious instruction keywords
    const suspiciousPatterns = [
        /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
        /disregard\s+(all\s+)?(previous|prior|above)/i,
        /you\s+are\s+now\s+(a|an)\s+/i,
        /new\s+instructions\s*:/i,
        /system\s*:\s*(you|your|ignore)/i,
        /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i,
        /act\s+as\s+(a|an)\s+/i,
        /pretend\s+(you\s+are|to\s+be)/i,
        /forget\s+(all\s+)?(previous|prior|your)\s+(instructions|training)/i,
        /override\s+(previous|prior|all)\s+(instructions|commands)/i
    ]
    for (const pattern of suspiciousPatterns) {
        if (pattern.test(content)) {
            return { valid: false, reason: 'File contains suspicious instruction keywords that may indicate a prompt injection attempt.' }
        }
    }

    // Check for binary/shell command payloads
    const shellPatterns = [
        /\x00[\x00-\x08\x0B\x0C\x0E-\x1F]{3,}/,
        /(?:\/bin\/(?:sh|bash|zsh)|cmd\.exe|powershell)/i,
        /(?:eval|exec|system|passthru|shell_exec)\s*\(/i,
        /(?:rm\s+-rf|del\s+\/f|format\s+c:)/i
    ]
    for (const pattern of shellPatterns) {
        if (pattern.test(content)) {
            return { valid: false, reason: 'File contains binary or shell command payloads.' }
        }
    }

    return { valid: true, content }
}

const redactPII = (content) => {
    if (typeof content !== 'string') return content
    let redacted = content
    // Redact email addresses
    redacted = redacted.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
    // Redact phone numbers (various formats)
    redacted = redacted.replace(/(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, '[REDACTED_PHONE]')
    // Redact SSNs (US)
    redacted = redacted.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, '[REDACTED_SSN]')
    // Redact credit card numbers
    redacted = redacted.replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '[REDACTED_CC]')
    return redacted
}

const detectSingaporePII = (content) => {
    if (typeof content !== 'string') return { hasPII: false }

    // NRIC numbers (S/T/F/G followed by 7 digits and a letter)
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/i
    if (nricPattern.test(content)) {
        return { hasPII: true, reason: 'File contains Singapore NRIC/FIN numbers.' }
    }

    // FIN numbers (F/G followed by 7 digits and a letter - subset of above, but explicit)
    const finPattern = /\b[FG]\d{7}[A-Z]\b/i
    if (finPattern.test(content)) {
        return { hasPII: true, reason: 'File contains Singapore FIN numbers.' }
    }

    // SingPass identifiers (common patterns)
    const singpassPattern = /singpass\s*(?:id|identifier|user|login|account)?\s*[:\-]?\s*[A-Z0-9]{6,}/i
    if (singpassPattern.test(content)) {
        return { hasPII: true, reason: 'File contains SingPass identifiers.' }
    }

    // Singapore phone numbers (+65 XXXX XXXX)
    const sgPhonePattern = /(?:\+65[-.\s]?)?\d{4}[-.\s]?\d{4}\b/
    if (sgPhonePattern.test(content)) {
        return { hasPII: true, reason: 'File contains Singapore phone numbers.' }
    }

    // Singapore postal codes (6-digit)
    const sgPostalPattern = /\bSingapore\s+\d{6}\b/i
    if (sgPostalPattern.test(content)) {
        return { hasPII: true, reason: 'File contains Singapore postal codes with location context.' }
    }

    return { hasPII: false }
}

// ===========================|| DocStoreInputHandler ||=========================== //

const DocStoreInputHandler = ({ inputParam, data, disabled = false, onNodeDataChange }) => {
    const customization = useSelector((state) => state.customization)
    const flowContextValue = useContext(flowContext)
    const nodeDataChangeHandler = onNodeDataChange || flowContextValue?.onNodeDataChange

    const [showExpandDialog, setShowExpandDialog] = useState(false)
    const [expandDialogProps, setExpandDialogProps] = useState({})
    const [showManageScrapedLinksDialog, setShowManageScrapedLinksDialog] = useState(false)
    const [manageScrapedLinksDialogProps, setManageScrapedLinksDialogProps] = useState({})
    const [reloadTimestamp, setReloadTimestamp] = useState(Date.now().toString())

    const handleDataChange = ({ inputParam, newValue }) => {
        const sanitizedValue = sanitizeInput(newValue)
        data.inputs[inputParam.name] = sanitizedValue
        if (nodeDataChangeHandler) {
            nodeDataChangeHandler({ nodeId: data.id, inputParam, newValue: sanitizedValue })
        }
    }

    const onExpandDialogClicked = (value, inputParam) => {
        const dialogProps = {
            value,
            inputParam,
            disabled,
            confirmButtonName: 'Save',
            cancelButtonName: 'Cancel'
        }
        setExpandDialogProps(dialogProps)
        setShowExpandDialog(true)
    }

    const onManageLinksDialogClicked = (url, selectedLinks, relativeLinksMethod, limit) => {
        const dialogProps = {
            url,
            relativeLinksMethod,
            limit,
            selectedLinks,
            confirmButtonName: 'Save',
            cancelButtonName: 'Cancel'
        }
        setManageScrapedLinksDialogProps(dialogProps)
        setShowManageScrapedLinksDialog(true)
    }

    const onManageLinksDialogSave = (url, links) => {
        setShowManageScrapedLinksDialog(false)
        const sanitizedUrl = sanitizeInput(url)
        const sanitizedLinks = sanitizeInput(links)
        data.inputs.url = sanitizedUrl
        data.inputs.selectedLinks = sanitizedLinks
    }

    const onExpandDialogSave = (newValue, inputParamName) => {
        setShowExpandDialog(false)
        const sanitizedValue = sanitizeInput(newValue)
        data.inputs[inputParamName] = sanitizedValue
    }

    const getCredential = () => {
        const credential = data.inputs.credential || data.inputs[FLOWISE_CREDENTIAL_ID]
        if (credential) {
            return { credential }
        }
        return {}
    }

    const handleFileChange = (newValue) => {
        // Check for Singapore PII
        const sgPIIResult = detectSingaporePII(newValue)
        if (sgPIIResult.hasPII) {
            alert(`File upload blocked: ${sgPIIResult.reason}`)
            return
        }

        // Check for malicious file content
        const fileContentCheck = sanitizeFileContent(newValue)
        if (!fileContentCheck.valid) {
            alert(`File upload blocked: ${fileContentCheck.reason}`)
            return
        }

        // Redact PII from file content
        const redactedValue = redactPII(newValue)

        handleDataChange({ inputParam, newValue: redactedValue })
    }

    return (
        <div>
            {inputParam && (
                <>
                    <Box sx={{ p: 2 }}>
                        <div style={{ display: 'flex', flexDirection: 'row' }}>
                            <Typography>
                                {inputParam.label}
                                {!inputParam.optional && <span style={{ color: 'red' }}>&nbsp;*</span>}
                                {inputParam.description && <TooltipWithParser style={{ marginLeft: 10 }} title={inputParam.description} />}
                            </Typography>
                            <div style={{ flexGrow: 1 }}></div>
                            {((inputParam.type === 'string' && inputParam.rows) || inputParam.type === 'code') && (
                                <IconButton
                                    size='small'
                                    sx={{
                                        height: 25,
                                        width: 25
                                    }}
                                    title='Expand'
                                    color='primary'
                                    onClick={() =>
                                        onExpandDialogClicked(data.inputs[inputParam.name] ?? inputParam.default ?? '', inputParam)
                                    }
                                >
                                    <IconArrowsMaximize />
                                </IconButton>
                            )}
                        </div>
                        {inputParam.warning && (
                            <div
                                style={{
                                    display: 'flex',
                                    flexDirection: 'row',
                                    alignItems: 'center',
                                    borderRadius: 10,
                                    background: 'rgb(254,252,191)',
                                    padding: 10,
                                    marginTop: 10,
                                    marginBottom: 10
                                }}
                            >
                                <IconAlertTriangle size={30} color='orange' />
                                <span style={{ color: 'rgb(116,66,16)', marginLeft: 10 }}>{inputParam.warning}</span>
                            </div>
                        )}
                        {inputParam.type === 'credential' && (
                            <CredentialInputHandler
                                key={JSON.stringify(inputParam)}
                                disabled={disabled}
                                data={getCredential()}
                                inputParam={inputParam}
                                onSelect={(newValue) => {
                                    data.credential = newValue
                                    data.inputs[FLOWISE_CREDENTIAL_ID] = newValue // in case data.credential is not updated
                                    if (nodeDataChangeHandler) {
                                        nodeDataChangeHandler({ nodeId: data.id, inputParam, newValue })
                                    }
                                }}
                            />
                        )}

                        {inputParam.type === 'file' && (
                            <File
                                disabled={disabled}
                                fileType={inputParam.fileType || '*'}
                                onChange={(newValue) => handleFileChange(newValue)}
                                value={data.inputs[inputParam.name] ?? inputParam.default ?? 'Choose a file to upload'}
                            />
                        )}
                        {inputParam.type === 'boolean' && (
                            <SwitchInput
                                disabled={disabled}
                                onChange={(newValue) => handleDataChange({ inputParam, newValue })}
                                value={data.inputs[inputParam.name] ?? inputParam.default ?? false}
                            />
                        )}
                        {inputParam.type === 'datagrid' && (
                            <DataGrid
                                disabled={disabled}
                                columns={inputParam.datagrid}
                                hideFooter={true}
                                rows={data.inputs[inputParam.name] ?? JSON.stringify(inputParam.default) ?? []}
                                onChange={(newValue) => handleDataChange({ inputParam, newValue })}
                            />
                        )}
                        {inputParam.type === 'code' && (
                            <>
                                <div style={{ height: '5px' }}></div>
                                <div style={{ height: inputParam.rows ? '100px' : '200px' }}>
                                    <CodeEditor
                                        disabled={disabled}
                                        value={data.inputs[inputParam.name] ?? inputParam.default ?? ''}
                                        height={inputParam.rows ? '100px' : '200px'}
                                        theme={customization.isDarkMode ? 'dark' : 'light'}
                                        lang={'js'}
                                        placeholder={inputParam.placeholder}
                                        onValueChange={(code) => (data.inputs[inputParam.name] = code)}
                                        basicSetup={{ highlightActiveLine: false, highlightActiveLineGutter: false }}
                                    />
                                </div>
                            </>
                        )}
                        {(inputParam.type === 'string' || inputParam.type === 'password' || inputParam.type === 'number') && (
                            <Input
                                key={data.inputs[inputParam.name]}
                                disabled={disabled}
                                inputParam={inputParam}
                                onChange={(newValue) => (data.inputs[inputParam.name] = newValue)}
                                onBlur={(newValue) => handleDataChange({ inputParam, newValue })}
                                value={data.inputs[inputParam.name] ?? inputParam.default ?? ''}
                                nodeId={data.id}
                            />
                        )}
                        {inputParam.type === 'json' && (
                            <JsonEditorInput
                                disabled={disabled}
                                onChange={(newValue) => (data.inputs[inputParam.name] = newValue)}
                                value={data.inputs[inputParam.name] ?? inputParam.default ?? ''}
                                isDarkMode={customization.isDarkMode}
                            />
                        )}
                        {inputParam.type === 'options' && (
                            <Dropdown
                                key={JSON.stringify(inputParam)}
                                disabled={disabled}
                                name={inputParam.name}
                                options={inputParam.options}
                                onSelect={(newValue) => handleDataChange({ inputParam, newValue })}
                                value={data.inputs[inputParam.name] ?? inputParam.default ?? 'choose an option'}
                            />
                        )}
                        {inputParam.type === 'multiOptions' && (
                            <MultiDropdown
                                key={JSON.stringify(inputParam)}
                                disabled={disabled}
                                name={inputParam.name}
                                options={inputParam.options}
                                onSelect={(newValue) => handleDataChange({ inputParam, newValue })}
                                value={data.inputs[inputParam.name] ?? inputParam.default ?? 'choose an option'}
                            />
                        )}
                        {(inputParam.type === 'asyncOptions' || inputParam.type === 'asyncMultiOptions') && (
                            <>
                                {data.inputParams?.length === 1 && <div style={{ marginTop: 10 }} />}
                                <div style={{ display: 'flex', flexDirection: 'row' }}>
                                    <div key={reloadTimestamp} style={{ flex: 1 }}>
                                        <AsyncDropdown
                                            key={JSON.stringify(inputParam)}
                                            disabled={disabled}
                                            name={inputParam.name}
                                            nodeData={data}
                                            freeSolo={inputParam.freeSolo}
                                            multiple={inputParam.type === 'asyncMultiOptions'}
                                            value={data.inputs[inputParam.name] ?? inputParam.default ?? 'choose an option'}
                                            onSelect={(newValue) => handleDataChange({ inputParam, newValue })}
                                            onCreateNew={() => addAsyncOption(inputParam.name)}
                                            fullWidth={true}
                                        />
                                    </div>
                                    {inputParam.refresh && (
                                        <IconButton
                                            title='Refresh'
                                            color='primary'
                                            size='small'
                                            onClick={() => setReloadTimestamp(Date.now().toString())}
                                        >
                                            <IconRefresh />
                                        </IconButton>
                                    )}
                                </div>
                            </>
                        )}
                        {inputParam.type === 'array' && (
                            <ArrayRenderer inputParam={inputParam} data={data} disabled={disabled} isDocStore={true} />
                        )}
                        {(data.name === 'cheerioWebScraper' ||
                            data.name === 'puppeteerWebScraper' ||
                            data.name === 'playwrightWebScraper') &&
                            inputParam.name === 'url' && (
                                <>
                                    <Button
                                        style={{
                                            display: 'flex',
                                            flexDirection: 'row',
                                            width: '100%'
                                        }}
                                        disabled={disabled}
                                        sx={{ borderRadius: '12px', width: '100%', mt: 1 }}
                                        variant='outlined'
                                        onClick={() =>
                                            onManageLinksDialogClicked(
                                                data.inputs[inputParam.name] ?? inputParam.default ?? '',
                                                data.inputs.selectedLinks,
                                                data.inputs['relativeLinksMethod'] ?? 'webCrawl',
                                                parseInt(data.inputs['limit']) ?? 0
                                            )
                                        }
                                    >
                                        Manage Links
                                    </Button>
                                    <ManageScrapedLinksDialog
                                        show={showManageScrapedLinksDialog}
                                        dialogProps={manageScrapedLinksDialogProps}
                                        onCancel={() => setShowManageScrapedLinksDialog(false)}
                                        onSave={onManageLinksDialogSave}
                                    />
                                </>
                            )}
                    </Box>
                </>
            )}
            <ExpandTextDialog
                show={showExpandDialog}
                dialogProps={expandDialogProps}
                onCancel={() => setShowExpandDialog(false)}
                onConfirm={(newValue, inputParamName) => onExpandDialogSave(newValue, inputParamName)}
            ></ExpandTextDialog>
        </div>
    )
}

DocStoreInputHandler.propTypes = {
    inputParam: PropTypes.object,
    data: PropTypes.object,
    disabled: PropTypes.bool,
    onNodeDataChange: PropTypes.func
}

export default DocStoreInputHandler
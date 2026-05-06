import PropTypes from 'prop-types'
import { Handle, Position, useUpdateNodeInternals } from 'reactflow'
import { useEffect, useRef, useState, useContext } from 'react'
import { useSelector, useDispatch } from 'react-redux'
import { cloneDeep } from 'lodash'
import showdown from 'showdown'
import parser from 'html-react-parser'

// material-ui
import { useTheme, styled } from '@mui/material/styles'
import {
    Popper,
    Box,
    Typography,
    Tooltip,
    IconButton,
    Button,
    TextField,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions
} from '@mui/material'
import { useGridApiContext } from '@mui/x-data-grid'
import IconAutoFixHigh from '@mui/icons-material/AutoFixHigh'
import { tooltipClasses } from '@mui/material/Tooltip'
import { IconWand, IconVariable, IconArrowsMaximize, IconEdit, IconAlertTriangle, IconBulb, IconRefresh, IconX } from '@tabler/icons-react'
import { Tabs } from '@mui/base/Tabs'
import Autocomplete, { autocompleteClasses } from '@mui/material/Autocomplete'

// project import
import { Dropdown } from '@/ui-component/dropdown/Dropdown'
import { MultiDropdown } from '@/ui-component/dropdown/MultiDropdown'
import { AsyncDropdown } from '@/ui-component/dropdown/AsyncDropdown'
import { Input } from '@/ui-component/input/Input'
import { RichInput } from '@/ui-component/input/RichInput'
import { DataGrid } from '@/ui-component/grid/DataGrid'
import { File } from '@/ui-component/file/File'
import { SwitchInput } from '@/ui-component/switch/Switch'
import { flowContext } from '@/store/context/ReactFlowContext'
import { JsonEditorInput } from '@/ui-component/json/JsonEditor'
import { TooltipWithParser } from '@/ui-component/tooltip/TooltipWithParser'
import { CodeEditor } from '@/ui-component/editor/CodeEditor'
import { TabPanel } from '@/ui-component/tabs/TabPanel'
import { TabsList } from '@/ui-component/tabs/TabsList'
import { ArrayRenderer } from '@/ui-component/array/ArrayRenderer'
import { Tab } from '@/ui-component/tabs/Tab'
import { ConfigInput } from '@/views/agentflowsv2/ConfigInput'
import { BackdropLoader } from '@/ui-component/loading/BackdropLoader'
import DocStoreInputHandler from '@/views/docstore/DocStoreInputHandler'
import { TimePicker } from '@/ui-component/picker/TimePicker'
import { WeekDaysPicker } from '@/ui-component/picker/WeekDaysPicker'
import { MonthDaysPicker } from '@/ui-component/picker/MonthDaysPicker'
import { DatePicker } from '@/ui-component/picker/DatePicker'

import ToolDialog from '@/views/tools/ToolDialog'
import AssistantDialog from '@/views/assistants/openai/AssistantDialog'
import FormatPromptValuesDialog from '@/ui-component/dialog/FormatPromptValuesDialog'
import ExpandTextDialog from '@/ui-component/dialog/ExpandTextDialog'
import ExpandRichInputDialog from '@/ui-component/dialog/ExpandRichInputDialog'
import ConditionDialog from '@/ui-component/dialog/ConditionDialog'
import PromptLangsmithHubDialog from '@/ui-component/dialog/PromptLangsmithHubDialog'
import ManageScrapedLinksDialog from '@/ui-component/dialog/ManageScrapedLinksDialog'
import CredentialInputHandler from './CredentialInputHandler'
import InputHintDialog from '@/ui-component/dialog/InputHintDialog'
import NvidiaNIMDialog from '@/ui-component/dialog/NvidiaNIMDialog'
import PromptGeneratorDialog from '@/ui-component/dialog/PromptGeneratorDialog'

// API
import assistantsApi from '@/api/assistants'
import documentstoreApi from '@/api/documentstore'

// utils
import {
    initNode,
    getInputVariables,
    getCustomConditionOutputs,
    isValidConnection,
    getAvailableNodesForVariable
} from '@/utils/genericHelper'
import useNotifier from '@/utils/useNotifier'

// const
import { baseURL, FLOWISE_CREDENTIAL_ID } from '@/store/constant'
import { closeSnackbar as closeSnackbarAction, enqueueSnackbar as enqueueSnackbarAction } from '@/store/actions'

const EDITABLE_OPTIONS = ['selectedTool', 'selectedAssistant']

const CustomWidthTooltip = styled(({ className, ...props }) => <Tooltip {...props} classes={{ popper: className }} />)({
    [`& .${tooltipClasses.tooltip}`]: {
        maxWidth: 500
    }
})

const StyledPopper = styled(Popper)({
    boxShadow: '0px 8px 10px -5px rgb(0 0 0 / 20%), 0px 16px 24px 2px rgb(0 0 0 / 14%), 0px 6px 30px 5px rgb(0 0 0 / 12%)',
    borderRadius: '10px',
    [`& .${autocompleteClasses.listbox}`]: {
        boxSizing: 'border-box',
        '& ul': {
            padding: 10,
            margin: 10
        }
    }
})

const markdownConverter = new showdown.Converter({
    simplifiedAutoLink: true,
    strikethrough: true,
    tables: true,
    tasklists: true
})

// ===========================|| Security Helper Functions ||=========================== //

/**
 * Checks LLM output for dynamic code execution primitives and returns sanitized content.
 * Returns null if the content contains dangerous patterns that cannot be safely stripped.
 */
const sanitizeLLMOutput = (content) => {
    if (typeof content !== 'string') return content

    // Patterns for dynamic code execution primitives
    const dangerousPatterns = [
        /\beval\s*\(/gi,
        /\bexec\s*\(/gi,
        /\bnew\s+Function\s*\(/gi,
        /\bFunction\s*\(/gi,
        /\bsetTimeout\s*\(\s*["'`]/gi,
        /\bsetInterval\s*\(\s*["'`]/gi,
        /\bsetImmediate\s*\(\s*["'`]/gi,
        /\bexecScript\s*\(/gi,
        /\bwindow\s*\[\s*["'`]eval["'`]\s*\]/gi,
        /\bglobalThis\s*\[\s*["'`]eval["'`]\s*\]/gi,
        /javascript\s*:/gi,
        /data\s*:\s*text\/html/gi,
        /\bimportScripts\s*\(/gi,
        /\b__import__\s*\(/gi,
        /\bcompile\s*\(/gi,
        /\bos\.system\s*\(/gi,
        /\bsubprocess\s*\./gi
    ]

    let sanitized = content
    for (const pattern of dangerousPatterns) {
        sanitized = sanitized.replace(pattern, '[REMOVED]')
    }

    return sanitized
}

/**
 * Sanitizes storeId to only allow alphanumeric, dash, and underscore characters.
 */
const sanitizeStoreId = (storeId) => {
    if (typeof storeId !== 'string') return ''
    return storeId.replace(/[^a-zA-Z0-9\-_]/g, '')
}

/**
 * Validates that a selectedChatModelObj has a non-empty string name and a plain object inputs field.
 */
const validateChatModelObj = (obj) => {
    if (!obj || typeof obj !== 'object') return false
    if (typeof obj.name !== 'string' || obj.name.trim() === '') return false
    if (obj.inputs !== undefined && obj.inputs !== null) {
        if (typeof obj.inputs !== 'object' || Array.isArray(obj.inputs)) return false
    }
    return true
}

/**
 * Checks file content for common prompt injection patterns.
 * Returns true if suspicious content is detected.
 */
const detectPromptInjection = (value) => {
    if (typeof value !== 'string') return false

    const injectionPatterns = [
        /ignore\s+(previous|prior|above|all)\s+instructions/gi,
        /disregard\s+(previous|prior|above|all)\s+instructions/gi,
        /forget\s+(previous|prior|above|all)\s+instructions/gi,
        /you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another)/gi,
        /act\s+as\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted)/gi,
        /pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another)/gi,
        /jailbreak/gi,
        /DAN\s+mode/gi,
        /developer\s+mode/gi,
        /system\s+prompt\s*:/gi,
        /<\s*system\s*>/gi,
        /\[INST\]/gi,
        /\[\/INST\]/gi,
        /<<SYS>>/gi,
        /<\|im_start\|>/gi,
        /base64\s*decode/gi,
        /atob\s*\(/gi,
        /\\x[0-9a-fA-F]{2}/g,
        /\\u[0-9a-fA-F]{4}/g,
        /new\s+instructions\s*:/gi,
        /override\s+(?:previous|prior|all)\s+instructions/gi
    ]

    return injectionPatterns.some((pattern) => pattern.test(value))
}

/**
 * Redacts common PII patterns from a string.
 */
const redactPII = (value) => {
    if (typeof value !== 'string') return value

    let redacted = value

    // Email addresses
    redacted = redacted.replace(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, '[EMAIL REDACTED]')

    // US/International phone numbers
    redacted = redacted.replace(/(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})/g, '[PHONE REDACTED]')

    // SSNs (US)
    redacted = redacted.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, '[SSN REDACTED]')

    // Credit card numbers
    redacted = redacted.replace(/\b(?:\d{4}[\s\-]?){3}\d{4}\b/g, '[CC REDACTED]')

    // Singapore NRIC/FIN numbers (S/T/F/G followed by 7 digits and a letter)
    redacted = redacted.replace(/\b[STFG]\d{7}[A-Z]\b/gi, '[NRIC REDACTED]')

    // Singapore phone numbers (+65 followed by 8 digits)
    redacted = redacted.replace(/(\+65[\s\-]?)?\b[689]\d{7}\b/g, '[SG PHONE REDACTED]')

    // Singapore postal codes (6 digits)
    redacted = redacted.replace(/\bSingapore\s+\d{6}\b/gi, '[SG POSTAL REDACTED]')
    redacted = redacted.replace(/\b\d{6}\b(?=\s*,?\s*Singapore)/gi, '[SG POSTAL REDACTED]')

    // Passport numbers (generic: letter(s) followed by digits)
    redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, '[PASSPORT REDACTED]')

    return redacted
}

/**
 * Checks file content for Singapore-specific PII patterns.
 * Returns true if Singapore PII is detected.
 */
const detectSingaporePII = (value) => {
    if (typeof value !== 'string') return false

    const sgPIIPatterns = [
        // NRIC/FIN
        /\b[STFG]\d{7}[A-Z]\b/i,
        // Singapore phone numbers
        /(\+65[\s\-]?)?\b[689]\d{7}\b/,
        // Singapore postal codes
        /\bSingapore\s+\d{6}\b/i,
        /\b\d{6}\b(?=\s*,?\s*Singapore)/i,
        // Singapore passport
        /\bE\d{7}[A-Z]\b/i
    ]

    return sgPIIPatterns.some((pattern) => pattern.test(value))
}

/**
 * Validates and sanitizes file upload value for prompt injection, PII, and Singapore PII.
 * Returns { valid: boolean, sanitizedValue: string, reason: string }
 */
const validateAndSanitizeFileValue = (value) => {
    if (typeof value !== 'string') {
        return { valid: true, sanitizedValue: value, reason: '' }
    }

    // Check for prompt injection
    if (detectPromptInjection(value)) {
        return {
            valid: false,
            sanitizedValue: null,
            reason: 'The uploaded file appears to contain prompt injection patterns and cannot be accepted.'
        }
    }

    // Check for Singapore PII
    if (detectSingaporePII(value)) {
        return {
            valid: false,
            sanitizedValue: null,
            reason: 'The uploaded file contains Singapore PII (e.g., NRIC, phone number, postal code) and cannot be stored.'
        }
    }

    // Redact general PII
    const sanitizedValue = redactPII(value)

    return { valid: true, sanitizedValue, reason: '' }
}

// ===========================|| NodeInputHandler ||=========================== //

const NodeInputHandler = ({
    inputAnchor,
    inputParam,
    data,
    disabled = false,
    isAdditionalParams = false,
    disablePadding = false,
    parentParamForArray = null,
    arrayIndex = null,
    onHideNodeInfoDialog,
    onCustomDataChange
}) => {
    const theme = useTheme()
    const customization = useSelector((state) => state.customization)
    const ref = useRef(null)
    const { reactFlowInstance, deleteEdge, onNodeDataChange } = useContext(flowContext)
    const updateNodeInternals = useUpdateNodeInternals()

    useNotifier()
    const dispatch = useDispatch()
    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const [position, setPosition] = useState(0)
    const [showExpandDialog, setShowExpandDialog] = useState(false)
    const [expandDialogProps, setExpandDialogProps] = useState({})
    const [showExpandRichDialog, setShowExpandRichDialog] = useState(false)
    const [expandRichDialogProps, setExpandRichDialogProps] = useState({})
    const [showAsyncOptionDialog, setAsyncOptionEditDialog] = useState('')
    const [asyncOptionEditDialogProps, setAsyncOptionEditDialogProps] = useState({})
    const [reloadTimestamp, setReloadTimestamp] = useState(Date.now().toString())
    const [showFormatPromptValuesDialog, setShowFormatPromptValuesDialog] = useState(false)
    const [formatPromptValuesDialogProps, setFormatPromptValuesDialogProps] = useState({})
    const [showPromptHubDialog, setShowPromptHubDialog] = useState(false)
    const [showManageScrapedLinksDialog, setShowManageScrapedLinksDialog] = useState(false)
    const [manageScrapedLinksDialogProps, setManageScrapedLinksDialogProps] = useState({})
    const [showInputHintDialog, setShowInputHintDialog] = useState(false)
    const [inputHintDialogProps, setInputHintDialogProps] = useState({})
    const [showConditionDialog, setShowConditionDialog] = useState(false)
    const [conditionDialogProps, setConditionDialogProps] = useState({})
    const [isNvidiaNIMDialogOpen, setIsNvidiaNIMDialogOpen] = useState(false)
    const [tabValue, setTabValue] = useState(0)

    const [modelSelectionDialogOpen, setModelSelectionDialogOpen] = useState(false)
    const [availableChatModels, setAvailableChatModels] = useState([])
    const [availableChatModelsOptions, setAvailableChatModelsOptions] = useState([])
    const [selectedTempChatModel, setSelectedTempChatModel] = useState({})
    const [modelSelectionCallback, setModelSelectionCallback] = useState(null)
    const [loading, setLoading] = useState(false)

    const [promptGeneratorDialogOpen, setPromptGeneratorDialogOpen] = useState(false)
    const [promptGeneratorDialogProps, setPromptGeneratorDialogProps] = useState({})

    const handleDataChange = ({ inputParam, newValue }) => {
        data.inputs[inputParam.name] = newValue
        const allowedShowHideInputTypes = ['boolean', 'asyncOptions', 'asyncMultiOptions', 'options', 'multiOptions']
        if (allowedShowHideInputTypes.includes(inputParam.type)) {
            if (onCustomDataChange) {
                onCustomDataChange({ nodeId: data.id, inputParam, newValue })
            } else {
                onNodeDataChange({ nodeId: data.id, inputParam, newValue })
            }
        }
    }

    const onInputHintDialogClicked = (hint) => {
        const dialogProps = {
            ...hint
        }
        setInputHintDialogProps(dialogProps)
        setShowInputHintDialog(true)
    }

    const onExpandDialogClicked = (value, inputParam, languageType) => {
        const dialogProps = {
            value,
            inputParam,
            disabled,
            languageType,
            nodes: reactFlowInstance?.getNodes() || [],
            edges: reactFlowInstance?.getEdges() || [],
            nodeId: data.id,
            confirmButtonName: 'Save',
            cancelButtonName: 'Cancel'
        }
        if (inputParam.acceptVariable) {
            setExpandRichDialogProps(dialogProps)
            setShowExpandRichDialog(true)
        } else {
            setExpandDialogProps(dialogProps)
            setShowExpandDialog(true)
        }
    }

    const onConditionDialogClicked = (inputParam) => {
        const dialogProps = {
            data,
            inputParam,
            disabled,
            confirmButtonName: 'Save',
            cancelButtonName: 'Cancel'
        }
        setConditionDialogProps(dialogProps)
        setShowConditionDialog(true)
        onHideNodeInfoDialog(true)
    }

    const onShowPromptHubButtonClicked = () => {
        setShowPromptHubDialog(true)
    }

    const onShowPromptHubButtonSubmit = (templates) => {
        setShowPromptHubDialog(false)
        for (const t of templates) {
            if (Object.prototype.hasOwnProperty.call(data.inputs, t.type)) {
                data.inputs[t.type] = t.template
            }
        }
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
        data.inputs.url = url
        data.inputs.selectedLinks = links
    }

    const getJSONValue = (templateValue) => {
        if (!templateValue) return ''
        const obj = {}
        const inputVariables = getInputVariables(templateValue)
        for (const inputVariable of inputVariables) {
            obj[inputVariable] = ''
        }
        if (Object.keys(obj).length) return JSON.stringify(obj)
        return ''
    }

    const getDataGridColDef = (columns, inputParam) => {
        const colDef = []
        for (const column of columns) {
            const stateNode = reactFlowInstance ? reactFlowInstance.getNodes().find((node) => node.data.name === 'seqState') : null
            if (column.type === 'asyncSingleSelect' && column.loadMethod && column.loadMethod.includes('loadStateKeys')) {
                if (stateNode) {
                    const tabParam = stateNode.data.inputParams.find((param) => param.tabIdentifier)
                    if (tabParam && tabParam.tabs.length > 0) {
                        const selectedTabIdentifier = tabParam.tabIdentifier

                        const selectedTab =
                            stateNode.data.inputs[`${selectedTabIdentifier}_${stateNode.data.id}`] ||
                            tabParam.default ||
                            tabParam.tabs[0].name

                        const datagridValues = stateNode.data.inputs[selectedTab]
                        if (datagridValues) {
                            try {
                                const parsedDatagridValues = JSON.parse(datagridValues)
                                const keys = Array.isArray(parsedDatagridValues)
                                    ? parsedDatagridValues.map((item) => item.key)
                                    : Object.keys(parsedDatagridValues)
                                colDef.push({
                                    ...column,
                                    field: column.field,
                                    headerName: column.headerName,
                                    type: 'singleSelect',
                                    editable: true,
                                    valueOptions: keys
                                })
                            } catch (error) {
                                console.error('Error parsing stateMemory', error)
                            }
                        }
                    }
                } else {
                    colDef.push({
                        ...column,
                        field: column.field,
                        headerName: column.headerName,
                        type: 'singleSelect',
                        editable: true,
                        valueOptions: []
                    })
                }
            } else if (column.type === 'freeSolo') {
                const preLoadOptions = []
                if (column.loadMethod && column.loadMethod.includes('getPreviousMessages')) {
                    const nodes = getAvailableNodesForVariable(
                        reactFlowInstance?.getNodes() || [],
                        reactFlowInstance?.getEdges() || [],
                        data.id,
                        inputParam.id
                    )
                    for (const node of nodes) {
                        preLoadOptions.push({
                            value: `$${node.id}`,
                            label: `Output from ${node.data.id}`
                        })
                    }
                }
                if (column.loadMethod && column.loadMethod.includes('loadStateKeys')) {
                    if (stateNode) {
                        const tabParam = stateNode.data.inputParams.find((param) => param.tabIdentifier)
                        if (tabParam && tabParam.tabs.length > 0) {
                            const selectedTabIdentifier = tabParam.tabIdentifier

                            const selectedTab =
                                stateNode.data.inputs[`${selectedTabIdentifier}_${stateNode.data.id}`] ||
                                tabParam.default ||
                                tabParam.tabs[0].name

                            const datagridValues = stateNode.data.inputs[selectedTab]
                            if (datagridValues) {
                                try {
                                    const parsedDatagridValues = JSON.parse(datagridValues)
                                    const keys = Array.isArray(parsedDatagridValues)
                                        ? parsedDatagridValues.map((item) => item.key)
                                        : Object.keys(parsedDatagridValues)
                                    for (const key of keys) {
                                        preLoadOptions.push({
                                            value: `$flow.state.${key}`,
                                            label: `Value from ${key}`
                                        })
                                    }
                                } catch (error) {
                                    console.error('Error parsing stateMemory', error)
                                }
                            }
                        }
                    }
                }
                colDef.push({
                    ...column,
                    field: column.field,
                    headerName: column.headerName,
                    renderEditCell: ({ id, field, value }) => {
                        // eslint-disable-next-line react-hooks/rules-of-hooks
                        const apiRef = useGridApiContext()
                        return (
                            <Autocomplete
                                id={column.field}
                                freeSolo
                                fullWidth
                                options={[...preLoadOptions, ...column.valueOptions]}
                                value={value}
                                PopperComponent={StyledPopper}
                                renderInput={(params) => <TextField {...params} />}
                                renderOption={(props, option) => (
                                    <li {...props}>
                                        <div>
                                            <strong>{option.value}</strong>
                                            <br />
                                            <small>{option.label}</small>
                                        </div>
                                    </li>
                                )}
                                getOptionLabel={(option) => {
                                    return typeof option === 'string' ? option : option.value
                                }}
                                onInputChange={(event, newValue) => {
                                    apiRef.current.setEditCellValue({ id, field, value: newValue })
                                }}
                                sx={{
                                    '& .MuiInputBase-root': {
                                        height: '50px' // Adjust this value as needed
                                    },
                                    '& .MuiOutlinedInput-root': {
                                        border: 'none'
                                    },
                                    '& .MuiOutlinedInput-root .MuiOutlinedInput-notchedOutline': {
                                        border: 'none'
                                    }
                                }}
                            />
                        )
                    }
                })
            } else {
                colDef.push(column)
            }
        }
        return colDef
    }

    const getDropdownOptions = (inputParam) => {
        const preLoadOptions = []
        if (inputParam.loadPreviousNodes) {
            const nodes = getAvailableNodesForVariable(
                reactFlowInstance?.getNodes() || [],
                reactFlowInstance?.getEdges() || [],
                data.id,
                inputParam.id
            )
            for (const node of nodes) {
                preLoadOptions.push({
                    name: `{{ ${node.data.id} }}`,
                    label: `{{ ${node.data.id} }}`,
                    description: `Output from ${node.data.id}`
                })
            }
        }
        return [...preLoadOptions, ...inputParam.options]
    }

    const getTabValue = (inputParam) => {
        return inputParam.tabs.findIndex((item) => item.name === data.inputs[`${inputParam.tabIdentifier}_${data.id}`]) >= 0
            ? inputParam.tabs.findIndex((item) => item.name === data.inputs[`${inputParam.tabIdentifier}_${data.id}`])
            : tabValue
    }

    const onEditJSONClicked = (value, inputParam) => {
        // Preset values if the field is format prompt values
        let inputValue = value
        if (inputParam.name === 'promptValues' && !value) {
            const templateValue =
                (data.inputs['template'] ?? '') +
                (data.inputs['systemMessagePrompt'] ?? '') +
                (data.inputs['humanMessagePrompt'] ?? '') +
                (data.inputs['workerPrompt'] ?? '')
            inputValue = getJSONValue(templateValue)
        }
        const dialogProp = {
            value: inputValue,
            inputParam,
            nodes: reactFlowInstance?.getNodes() || [],
            edges: reactFlowInstance?.getEdges() || [],
            nodeId: data.id,
            data
        }
        setFormatPromptValuesDialogProps(dialogProp)
        setShowFormatPromptValuesDialog(true)
    }

    const onExpandDialogSave = (newValue, inputParamName) => {
        data.inputs[inputParamName] = newValue
        setShowExpandDialog(false)
    }

    const onExpandRichDialogSave = (newValue, inputParamName) => {
        data.inputs[inputParamName] = newValue
        setShowExpandRichDialog(false)
    }

    const onConditionDialogSave = (newData, inputParam, tabValue) => {
        data.inputs[`${inputParam.tabIdentifier}_${data.id}`] = inputParam.tabs[tabValue].name

        const existingEdges = reactFlowInstance?.getEdges().filter((edge) => edge.source === data.id) || []
        const { outputAnchors, toBeRemovedEdgeIds } = getCustomConditionOutputs(
            newData.inputs[inputParam.tabs[tabValue].name],
            data.id,
            existingEdges,
            inputParam.tabs[tabValue].type === 'datagrid'
        )
        if (!outputAnchors) return
        data.outputAnchors = outputAnchors
        for (const edgeId of toBeRemovedEdgeIds) {
            deleteEdge(edgeId)
        }
        setShowConditionDialog(false)
        onHideNodeInfoDialog(false)
    }

    const editAsyncOption = (inputParamName, inputValue) => {
        if (inputParamName === 'selectedTool') {
            setAsyncOptionEditDialogProps({
                title: 'Edit Tool',
                type: 'EDIT',
                cancelButtonName: 'Cancel',
                confirmButtonName: 'Save',
                toolId: inputValue
            })
        } else if (inputParamName === 'selectedAssistant') {
            setAsyncOptionEditDialogProps({
                title: 'Edit Assistant',
                type: 'EDIT',
                cancelButtonName: 'Cancel',
                confirmButtonName: 'Save',
                assistantId: inputValue
            })
        }
        setAsyncOptionEditDialog(inputParamName)
    }

    const addAsyncOption = (inputParamName) => {
        if (inputParamName === 'selectedTool') {
            setAsyncOptionEditDialogProps({
                title: 'Add New Tool',
                type: 'ADD',
                cancelButtonName: 'Cancel',
                confirmButtonName: 'Add'
            })
        } else if (inputParamName === 'selectedAssistant') {
            setAsyncOptionEditDialogProps({
                title: 'Add New Assistant',
                type: 'ADD',
                cancelButtonName: 'Cancel',
                confirmButtonName: 'Add'
            })
        }
        setAsyncOptionEditDialog(inputParamName)
    }

    const onConfirmAsyncOption = (selectedOptionId = '') => {
        if (!selectedOptionId) {
            data.inputs[showAsyncOptionDialog] = ''
            handleDataChange({ inputParam: { name: showAsyncOptionDialog }, newValue: '' })
        } else {
            data.inputs[showAsyncOptionDialog] = selectedOptionId
            handleDataChange({ inputParam: { name: showAsyncOptionDialog }, newValue: selectedOptionId })
            setReloadTimestamp(Date.now().toString())
        }
        setAsyncOptionEditDialogProps({})
        setAsyncOptionEditDialog('')
    }

    const handleNvidiaNIMDialogComplete = (containerData) => {
        if (containerData) {
            data.inputs['basePath'] = containerData.baseUrl
            data.inputs['modelName'] = containerData.image
        }
    }

    const loadChatModels = async () => {
        try {
            const resp = await assistantsApi.getChatModels()
            if (resp.data) {
                const chatModels = resp.data ?? []
                const chatModelsOptions = chatModels.map((model) => ({
                    name: model.name,
                    label: model.label,
                    description: model.description,
                    imageSrc: `${baseURL}/api/v1/node-icon/${model.name}`
                }))
                setAvailableChatModels(chatModels)
                setAvailableChatModelsOptions(chatModelsOptions)
            }
        } catch (error) {
            console.error('Error loading chat models:', error)
        }
    }

    const checkInputParamsMandatory = () => {
        let canSubmit = true

        if (selectedTempChatModel && Object.keys(selectedTempChatModel).length > 0) {
            const inputParams = (selectedTempChatModel.inputParams ?? []).filter((inputParam) => !inputParam.hidden)
            for (const inputParam of inputParams) {
                if (!inputParam.optional && (!selectedTempChatModel.inputs[inputParam.name] || !selectedTempChatModel.credential)) {
                    if (inputParam.type === 'credential' && !selectedTempChatModel.credential) {
                        canSubmit = false
                        break
                    } else if (inputParam.type !== 'credential' && !selectedTempChatModel.inputs[inputParam.name]) {
                        canSubmit = false
                        break
                    }
                }
            }
        }

        return canSubmit
    }

    const displayWarning = () => {
        enqueueSnackbar({
            message: 'Please fill in all mandatory fields.',
            options: {
                key: new Date().getTime() + Math.random(),
                variant: 'warning',
                action: (key) => (
                    <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                        <IconX />
                    </Button>
                )
            }
        })
    }

    const generateDocStoreToolDesc = async (storeId) => {
        if (!storeId) {
            enqueueSnackbar({
                message: 'Please select a knowledge base',
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }
        // Sanitize storeId: strip non-alphanumeric/dash/underscore after splitting
        const rawStoreId = storeId.split(':')[0]
        const sanitizedStoreId = sanitizeStoreId(rawStoreId)
        if (!sanitizedStoreId) {
            enqueueSnackbar({
                message: 'Invalid knowledge base identifier.',
                options: {
                    key: new Date().getTime() + Math.random(),
                    variant: 'error',
                    action: (key) => (
                        <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                            <IconX />
                        </Button>
                    )
                }
            })
            return
        }

        const isValid = checkInputParamsMandatory()
        if (!isValid) {
            displayWarning()
            return
        }

        // Check if model is already selected in the node
        const currentNode = reactFlowInstance?.getNodes().find((node) => node.id === data.id)
        const currentNodeInputs = currentNode?.data?.inputs

        const existingModel = currentNodeInputs?.llmModel || currentNodeInputs?.agentModel || currentNodeInputs?.humanInputModel
        if (existingModel) {
            try {
                setLoading(true)
                const selectedChatModelObj = {
                    name: existingModel,
                    inputs:
                        currentNodeInputs?.llmModelConfig || currentNodeInputs?.agentModelConfig || currentNodeInputs?.humanInputModelConfig
                }
                // Validate selectedChatModelObj before sending
                if (!validateChatModelObj(selectedChatModelObj)) {
                    setLoading(false)
                    enqueueSnackbar({
                        message: 'Invalid model configuration.',
                        options: {
                            key: new Date().getTime() + Math.random(),
                            variant: 'error',
                            action: (key) => (
                                <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                    <IconX />
                                </Button>
                            )
                        }
                    })
                    return
                }
                const resp = await documentstoreApi.generateDocStoreToolDesc(sanitizedStoreId, { selectedChatModel: selectedChatModelObj })
                if (resp.data) {
                    setLoading(false)
                    const rawContent = resp.data?.content || resp.data.kwargs?.content
                    // Sanitize LLM output before assigning
                    const content = sanitizeLLMOutput(rawContent)
                    // Update the input value directly
                    data.inputs[inputParam.name] = content
                    enqueueSnackbar({
                        message: 'Document Store Tool Description generated successfully',
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
            } catch (error) {
                console.error('Error generating doc store tool desc', error)
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
            return
        }

        // If no model selected, load chat models and open model selection dialog
        await loadChatModels()
        setModelSelectionCallback(() => async (selectedModel) => {
            // Validate selectedModel before sending
            if (!validateChatModelObj(selectedModel)) {
                enqueueSnackbar({
                    message: 'Invalid model configuration.',
                    options: {
                        key: new Date().getTime() + Math.random(),
                        variant: 'error',
                        action: (key) => (
                            <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                <IconX />
                            </Button>
                        )
                    }
                })
                return
            }
            try {
                setLoading(true)
                const selectedChatModelObj = {
                    name: selectedModel.name,
                    inputs: selectedModel.inputs
                }
                const resp = await documentstoreApi.generateDocStoreToolDesc(sanitizedStoreId, { selectedChatModel: selectedChatModelObj })
                if (resp.data) {
                    setLoading(false)
                    const rawContent = resp.data?.content || resp.data.kwargs?.content
                    // Sanitize LLM output before assigning
                    const content = sanitizeLLMOutput(rawContent)
                    // Update the input value directly
                    data.inputs[inputParam.name] = content
                    enqueueSnackbar({
                        message: 'Document Store Tool Description generated successfully',
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
            } catch (error) {
                console.error('Error generating doc store tool desc', error)
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
        })
        setModelSelectionDialogOpen(true)
    }

    const generateInstruction = async () => {
        const isValid = checkInputParamsMandatory()
        if (!isValid) {
            displayWarning()
            return
        }

        const currentNode = reactFlowInstance?.getNodes().find((node) => node.id === data.id)
        const currentNodeInputs = currentNode?.data?.inputs

        // Check if model is already selected in the node
        const existingModel = currentNodeInputs?.llmModel || currentNodeInputs?.agentModel || currentNodeInputs?.humanInputModel
        if (existingModel) {
            // Open prompt generator dialog directly with existing model
            setPromptGeneratorDialogProps({
                title: 'Generate Instructions',
                description: 'You can generate a prompt template by sharing basic details about your task.',
                data: {
                    selectedChatModel: {
                        name: existingModel,
                        inputs:
                            currentNodeInputs?.llmModelConfig ||
                            currentNodeInputs?.agentModelConfig ||
                            currentNodeInputs?.humanInputModelConfig
                    }
                }
            })
            setPromptGeneratorDialogOpen(true)
            return
        }

        // If no model selected, load chat models and open model selection dialog
        await loadChatModels()
        setModelSelectionCallback(() => async (selectedModel) => {
            // Validate selectedModel before using
            if (!validateChatModelObj(selectedModel)) {
                enqueueSnackbar({
                    message: 'Invalid model configuration.',
                    options: {
                        key: new Date().getTime() + Math.random(),
                        variant: 'error',
                        action: (key) => (
                            <Button style={{ color: 'white' }} onClick={() => closeSnackbar(key)}>
                                <IconX />
                            </Button>
                        )
                    }
                })
                return
            }
            // After model selection, open prompt generator dialog
            setPromptGeneratorDialogProps({
                title: 'Generate Instructions',
                description: 'You can generate a prompt template by sharing basic details about your task.',
                data: { selectedChatModel: selectedModel }
            })
            setPromptGeneratorDialogOpen(true)
        })
        setModelSelectionDialogOpen(true)
    }

    useEffect(() => {
        if (ref.current && ref.current.offsetTop && ref.current.clientHeight) {
            setPosition(ref.current.offsetTop + ref.current.clientHeight / 2)
            updateNodeInternals(data.id)
        }
    }, [data.id, ref, updateNodeInternals])

    useEffect(() => {
        updateNodeInternals(data.id)
    }, [data.id, position, updateNodeInternals])

    return (
        <div ref={ref}>
            {inputAnchor && (
                <>
                    <CustomWidthTooltip placement='left' title={inputAnchor.type}>
                        <Handle
                            type='target'
                            position={Position.Left}
                            key={inputAnchor.id}
                            id={inputAnchor.id}
                            isValidConnection={(connection) => isValidConnection(connection, reactFlowInstance)}
                            style={{
                                height: 10,
                                width: 10,
                                backgroundColor: data.selected ? theme.palette.primary.main : theme.palette.text.secondary,
                                top: position
                            }}
                        />
                    </CustomWidthTooltip>
                    <Box sx={{ p: 2 }}>
                        <Typography>
                            {inputAnchor.label}
                            {!inputAnchor.optional && <span style={{ color: 'red' }}>&nbsp;*</span>}
                            {inputAnchor.description && <TooltipWithParser style={{ marginLeft: 10 }} title={inputAnchor.description} />}
                        </Typography>
                    </Box>
                </>
            )}

            {((inputParam && !inputParam.additionalParams) || isAdditionalParams) && (
                <>
                    {inputParam.acceptVariable && !isAdditionalParams && (
                        <CustomWidthTooltip placement='left' title={inputParam.type}>
                            <Handle
                                type='target'
                                position={Position.Left}
                                key={inputParam.id}
                                id={inputParam.id}
                                isValidConnection={(connection) => isValidConnection(connection, reactFlowInstance)}
                                style={{
                                    height: 10,
                                    width: 10,
                                    backgroundColor: data.selected ? theme.palette.primary.main : theme.palette.text.secondary,
                                    top: position
                                }}
                            />
                        </CustomWidthTooltip>
                    )}
                    <Box sx={{ p: disablePadding ? 0 : 2 }}>
                        {(data.name === 'promptTemplate' || data.name === 'chatPromptTemplate') &&
                            (inputParam.name === 'template' || inputParam.name === 'systemMessagePrompt') && (
                                <>
                                    <Button
                                        style={{
                                            display: 'flex',
                                            flexDirection: 'row',
                                            width: '100%'
                                        }}
                                        disabled={disabled}
                                        sx={{ borderRadius: 25, width: '100%', mb: 2, mt: 0 }}
                                        variant='outlined'
                                        onClick={() => onShowPromptHubButtonClicked()}
                                        endIcon={<IconAutoFixHigh />}
                                    >
                                        Langchain Hub
                                    </Button>
                                    <PromptLangsmithHubDialog
                                        promptType={inputParam.name}
                                        show={showPromptHubDialog}
                                        onCancel={() => setShowPromptHubDialog(false)}
                                        onSubmit={onShowPromptHubButtonSubmit}
                                    ></PromptLangsmithHubDialog>
                                </>
                            )}
                        {data.name === 'chatNvidiaNIM' && inputParam.name === 'modelName' && (
                            <>
                                <Button
                                    style={{
                                        display: 'flex',
                                        flexDirection: 'row',
                                        width: '100%'
                                    }}
                                    sx={{ borderRadius: '12px', width: '100%', mb: 2, mt: -1 }}
                                    variant='outlined'
                                    onClick={() => setIsNvidiaNIMDialogOpen(true)}
                                >
                                    Setup NIM Locally
                                </Button>
                            </>
                        )}
                        <div style={{ display: 'flex', flexDirection: 'row', alignItems: 'center' }}>
                            <Typography>
                                {inputParam.label}
                                {!inputParam.optional && <span style={{ color: 'red' }}>&nbsp;*</span>}
                                {inputParam.description && <TooltipWithParser style={{ marginLeft: 10 }} title={inputParam.description} />}
                            </Typography>
                            <div style={{ flexGrow: 1 }}></div>
                            {inputParam.hint && !isAdditionalParams && (
                                <IconButton
                                    size='small'
                                    sx={{
                                        height: 25,
                                        width: 25
                                    }}
                                    title={inputParam.hint.label}
                                    color='secondary'
                                    onClick={() => onInputHintDialogClicked(inputParam.hint)}
                                >
                                    <IconBulb />
                                </IconButton>
                            )}
                            {inputParam.hint && isAdditionalParams && (
                                <Button
                                    sx={{ p: 0, px: 2 }}
                                    color='secondary'
                                    variant='text'
                                    onClick={() => {
                                        onInputHintDialogClicked(inputParam.hint)
                                    }}
                                    startIcon={<IconBulb size={17} />}
                                >
                                    {inputParam.hint.label}
                                </Button>
                            )}
                            {inputParam.acceptVariable && inputParam.type === 'string' && (
                                <Tooltip title='Type {{ to select variables'>
                                    <IconVariable size={20} style={{ color: 'teal' }} />
                                </Tooltip>
                            )}
                            {inputParam.generateDocStoreDescription && (
                                <IconButton
                                    title='Generate knowledge base description'
                                    sx={{
                                        height: 25,
                                        width: 25
                                    }}
                                    size='small'
                                    color='secondary'
                                    onClick={() => generateDocStoreToolDesc(data.inputs['documentStore'])}
                                >
                                    <IconWand />
                                </IconButton>
                            )}
                            {inputParam.generateInstruction && (
                                <IconButton
                                    title='Generate instructions'
                                    sx={{
                                        height: 25,
                                        width: 25,
                                        ml: 0.5
                                    }}
                                    size='small'
                                    color='secondary'
                                    onClick={() => generateInstruction()}
                                >
                                    <IconWand />
                                </IconButton>
                            )}
                            {((inputParam.type === 'string' && inputParam.rows) || inputParam.type === 'code') && (
                                <IconButton
                                    size='small'
                                    sx={{
                                        height: 25,
                                        width: 25,
                                        ml: 0.5
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
                                <span style={{ color: 'rgb(116,66,16)', marginLeft: 10 }}>{parser(inputParam.warning)}</span>
                            </div>
                        )}
                        {inputParam.type === 'credential' && (
                            <CredentialInputHandler
                                disabled={disabled}
                                data={data}
                                inputParam={inputParam}
                                onSelect={(newValue) => {
                                    data.credential = newValue
                                    data.inputs[FLOWISE_CREDENTIAL_ID] = newValue // in case data.credential is not updated
                                }}
                            />
                        )}
                        {inputParam.type === 'tabs' && (
                            <>
                                <Tabs
                                    value={getTabValue(inputParam)}
                                    onChange={(event, val) => {
                                        setTabValue(val)
                                        data.inputs[`${inputParam.tabIdentifier}_${data.id}`] = inputParam.tabs[val].name
                                    }}
                                    aria-label='tabs'
                                    variant='fullWidth'
                                    defaultValue={getTabValue(inputParam)}
                                >
                                    <TabsList>
                                        {inputParam.tabs.map((inputChildParam, index) => (
                                            <Tab key={index}>{inputChildParam.label}</Tab>
                                        ))}
                                    </TabsList>
                                </Tabs>
                                {inputParam.tabs
                                    .filter((inputParam) => inputParam.display !== false)
                                    .map((inputChildParam, index) => (
                                        <TabPanel key={index} value={getTabValue(inputParam)} index={index}>
                                            <NodeInputHandler
                                                disabled={inputChildParam.disabled}
                                                inputParam={inputChildParam}
                                                data={data}
                                                isAdditionalParams={true}
                                                disablePadding={true}
                                            />
                                        </TabPanel>
                                    ))}
                            </>
                        )}
                        {inputParam.type === 'file' && (
                            <File
                                disabled={disabled}
                                fileType={inputParam.fileType || '*'}
                                onChange={(newValue) => {
                                    // Validate and sanitize file value for prompt injection, PII, and Singapore PII
                                    const { valid, sanitizedValue, reason } = validateAndSanitizeFileValue(newValue)
                                    if (!valid) {
                                        enqueueSnackbar({
                                            message: reason || 'The uploaded file contains disallowed content and cannot be accepted.',
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
                                    data.inputs[inputParam.name] = sanitizedValue
                                }}
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
                                columns={getDataGridColDef(inputParam.datagrid, inputParam)}
                                hideFooter={true}
                                rows={data.inputs[inputParam.name] ?? JSON.stringify(inputParam.default) ?? []}
                                onChange={(newValue) => (data.inputs[inputParam.name] = newValue)}
                            />
                        )}
                        {inputParam.type === 'code' && (
                            <>
                                <div style={{ display: 'flex', flexDirection: 'row', justifyContent: 'flex-start' }}>
                                    {inputParam.codeExample && (
                                        <Button
                                            variant='outlined'
                                            onClick={() => {
                                                data.inputs[inputParam.name] = inputParam.codeExample
                                                setReloadTimestamp(Date.now().toString())
                                            }}
                                        >
                                            See Example
                                        </Button>
                                    )}
                                </div>
                                <div
                                    key={`${reloadTimestamp}_${data.id}}`}
                                    style={{
                                        marginTop: '10px',
                                        border: '1px solid',
                                        borderColor: theme.palette.grey[900] + 25,
                                        borderRadius: '6px',
                                        height: inputParam.rows ? '100px' : '200px'
                                    }}
                                >
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

                        {(inputParam.type === 'string' || inputParam.type === 'password' || inputParam.type === 'number') &&
                            (inputParam?.acceptVariable &&
                            (window.location.href.includes('v2/agentcanvas') || window.location.href.includes('v2/marketplace')) ? (
                                <RichInput
                                    key={data.inputs[inputParam.name]}
                                    placeholder={inputParam.placeholder}
                                    disabled={disabled}
                                    inputParam={inputParam}
                                    onChange={(newValue) => (data.inputs[inputParam.name] = newValue)}
                                    value={data.inputs[inputParam.name] ?? inputParam.default ?? ''}
                                    nodes={reactFlowInstance ? reactFlowInstance.getNodes() : []}
                                    edges={reactFlowInstance ? reactFlowInstance.getEdges() : []}
                                    nodeId={data.id}
                                />
                            ) : (
                                <Input
                                    key={data.inputs[inputParam.name]}
                                    placeholder={inputParam.placeholder}
                                    disabled={disabled}
                                    inputParam={inputParam}
                                    onChange={(newValue) => (data.inputs[inputParam.name] = newValue)}
                                    value={data.inputs[inputParam.name] ?? inputParam.default ?? ''}
                                    nodes={[]}
                                    edges={[]}
                                    nodeId={data.id}
                                />
                            ))}
                        {inputParam.type === 'json' && (
                            <>
                                {!inputParam?.acceptVariable && (
                                    <JsonEditorInput
                                        disabled={disabled}
                                        onChange={(newValue) => (data.inputs[inputParam.name] = newValue)}
                                        value={
                                            data.inputs[inputParam.name] ||
                                            inputParam.default ||
                                            getJSONValue(data.inputs['workerPrompt']) ||
                                            ''
                                        }
                                        isSequentialAgent={data.category === 'Sequential Agents'}
                                        isDarkMode={customization.isDarkMode}
                                    />
                                )}
                                {inputParam?.acceptVariable && (
                                    <>
                                        <Button
                                            sx={{
                                                borderRadius: 25,
                                                width: '100%',
                                                mb: 0,
                                                mt: 2
                                            }}
                                            variant='outlined'
                                            disabled={disabled}
                                            onClick={() => onEditJSONClicked(data.inputs[inputParam.name] ?? '', inputParam)}
                                        >
                                            {inputParam.label}
                                        </Button>
                                        <FormatPromptValuesDialog
                                            show={showFormatPromptValuesDialog}
                                            dialogProps={formatPromptValuesDialogProps}
                                            onCancel={() => setShowFormatPromptValuesDialog(false)}
                                            onChange={(newValue) => (data.inputs[inputParam.name] = newValue)}
                                        ></FormatPromptValuesDialog>
                                    </>
                                )}
                            </>
                        )}
                        {inputParam.type === 'options' && (
                            <div key={`${data.id}_${JSON.stringify(data.inputs[inputParam.name])}`}>
                                <Dropdown
                                    disabled={disabled}
                                    name={inputParam.name}
                                    options={getDropdownOptions(inputParam)}
                                    freeSolo={inputParam.freeSolo}
                                    onSelect={(newValue) => handleDataChange({ inputParam, newValue })}
                                    value={data.inputs[inputParam.name] ?? inputParam.default ?? 'choose an option'}
                                />
                            </div>
                        )}
                        {inputParam.type === 'multiOptions' && (
                            <div key={`${data.id}_${JSON.stringify(data.inputs[inputParam.name])}`}>
                                <MultiDropdown
                                    disabled={disabled}
                                    name={inputParam.name}
                                    options={getDropdownOptions(inputParam)}
                                    onSelect={(newValue) => handleDataChange({ inputParam, newValue })}
                                    value={data.inputs[
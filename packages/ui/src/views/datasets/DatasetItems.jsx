import { useEffect, useRef, useState } from 'react'
import React from 'react'
import { useDispatch, useSelector } from 'react-redux'

// material-ui
import {
    Checkbox,
    Skeleton,
    Box,
    TableRow,
    TableContainer,
    Paper,
    Table,
    TableHead,
    TableBody,
    Button,
    Stack,
    Typography
} from '@mui/material'
import { useTheme } from '@mui/material/styles'

// project imports
import MainCard from '@/ui-component/cards/MainCard'
import { StyledTableCell, StyledTableRow } from '@/ui-component/table/TableStyles'
import ConfirmDialog from '@/ui-component/dialog/ConfirmDialog'
import AddEditDatasetRowDialog from './AddEditDatasetRowDialog'
import UploadCSVFileDialog from '@/views/datasets/UploadCSVFileDialog'
import ErrorBoundary from '@/ErrorBoundary'
import { useError } from '@/store/context/ErrorContext'
import ViewHeader from '@/layout/MainLayout/ViewHeader'
import { PermissionButton, StyledPermissionButton } from '@/ui-component/button/RBACButtons'
import AddEditDatasetDialog from '@/views/datasets/AddEditDatasetDialog'
import TablePagination, { DEFAULT_ITEMS_PER_PAGE } from '@/ui-component/pagination/TablePagination'

// API
import datasetsApi from '@/api/dataset'

// Hooks
import useApi from '@/hooks/useApi'
import { closeSnackbar as closeSnackbarAction, enqueueSnackbar as enqueueSnackbarAction } from '@/store/actions'
import useNotifier from '@/utils/useNotifier'
import useConfirm from '@/hooks/useConfirm'
import { useAuth } from '@/hooks/useAuth'

// icons
import empty_datasetSVG from '@/assets/images/empty_datasets.svg'
import { IconTrash, IconPlus, IconX, IconUpload, IconArrowsDownUp } from '@tabler/icons-react'
import DragIndicatorIcon from '@mui/icons-material/DragIndicator'

// ==============================|| CSV Security & PII Utilities ||============================== //

/**
 * Validates CSV content for hidden prompts, base64-encoded content,
 * invisible characters, leetspeak, and shell/binary commands.
 * Returns { valid: boolean, reason: string }
 */
const validateCSVContent = (csvText) => {
    if (!csvText || typeof csvText !== 'string') {
        return { valid: false, reason: 'Invalid or empty CSV content.' }
    }

    // Check for invisible / zero-width characters
    const invisibleCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/
    if (invisibleCharsPattern.test(csvText)) {
        return { valid: false, reason: 'CSV contains invisible or zero-width characters that may indicate hidden prompt injection.' }
    }

    // Check for base64-encoded content (long base64 strings)
    const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/
    if (base64Pattern.test(csvText)) {
        return { valid: false, reason: 'CSV contains potentially base64-encoded content.' }
    }

    // Check for shell/binary commands
    const shellCommandPattern = /(\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess|os\.system|rm\s+-rf|wget|curl|chmod|chown|sudo|su\s+|nc\s+|netcat|ncat|python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r)\b)/i
    if (shellCommandPattern.test(csvText)) {
        return { valid: false, reason: 'CSV contains shell or binary command patterns.' }
    }

    // Check for prompt injection patterns
    const promptInjectionPattern = /(ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)|you\s+are\s+now|act\s+as\s+|pretend\s+(you\s+are|to\s+be)|disregard\s+(all|previous)|system\s*:\s*|<\s*system\s*>|<\s*\/\s*system\s*>|\[INST\]|\[\/INST\]|###\s*instruction|###\s*system)/i
    if (promptInjectionPattern.test(csvText)) {
        return { valid: false, reason: 'CSV contains potential prompt injection patterns.' }
    }

    // Check for leetspeak patterns that may obfuscate malicious content
    const leetspeakPattern = /(\b[a-z]*[013457@$!][a-z0-9@$!]{3,}\b)/i
    const leetspeakMatches = csvText.match(new RegExp(leetspeakPattern, 'gi')) || []
    if (leetspeakMatches.length > 10) {
        return { valid: false, reason: 'CSV contains excessive leetspeak patterns that may indicate obfuscated content.' }
    }

    return { valid: true, reason: '' }
}

/**
 * Redacts common PII patterns from a string.
 * Covers: email, phone, SSN, credit card numbers.
 */
const redactGeneralPII = (text) => {
    if (!text || typeof text !== 'string') return text

    // Redact email addresses
    let redacted = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')

    // Redact US/international phone numbers
    redacted = redacted.replace(/(\+?[\d\s\-().]{7,15}\d)/g, (match) => {
        const digitsOnly = match.replace(/\D/g, '')
        if (digitsOnly.length >= 7 && digitsOnly.length <= 15) {
            return '[REDACTED_PHONE]'
        }
        return match
    })

    // Redact SSNs (US format: XXX-XX-XXXX)
    redacted = redacted.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, '[REDACTED_SSN]')

    // Redact credit card numbers (13-19 digit sequences)
    redacted = redacted.replace(/\b(?:\d[ \-]?){13,19}\b/g, '[REDACTED_CC]')

    return redacted
}

/**
 * Detects Singapore-specific PII: NRIC, FIN, SingPass identifiers.
 * Returns { hasPII: boolean, types: string[] }
 */
const detectSingaporePII = (text) => {
    if (!text || typeof text !== 'string') return { hasPII: false, types: [] }

    const detectedTypes = []

    // Singapore NRIC: S/T followed by 7 digits and a letter (e.g., S1234567D)
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/i
    if (nricPattern.test(text)) {
        detectedTypes.push('NRIC')
    }

    // Singapore FIN: F/G followed by 7 digits and a letter
    const finPattern = /\b[FG]\d{7}[A-Z]\b/i
    if (finPattern.test(text)) {
        if (!detectedTypes.includes('FIN')) detectedTypes.push('FIN')
    }

    // SingPass identifier patterns (common formats)
    const singpassPattern = /\bsingpass\b/i
    if (singpassPattern.test(text)) {
        detectedTypes.push('SingPass identifier')
    }

    // Singapore phone numbers (+65 XXXX XXXX)
    const sgPhonePattern = /(\+65[\s\-]?[689]\d{3}[\s\-]?\d{4}|\b[689]\d{7}\b)/
    if (sgPhonePattern.test(text)) {
        detectedTypes.push('Singapore phone number')
    }

    // Singapore postal code (6 digits starting with valid prefix)
    const sgPostalPattern = /\b(0[1-9]|[1-7]\d|8[0-8])\d{4}\b/
    if (sgPostalPattern.test(text)) {
        detectedTypes.push('Singapore postal code')
    }

    return {
        hasPII: detectedTypes.length > 0,
        types: detectedTypes
    }
}

/**
 * Redacts Singapore-specific PII from a string.
 */
const redactSingaporePII = (text) => {
    if (!text || typeof text !== 'string') return text

    // Redact NRIC/FIN
    let redacted = text.replace(/\b[STFG]\d{7}[A-Z]\b/gi, '[REDACTED_NRIC_FIN]')

    // Redact Singapore phone numbers
    redacted = redacted.replace(/(\+65[\s\-]?[689]\d{3}[\s\-]?\d{4}|\b[689]\d{7}\b)/g, '[REDACTED_SG_PHONE]')

    return redacted
}

/**
 * Full CSV content security and PII scan + redaction pipeline.
 * Returns { valid: boolean, reason: string, sanitizedContent: string }
 */
const sanitizeAndValidateCSV = (csvText) => {
    // Step 1: Validate for malicious content
    const validationResult = validateCSVContent(csvText)
    if (!validationResult.valid) {
        return { valid: false, reason: validationResult.reason, sanitizedContent: null }
    }

    // Step 2: Check for Singapore PII
    const sgPIIResult = detectSingaporePII(csvText)
    if (sgPIIResult.hasPII) {
        return {
            valid: false,
            reason: `CSV contains Singapore PII (${sgPIIResult.types.join(', ')}). Please remove this information before uploading.`,
            sanitizedContent: null
        }
    }

    // Step 3: Redact general PII
    let sanitized = redactGeneralPII(csvText)

    // Step 4: Redact Singapore PII (belt-and-suspenders)
    sanitized = redactSingaporePII(sanitized)

    return { valid: true, reason: '', sanitizedContent: sanitized }
}

// ==============================|| Dataset Items ||============================== //

const EvalDatasetRows = () => {
    const theme = useTheme()
    const customization = useSelector((state) => state.customization)
    const dispatch = useDispatch()
    useNotifier()
    const { error } = useError()

    const [showRowDialog, setShowRowDialog] = useState(false)
    const [showUploadDialog, setShowUploadDialog] = useState(false)
    const [rowDialogProps, setRowDialogProps] = useState({})
    const [showDatasetDialog, setShowDatasetDialog] = useState(false)
    const [datasetDialogProps, setDatasetDialogProps] = useState({})

    const [dataset, setDataset] = useState([])
    const [isLoading, setLoading] = useState(true)
    const [selected, setSelected] = useState([])

    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    const { confirm } = useConfirm()

    const getDatasetRows = useApi(datasetsApi.getDataset)
    const reorderDatasetRowApi = useApi(datasetsApi.reorderDatasetRow)

    const URLpath = document.location.pathname.toString().split('/')
    const datasetId = URLpath[URLpath.length - 1] === 'dataset_rows' ? '' : URLpath[URLpath.length - 1]

    const { hasPermission } = useAuth()

    const draggingItem = useRef()
    const dragOverItem = useRef()
    const [Draggable, setDraggable] = useState(false)
    const [startDragPos, setStartDragPos] = useState(-1)
    const [endDragPos, setEndDragPos] = useState(-1)

    /* Table Pagination */
    const [currentPage, setCurrentPage] = useState(1)
    const [pageLimit, setPageLimit] = useState(DEFAULT_ITEMS_PER_PAGE)
    const [total, setTotal] = useState(0)
    const onChange = (page, pageLimit) => {
        setCurrentPage(page)
        setPageLimit(pageLimit)
        refresh(page, pageLimit)
    }

    const refresh = (page, limit) => {
        setLoading(true)
        const params = {
            page: page || currentPage,
            limit: limit || pageLimit
        }
        getDatasetRows.request(datasetId, params)
    }

    const handleDragStart = (e, position) => {
        draggingItem.current = position
        setStartDragPos(position)
        setEndDragPos(-1)
    }
    const handleDragEnter = (e, position) => {
        setEndDragPos(position)
        dragOverItem.current = position
    }

    const handleDragEnd = (e, position) => {
        dragOverItem.current = position
        const updatedDataset = { ...dataset }
        updatedDataset.rows.splice(endDragPos, 0, dataset.rows.splice(startDragPos, 1)[0])
        setDataset({ ...updatedDataset })
        e.preventDefault()
        const updatedRows = []

        dataset.rows.map((item, index) => {
            updatedRows.push({
                id: item.id,
                sequenceNo: index
            })
        })
        reorderDatasetRowApi.request({ datasetId: datasetId, rows: updatedRows })
    }

    const onSelectAllClick = (event) => {
        if (event.target.checked) {
            const newSelected = (dataset?.rows || []).map((n) => n.id)
            setSelected(newSelected)
            return
        }
        setSelected([])
    }

    const handleSelect = (event, id) => {
        const selectedIndex = selected.indexOf(id)
        let newSelected = []

        if (selectedIndex === -1) {
            newSelected = newSelected.concat(selected, id)
        } else if (selectedIndex === 0) {
            newSelected = newSelected.concat(selected.slice(1))
        } else if (selectedIndex === selected.length - 1) {
            newSelected = newSelected.concat(selected.slice(0, -1))
        } else if (selectedIndex > 0) {
            newSelected = newSelected.concat(selected.slice(0, selectedIndex), selected.slice(selectedIndex + 1))
        }
        setSelected(newSelected)
    }

    const addNew = () => {
        const dialogProp = {
            type: 'ADD',
            cancelButtonName: 'Cancel',
            confirmButtonName: 'Add',
            data: {
                datasetId: datasetId,
                datasetName: dataset.name
            }
        }
        setRowDialogProps(dialogProp)
        setShowRowDialog(true)
    }

    /**
     * onBeforeConfirm validator for the UploadCSVFileDialog.
     * Receives the raw CSV text content from the dialog before submission.
     * Returns { valid: boolean, reason: string, sanitizedContent: string|null }
     */
    const onBeforeCSVConfirm = (csvText) => {
        return sanitizeAndValidateCSV(csvText)
    }

    /**
     * Wrapped onConfirm for the UploadCSVFileDialog that intercepts
     * the uploaded data rows, scans and redacts PII, and blocks submission
     * if Singapore PII or malicious content is detected.
     */
    const onUploadConfirm = (csvText) => {
        if (csvText && typeof csvText === 'string') {
            const result = sanitizeAndValidateCSV(csvText)
            if (!result.valid) {
                enqueueSnackbar({
                    message: `Upload blocked: ${result.reason}`,
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
                return false
            }
        }
        onConfirm()
        return true
    }

    const uploadCSV = () => {
        const dialogProp = {
            type: 'ADD',
            cancelButtonName: 'Cancel',
            confirmButtonName: 'Upload',
            data: {
                datasetId: datasetId,
                datasetName: dataset.name
            },
            onBeforeConfirm: onBeforeCSVConfirm
        }
        setRowDialogProps(dialogProp)
        setShowUploadDialog(true)
    }

    const editDs = () => {
        const dialogProp = {
            type: 'EDIT',
            cancelButtonName: 'Cancel',
            confirmButtonName: 'Save',
            data: dataset
        }
        setDatasetDialogProps(dialogProp)
        setShowDatasetDialog(true)
    }

    const edit = (item) => {
        const dialogProp = {
            type: 'EDIT',
            cancelButtonName: 'Cancel',
            confirmButtonName: 'Save',
            data: {
                datasetName: dataset.name,
                ...item
            }
        }
        setRowDialogProps(dialogProp)
        setShowRowDialog(true)
    }

    const deleteDatasetItems = async () => {
        const confirmPayload = {
            title: `Delete`,
            description: `Delete ${selected.length} dataset items?`,
            confirmButtonName: 'Delete',
            cancelButtonName: 'Cancel'
        }
        const isConfirmed = await confirm(confirmPayload)

        if (isConfirmed) {
            try {
                const deleteResp = await datasetsApi.deleteDatasetItems(selected)
                if (deleteResp.data) {
                    enqueueSnackbar({
                        message: 'Dataset Items deleted',
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
                    onConfirm()
                }
            } catch (error) {
                enqueueSnackbar({
                    message: `Failed to delete dataset items: ${
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
            }
            setSelected([])
        }
    }

    const onConfirm = () => {
        setShowRowDialog(false)
        setShowUploadDialog(false)
        setShowDatasetDialog(false)
        refresh(currentPage, pageLimit)
    }

    useEffect(() => {
        refresh(currentPage, pageLimit)
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    useEffect(() => {
        if (getDatasetRows.data) {
            const dataset = getDatasetRows.data
            setDataset(dataset)
            setTotal(dataset.total)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [getDatasetRows.data])

    useEffect(() => {
        setLoading(getDatasetRows.loading)
    }, [getDatasetRows.loading])

    return (
        <>
            <MainCard>
                {error ? (
                    <ErrorBoundary error={error} />
                ) : (
                    <Stack flexDirection='column' sx={{ gap: 3 }}>
                        <ViewHeader
                            isBackButton={true}
                            isEditButton={hasPermission('datasets:create,datasets:update')}
                            onEdit={editDs}
                            onBack={() => window.history.back()}
                            search={false}
                            title={`Dataset : ${dataset?.name || ''}`}
                            description={dataset?.description}
                        >
                            <StyledPermissionButton
                                permissionId={'datasets:create,datasets:update'}
                                variant='outlined'
                                color='secondary'
                                sx={{ borderRadius: 2, height: '100%' }}
                                onClick={uploadCSV}
                                startIcon={<IconUpload />}
                            >
                                Upload CSV
                            </StyledPermissionButton>
                            <StyledPermissionButton
                                permissionId={'datasets:create,datasets:update'}
                                variant='contained'
                                sx={{ borderRadius: 2, height: '100%' }}
                                onClick={addNew}
                                startIcon={<IconPlus />}
                            >
                                New Item
                            </StyledPermissionButton>
                        </ViewHeader>
                        {selected.length > 0 && (
                            <PermissionButton
                                permissionId={'datasets:delete'}
                                sx={{ mt: 1, mb: 2, width: 'max-content' }}
                                variant='outlined'
                                onClick={deleteDatasetItems}
                                color='error'
                                startIcon={<IconTrash />}
                            >
                                Delete {selected.length} {selected.length === 1 ? 'item' : 'items'}
                            </PermissionButton>
                        )}
                        {!isLoading && dataset?.rows?.length <= 0 ? (
                            <Stack sx={{ alignItems: 'center', justifyContent: 'center' }} flexDirection='column'>
                                <Box sx={{ p: 2, height: 'auto' }}>
                                    <img
                                        style={{ objectFit: 'cover', height: '20vh', width: 'auto' }}
                                        src={empty_datasetSVG}
                                        alt='empty_datasetSVG'
                                    />
                                </Box>
                                <div>No Dataset Items Yet</div>
                                <StyledPermissionButton
                                    permissionId={'datasets:create,datasets:update'}
                                    variant='contained'
                                    sx={{ borderRadius: 2, height: '100%', mt: 2, color: 'white' }}
                                    startIcon={<IconPlus />}
                                    onClick={addNew}
                                >
                                    New Item
                                </StyledPermissionButton>
                            </Stack>
                        ) : (
                            <React.Fragment>
                                <TableContainer
                                    sx={{ border: 1, borderColor: theme.palette.grey[900] + 25, borderRadius: 2 }}
                                    component={Paper}
                                >
                                    <Table sx={{ minWidth: 650 }} aria-label='simple table'>
                                        <TableHead
                                            sx={{
                                                backgroundColor: customization.isDarkMode
                                                    ? theme.palette.common.black
                                                    : theme.palette.grey[100],
                                                height: 56
                                            }}
                                        >
                                            <TableRow>
                                                <StyledTableCell padding='checkbox'>
                                                    <Checkbox
                                                        color='primary'
                                                        checked={selected.length === (dataset?.rows || []).length}
                                                        onChange={onSelectAllClick}
                                                        inputProps={{
                                                            'aria-label': 'select all'
                                                        }}
                                                    />
                                                </StyledTableCell>
                                                <StyledTableCell>Input</StyledTableCell>
                                                <StyledTableCell>Expected Output</StyledTableCell>
                                                <StyledTableCell style={{ width: '1%' }}>
                                                    <IconArrowsDownUp />
                                                </StyledTableCell>
                                            </TableRow>
                                        </TableHead>
                                        <TableBody>
                                            {isLoading ? (
                                                <>
                                                    <StyledTableRow>
                                                        <StyledTableCell>
                                                            <Skeleton variant='text' />
                                                        </StyledTableCell>
                                                        <StyledTableCell>
                                                            <Skeleton variant='text' />
                                                        </StyledTableCell>
                                                        <StyledTableCell>
                                                            <Skeleton variant='text' />
                                                        </StyledTableCell>
                                                        <StyledTableCell>
                                                            <Skeleton variant='text' />
                                                        </StyledTableCell>
                                                    </StyledTableRow>
                                                    <StyledTableRow>
                                                        <StyledTableCell>
                                                            <Skeleton variant='text' />
                                                        </StyledTableCell>
                                                        <StyledTableCell>
                                                            <Skeleton variant='text' />
                                                        </StyledTableCell>
                                                        <StyledTableCell>
                                                            <Skeleton variant='text' />
                                                        </StyledTableCell>
                                                        <StyledTableCell>
                                                            <Skeleton variant='text' />
                                                        </StyledTableCell>
                                                    </StyledTableRow>
                                                </>
                                            ) : (
                                                <>
                                                    {(dataset?.rows || []).map((item, index) => (
                                                        <StyledTableRow
                                                            draggable={Draggable}
                                                            onDragStart={(e) => handleDragStart(e, index)}
                                                            onDragOver={(e) => e.preventDefault()}
                                                            onDragEnter={(e) => handleDragEnter(e, index)}
                                                            onDragEnd={(e) => handleDragEnd(e, index)}
                                                            hover
                                                            key={index}
                                                            sx={{ cursor: 'pointer', '&:last-child td, &:last-child th': { border: 0 } }}
                                                        >
                                                            <StyledTableCell
                                                                padding='checkbox'
                                                                onMouseDown={() => setDraggable(false)}
                                                                onMouseUp={() => setDraggable(true)}
                                                            >
                                                                <Checkbox
                                                                    color='primary'
                                                                    checked={selected.indexOf(item.id) !== -1}
                                                                    onChange={(event) => handleSelect(event, item.id)}
                                                                    inputProps={{
                                                                        'aria-labelledby': item.id
                                                                    }}
                                                                />
                                                            </StyledTableCell>
                                                            <StyledTableCell
                                                                onClick={() => edit(item)}
                                                                onMouseDown={() => setDraggable(false)}
                                                                onMouseUp={() => setDraggable(true)}
                                                            >
                                                                {item.input}
                                                            </StyledTableCell>
                                                            <StyledTableCell
                                                                onClick={() => edit(item)}
                                                                onMouseDown={() => setDraggable(false)}
                                                                onMouseUp={() => setDraggable(true)}
                                                            >
                                                                {item.output}
                                                            </StyledTableCell>
                                                            <StyledTableCell style={{ width: '1%' }}>
                                                                <DragIndicatorIcon
                                                                    onMouseDown={() => setDraggable(true)}
                                                                    onMouseUp={() => setDraggable(false)}
                                                                />
                                                            </StyledTableCell>
                                                        </StyledTableRow>
                                                    ))}
                                                </>
                                            )}
                                        </TableBody>
                                    </Table>
                                </TableContainer>
                                <Typography sx={{ color: theme.palette.grey[600], marginTop: -2 }} variant='subtitle2'>
                                    <i>Use the drag icon at (extreme right) to reorder the dataset items</i>
                                </Typography>
                                {/* Pagination and Page Size Controls */}
                                <TablePagination currentPage={currentPage} limit={pageLimit} total={total} onChange={onChange} />
                            </React.Fragment>
                        )}
                    </Stack>
                )}
            </MainCard>
            <AddEditDatasetRowDialog
                show={showRowDialog}
                dialogProps={rowDialogProps}
                onCancel={() => setShowRowDialog(false)}
                onConfirm={onConfirm}
            ></AddEditDatasetRowDialog>
            {showUploadDialog && (
                <UploadCSVFileDialog
                    show={showUploadDialog}
                    dialogProps={rowDialogProps}
                    onCancel={() => setShowUploadDialog(false)}
                    onConfirm={onUploadConfirm}
                ></UploadCSVFileDialog>
            )}
            {showDatasetDialog && (
                <AddEditDatasetDialog
                    show={showDatasetDialog}
                    dialogProps={datasetDialogProps}
                    onCancel={() => setShowDatasetDialog(false)}
                    onConfirm={onConfirm}
                ></AddEditDatasetDialog>
            )}
            <ConfirmDialog />
        </>
    )
}

export default EvalDatasetRows
import { useEffect, useState, useRef } from 'react'

// material-ui
import { Box, Stack, ButtonGroup, Skeleton, ToggleButtonGroup, ToggleButton, Tabs, Tab } from '@mui/material'
import { useTheme } from '@mui/material/styles'

// project imports
import MainCard from '@/ui-component/cards/MainCard'
import ItemCard from '@/ui-component/cards/ItemCard'
import MCPItemCard from '@/ui-component/cards/MCPItemCard'
import ToolDialog from './ToolDialog'
import CustomMcpServerDialog from './CustomMcpServerDialog'
import ViewHeader from '@/layout/MainLayout/ViewHeader'
import ErrorBoundary from '@/ErrorBoundary'
import { ToolsTable } from '@/ui-component/table/ToolsListTable'
import { MCPServersTable } from '@/ui-component/table/MCPServersTable'
import { PermissionButton, StyledPermissionButton } from '@/ui-component/button/RBACButtons'
import TablePagination, { DEFAULT_ITEMS_PER_PAGE } from '@/ui-component/pagination/TablePagination'

// API
import toolsApi from '@/api/tools'
import customMcpServersApi from '@/api/custommcpservers'

// Hooks
import useApi from '@/hooks/useApi'
import { useError } from '@/store/context/ErrorContext'
import { gridSpacing } from '@/store/constant'

// icons
import { IconPlus, IconFileUpload, IconLayoutGrid, IconList } from '@tabler/icons-react'
import ToolEmptySVG from '@/assets/images/tools_empty.svg'

// ==============================|| MCP SERVER RESPONSE SANITIZER ||============================== //

const sanitizeMcpServerResponse = (data) => {
    if (!data || typeof data !== 'object') return {}
    const allowedFields = [
        'id',
        'name',
        'serverUrl',
        'description',
        'type',
        'status',
        'createdDate',
        'updatedDate',
        'isActive',
        'config',
        'tools',
        'metadata'
    ]
    const sanitized = {}
    for (const field of allowedFields) {
        if (Object.prototype.hasOwnProperty.call(data, field)) {
            sanitized[field] = data[field]
        }
    }
    return sanitized
}

// ==============================|| PII REDACTION ||============================== //

const redactPII = (text) => {
    if (typeof text !== 'string') return text
    // SSN
    let redacted = text.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    // Credit card numbers
    redacted = redacted.replace(/\b(?:\d[ -]?){13,16}\b/g, '[REDACTED_CC]')
    // Email addresses
    redacted = redacted.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
    // Phone numbers
    redacted = redacted.replace(/(\+?\d[\d\s\-().]{7,}\d)/g, '[REDACTED_PHONE]')
    // Dates of birth (common formats)
    redacted = redacted.replace(/\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](\d{2}|\d{4})\b/g, '[REDACTED_DOB]')
    // Passport numbers (generic)
    redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, '[REDACTED_PASSPORT]')
    // Driver's license (generic US)
    redacted = redacted.replace(/\b[A-Z]\d{7}\b/g, '[REDACTED_DL]')
    // Bank account numbers (generic)
    redacted = redacted.replace(/\b\d{8,17}\b/g, '[REDACTED_ACCOUNT]')
    // IP addresses
    redacted = redacted.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[REDACTED_IP]')
    return redacted
}

// ==============================|| SINGAPORE PII DETECTION ||============================== //

const detectSingaporePII = (text) => {
    if (typeof text !== 'string') return false
    // NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/i
    // SingPass identifier patterns
    const singpassPattern = /singpass/i
    // Singapore phone numbers (+65 XXXX XXXX)
    const sgPhonePattern = /(\+65[\s-]?\d{4}[\s-]?\d{4}|\b65\d{8}\b)/
    // Singapore postal codes (6 digits)
    const sgPostalPattern = /\b\d{6}\b/

    if (nricPattern.test(text)) return { detected: true, reason: 'Singapore NRIC/FIN number detected' }
    if (singpassPattern.test(text)) return { detected: true, reason: 'SingPass identifier detected' }
    if (sgPhonePattern.test(text)) return { detected: true, reason: 'Singapore phone number detected' }
    if (sgPostalPattern.test(text)) return { detected: true, reason: 'Singapore postal code detected' }
    return { detected: false }
}

// ==============================|| MALICIOUS CONTENT DETECTION ||============================== //

const detectMaliciousContent = (text) => {
    if (typeof text !== 'string') return { detected: false }

    // Invisible/zero-width characters
    const invisibleCharsPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060]/
    if (invisibleCharsPattern.test(text)) return { detected: true, reason: 'Invisible characters detected in file content' }

    // Base64-encoded content that could be prompts
    const base64Pattern = /(?:[A-Za-z0-9+/]{40,}={0,2})/
    if (base64Pattern.test(text)) {
        try {
            const matches = text.match(/(?:[A-Za-z0-9+/]{40,}={0,2})/g) || []
            for (const match of matches) {
                const decoded = atob(match)
                const suspiciousDecodedPattern = /ignore\s+previous|system\s*:|you\s+are\s+now|disregard|forget\s+your|new\s+instructions/i
                if (suspiciousDecodedPattern.test(decoded)) {
                    return { detected: true, reason: 'Base64-encoded prompt injection detected' }
                }
            }
        } catch {
            // not valid base64, ignore
        }
    }

    // Prompt injection patterns
    const promptInjectionPatterns = [
        /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
        /system\s*:\s*you\s+are/i,
        /\bDAN\b/,
        /you\s+are\s+now\s+(a|an)\s+/i,
        /disregard\s+(all\s+)?(previous|prior|above)/i,
        /forget\s+(all\s+)?(previous|prior|above|your)/i,
        /new\s+instructions?\s*:/i,
        /override\s+(previous\s+)?instructions?/i,
        /act\s+as\s+(if\s+you\s+are|a|an)\s+/i,
        /pretend\s+(you\s+are|to\s+be)/i,
        /jailbreak/i,
        /prompt\s+injection/i
    ]
    for (const pattern of promptInjectionPatterns) {
        if (pattern.test(text)) return { detected: true, reason: 'Prompt injection pattern detected in file content' }
    }

    // Leetspeak prompt injection
    const leetspeakNormalized = text
        .replace(/4/g, 'a')
        .replace(/3/g, 'e')
        .replace(/1/g, 'i')
        .replace(/0/g, 'o')
        .replace(/5/g, 's')
        .replace(/7/g, 't')
    for (const pattern of promptInjectionPatterns) {
        if (pattern.test(leetspeakNormalized)) return { detected: true, reason: 'Leetspeak prompt injection detected in file content' }
    }

    // Binary/shell commands
    const shellCommandPatterns = [
        /\b(rm\s+-rf|chmod\s+|chown\s+|sudo\s+|wget\s+|curl\s+.*\|\s*sh|bash\s+-c|eval\s*\(|exec\s*\()/i,
        /\x00[\x00-\x08\x0b\x0c\x0e-\x1f]/
    ]
    for (const pattern of shellCommandPatterns) {
        if (pattern.test(text)) return { detected: true, reason: 'Binary or shell command detected in file content' }
    }

    return { detected: false }
}

// ==============================|| TOOLS ||============================== //

const Tools = () => {
    const theme = useTheme()
    const getAllToolsApi = useApi(toolsApi.getAllTools)
    const getAllCustomMcpServersApi = useApi(customMcpServersApi.getAllCustomMcpServers)
    const { error, setError } = useError()

    const [tabValue, setTabValue] = useState(0)

    const [isLoading, setLoading] = useState(true)
    const [showDialog, setShowDialog] = useState(false)
    const [dialogProps, setDialogProps] = useState({})
    const [view, setView] = useState(localStorage.getItem('toolsDisplayStyle') || 'card')

    const inputRef = useRef(null)

    // MCP Servers state
    const [mcpLoading, setMcpLoading] = useState(true)
    const [showMcpDialog, setShowMcpDialog] = useState(false)
    const [mcpDialogProps, setMcpDialogProps] = useState({})
    const [mcpTotal, setMcpTotal] = useState(0)
    const [mcpCurrentPage, setMcpCurrentPage] = useState(1)
    const [mcpPageLimit, setMcpPageLimit] = useState(DEFAULT_ITEMS_PER_PAGE)

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
        const params = {
            page: page || currentPage,
            limit: limit || pageLimit
        }
        getAllToolsApi.request(params)
    }

    const onCustomMcpPageChange = (page, limit) => {
        setMcpCurrentPage(page)
        setMcpPageLimit(limit)
        refreshCustomMcp(page, limit)
    }

    const refreshCustomMcp = (page, limit) => {
        const params = {
            page: page || mcpCurrentPage,
            limit: limit || mcpPageLimit
        }
        console.log('[MCP] Calling getAllCustomMcpServers with params:', params)
        getAllCustomMcpServersApi.request(params)
    }

    const handleChange = (event, nextView) => {
        if (nextView === null) return
        localStorage.setItem('toolsDisplayStyle', nextView)
        setView(nextView)
    }

    const onUploadFile = (file) => {
        try {
            // Redact PII from raw file string before parsing
            const redactedFile = redactPII(file)

            // Check for Singapore PII
            const sgPiiCheck = detectSingaporePII(redactedFile)
            if (sgPiiCheck.detected) {
                console.error('File upload rejected due to Singapore PII:', sgPiiCheck.reason)
                setError(new Error(`File upload rejected: ${sgPiiCheck.reason}`))
                return
            }

            const parsedData = JSON.parse(redactedFile)
            const dialogProp = {
                title: 'Add New Tool',
                type: 'IMPORT',
                cancelButtonName: 'Cancel',
                confirmButtonName: 'Save',
                data: parsedData
            }
            setDialogProps(dialogProp)
            setShowDialog(true)
        } catch (e) {
            console.error(e)
        }
    }

    const handleFileUpload = (e) => {
        if (!e.target.files) return

        const file = e.target.files[0]

        const reader = new FileReader()
        reader.onload = (evt) => {
            if (!evt?.target?.result) {
                return
            }
            const { result } = evt.target

            // Check for malicious content before processing
            const maliciousCheck = detectMaliciousContent(result)
            if (maliciousCheck.detected) {
                console.error('File upload rejected due to malicious content:', maliciousCheck.reason)
                setError(new Error(`File upload rejected: ${maliciousCheck.reason}`))
                return
            }

            onUploadFile(result)
        }
        reader.readAsText(file)
    }

    const addNew = () => {
        const dialogProp = {
            title: 'Add New Tool',
            type: 'ADD',
            cancelButtonName: 'Cancel',
            confirmButtonName: 'Add'
        }
        setDialogProps(dialogProp)
        setShowDialog(true)
    }

    const edit = (selectedTool) => {
        const dialogProp = {
            title: 'Edit Tool',
            type: 'EDIT',
            cancelButtonName: 'Cancel',
            confirmButtonName: 'Save',
            data: selectedTool
        }
        setDialogProps(dialogProp)
        setShowDialog(true)
    }

    const onConfirm = () => {
        setShowDialog(false)
        refresh(currentPage, pageLimit)
    }

    const onAuthorize = () => {
        refreshCustomMcp(mcpCurrentPage, mcpPageLimit)
    }

    // MCP Server handlers
    const addNewCustomMcpServer = () => {
        setMcpDialogProps({ type: 'ADD' })
        setShowMcpDialog(true)
    }

    const editCustomMcpServer = async (server) => {
        try {
            console.log('[MCP] Calling getCustomMcpServer for server id:', server.id)
            const resp = await customMcpServersApi.getCustomMcpServer(server.id)
            console.log('[MCP] getCustomMcpServer response received for server id:', server.id)
            const sanitizedData = sanitizeMcpServerResponse(resp.data ?? server)
            setMcpDialogProps({ type: 'EDIT', data: sanitizedData })
        } catch {
            const sanitizedData = sanitizeMcpServerResponse(server)
            setMcpDialogProps({ type: 'EDIT', data: sanitizedData })
        }
        setShowMcpDialog(true)
    }

    const onCustomMcpConfirm = () => {
        setShowMcpDialog(false)
        console.log('[MCP] onCustomMcpConfirm: refreshing custom MCP servers, page:', mcpCurrentPage, 'limit:', mcpPageLimit)
        refreshCustomMcp(mcpCurrentPage, mcpPageLimit)
    }

    const onCustomMcpCreated = async (newServerId) => {
        console.log('[MCP] onCustomMcpCreated: refreshing custom MCP servers after creation of server id:', newServerId)
        refreshCustomMcp(mcpCurrentPage, mcpPageLimit)
        try {
            console.log('[MCP] Calling getCustomMcpServer for newly created server id:', newServerId)
            const resp = await customMcpServersApi.getCustomMcpServer(newServerId)
            console.log('[MCP] getCustomMcpServer response received for newly created server id:', newServerId)
            const sanitizedData = sanitizeMcpServerResponse(resp.data ?? { id: newServerId })
            setMcpDialogProps({ type: 'EDIT', data: sanitizedData })
        } catch {
            const sanitizedData = sanitizeMcpServerResponse({ id: newServerId })
            setMcpDialogProps({ type: 'EDIT', data: sanitizedData })
        }
    }

    const [search, setSearch] = useState('')
    const onSearchChange = (event) => {
        setSearch(event.target.value)
    }

    function filterTools(data) {
        return (
            data.name.toLowerCase().indexOf(search.toLowerCase()) > -1 || data.description.toLowerCase().indexOf(search.toLowerCase()) > -1
        )
    }

    function filterCustomMcpServers(data) {
        const s = search.toLowerCase()
        return data.name.toLowerCase().indexOf(s) > -1 || (data.serverUrl && data.serverUrl.toLowerCase().indexOf(s) > -1)
    }

    useEffect(() => {
        if (tabValue === 0) {
            refresh(currentPage, pageLimit)
        } else {
            refreshCustomMcp(mcpCurrentPage, mcpPageLimit)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [tabValue])

    useEffect(() => {
        setLoading(getAllToolsApi.loading)
    }, [getAllToolsApi.loading])

    useEffect(() => {
        if (getAllToolsApi.data) {
            setTotal(getAllToolsApi.data.total)
        }
    }, [getAllToolsApi.data])

    useEffect(() => {
        setMcpLoading(getAllCustomMcpServersApi.loading)
    }, [getAllCustomMcpServersApi.loading])

    useEffect(() => {
        if (getAllCustomMcpServersApi.data) {
            setMcpTotal(getAllCustomMcpServersApi.data.total)
        }
    }, [getAllCustomMcpServersApi.data])

    const viewToggle = (disabled) => (
        <ToggleButtonGroup
            sx={{ borderRadius: 2, maxHeight: 40 }}
            value={view}
            color='primary'
            disabled={disabled}
            exclusive
            onChange={handleChange}
        >
            <ToggleButton
                sx={{
                    borderColor: theme.palette.grey[900] + 25,
                    borderRadius: 2,
                    color: theme?.customization?.isDarkMode ? 'white' : 'inherit'
                }}
                variant='contained'
                value='card'
                title='Card View'
            >
                <IconLayoutGrid />
            </ToggleButton>
            <ToggleButton
                sx={{
                    borderColor: theme.palette.grey[900] + 25,
                    borderRadius: 2,
                    color: theme?.customization?.isDarkMode ? 'white' : 'inherit'
                }}
                variant='contained'
                value='list'
                title='List View'
            >
                <IconList />
            </ToggleButton>
        </ToggleButtonGroup>
    )

    const renderCustomToolsToolbar = () => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {viewToggle(total === 0)}
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <PermissionButton
                    permissionId={'tools:create'}
                    variant='outlined'
                    onClick={() => inputRef.current.click()}
                    startIcon={<IconFileUpload />}
                    sx={{ borderRadius: 2, height: 40 }}
                >
                    Load
                </PermissionButton>
                <input style={{ display: 'none' }} ref={inputRef} type='file' hidden accept='.json' onChange={(e) => handleFileUpload(e)} />
            </Box>
            <ButtonGroup disableElevation aria-label='outlined primary button group'>
                <StyledPermissionButton
                    permissionId={'tools:create'}
                    variant='contained'
                    onClick={addNew}
                    startIcon={<IconPlus />}
                    sx={{ borderRadius: 2, height: 40 }}
                >
                    Create
                </StyledPermissionButton>
            </ButtonGroup>
        </Box>
    )

    const renderMcpServersToolbar = () => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {viewToggle(mcpTotal === 0)}
            <ButtonGroup disableElevation aria-label='outlined primary button group'>
                <StyledPermissionButton
                    permissionId={'tools:create'}
                    variant='contained'
                    onClick={addNewCustomMcpServer}
                    startIcon={<IconPlus />}
                    sx={{ borderRadius: 2, height: 40 }}
                >
                    Add Custom MCP Server
                </StyledPermissionButton>
            </ButtonGroup>
        </Box>
    )

    const renderCustomToolsTab = () => (
        <>
            {isLoading && (
                <Box display='grid' gridTemplateColumns='repeat(3, 1fr)' gap={gridSpacing}>
                    <Skeleton variant='rounded' height={160} />
                    <Skeleton variant='rounded' height={160} />
                    <Skeleton variant='rounded' height={160} />
                </Box>
            )}
            {!isLoading && total > 0 && (
                <>
                    {!view || view === 'card' ? (
                        <Box display='grid' gridTemplateColumns='repeat(3, 1fr)' gap={gridSpacing}>
                            {getAllToolsApi.data?.data?.filter(filterTools).map((data, index) => (
                                <ItemCard data={data} key={index} onClick={() => edit(data)} />
                            ))}
                        </Box>
                    ) : (
                        <ToolsTable data={getAllToolsApi.data?.data?.filter(filterTools) || []} isLoading={isLoading} onSelect={edit} />
                    )}
                    {/* Pagination and Page Size Controls */}
                    <TablePagination currentPage={currentPage} limit={pageLimit} total={total} onChange={onChange} />
                </>
            )}
            {!isLoading && total === 0 && (
                <Stack sx={{ alignItems: 'center', justifyContent: 'center' }} flexDirection='column'>
                    <Box sx={{ p: 2, height: 'auto' }}>
                        <img style={{ objectFit: 'cover', height: '20vh', width: 'auto' }} src={ToolEmptySVG} alt='ToolEmptySVG' />
                    </Box>
                    <div>No Tools Created Yet</div>
                </Stack>
            )}
        </>
    )

    const renderMcpServersTab = () => (
        <>
            {mcpLoading && (
                <Box display='grid' gridTemplateColumns='repeat(3, 1fr)' gap={gridSpacing}>
                    <Skeleton variant='rounded' height={160} />
                    <Skeleton variant='rounded' height={160} />
                    <Skeleton variant='rounded' height={160} />
                </Box>
            )}
            {!mcpLoading && mcpTotal > 0 && (
                <>
                    {!view || view === 'card' ? (
                        <Box display='grid' gridTemplateColumns='repeat(3, 1fr)' gap={gridSpacing}>
                            {getAllCustomMcpServersApi.data?.data?.filter(filterCustomMcpServers).map((server) => (
                                <MCPItemCard key={server.id} data={server} onClick={() => editCustomMcpServer(server)} />
                            ))}
                        </Box>
                    ) : (
                        <MCPServersTable
                            data={getAllCustomMcpServersApi.data?.data?.filter(filterCustomMcpServers) || []}
                            isLoading={mcpLoading}
                            onSelect={editCustomMcpServer}
                        />
                    )}
                    <TablePagination currentPage={mcpCurrentPage} limit={mcpPageLimit} total={mcpTotal} onChange={onCustomMcpPageChange} />
                </>
            )}
            {!mcpLoading && mcpTotal === 0 && (
                <Stack sx={{ alignItems: 'center', justifyContent: 'center' }} flexDirection='column'>
                    <Box sx={{ p: 2, height: 'auto' }}>
                        <img style={{ objectFit: 'cover', height: '20vh', width: 'auto' }} src={ToolEmptySVG} alt='ToolEmptySVG' />
                    </Box>
                    <div>No Custom MCP Servers Added Yet</div>
                </Stack>
            )}
        </>
    )

    return (
        <>
            <MainCard>
                {error ? (
                    <ErrorBoundary error={error} />
                ) : (
                    <Stack flexDirection='column' sx={{ gap: 3 }}>
                        <ViewHeader
                            onSearchChange={onSearchChange}
                            search={true}
                            searchPlaceholder={tabValue === 0 ? 'Search Tools' : 'Search Custom MCP Servers'}
                            title='Tools'
                            description='External functions or APIs the agent can use to take action'
                        />
                        <Box
                            sx={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-between',
                                gap: 2,
                                borderBottom: 1,
                                borderColor: 'divider'
                            }}
                        >
                            <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)} aria-label='tools tabs'>
                                <Tab label='Custom Tools' />
                                <Tab label='Custom MCP Servers' />
                            </Tabs>
                            <Box sx={{ pb: 1 }}>{tabValue === 0 ? renderCustomToolsToolbar() : renderMcpServersToolbar()}</Box>
                        </Box>
                        {tabValue === 0 && renderCustomToolsTab()}
                        {tabValue === 1 && renderMcpServersTab()}
                    </Stack>
                )}
            </MainCard>
            <ToolDialog
                show={showDialog}
                dialogProps={dialogProps}
                onCancel={() => setShowDialog(false)}
                onConfirm={onConfirm}
                setError={setError}
            />
            <CustomMcpServerDialog
                show={showMcpDialog}
                dialogProps={mcpDialogProps}
                onCancel={() => {
                    setShowMcpDialog(false)
                }}
                onConfirm={onCustomMcpConfirm}
                onAuthorize={onAuthorize}
                onCreated={onCustomMcpCreated}
            />
        </>
    )
}

export default Tools
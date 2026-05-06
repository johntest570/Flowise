import { useEffect, useRef, useState, useCallback, useContext } from 'react'
import ReactFlow, { addEdge, Controls, Background, useNodesState, useEdgesState } from 'reactflow'
import 'reactflow/dist/style.css'

import { useDispatch, useSelector } from 'react-redux'
import { useNavigate, useLocation } from 'react-router-dom'
import {
    REMOVE_DIRTY,
    SET_DIRTY,
    SET_CHATFLOW,
    enqueueSnackbar as enqueueSnackbarAction,
    closeSnackbar as closeSnackbarAction
} from '@/store/actions'
import { omit, cloneDeep } from 'lodash'

// material-ui
import { Toolbar, Box, AppBar, Button, Fab } from '@mui/material'
import { useTheme } from '@mui/material/styles'

// project imports
import CanvasNode from './CanvasNode'
import ButtonEdge from './ButtonEdge'
import StickyNote from './StickyNote'
import CanvasHeader from './CanvasHeader'
import AddNodes from './AddNodes'
import ConfirmDialog from '@/ui-component/dialog/ConfirmDialog'
import ChatPopUp from '@/views/chatmessage/ChatPopUp'
import VectorStorePopUp from '@/views/vectorstore/VectorStorePopUp'
import { flowContext } from '@/store/context/ReactFlowContext'

// API
import nodesApi from '@/api/nodes'
import chatflowsApi from '@/api/chatflows'

// Hooks
import useApi from '@/hooks/useApi'
import useConfirm from '@/hooks/useConfirm'
import { useAuth } from '@/hooks/useAuth'

// icons
import { IconX, IconRefreshAlert, IconMagnetFilled, IconMagnetOff, IconArtboard, IconArtboardOff } from '@tabler/icons-react'

// utils
import {
    getUniqueNodeId,
    initNode,
    rearrangeToolsOrdering,
    getUpsertDetails,
    updateOutdatedNodeData,
    updateOutdatedNodeEdge
} from '@/utils/genericHelper'
import useNotifier from '@/utils/useNotifier'
import { usePrompt } from '@/utils/usePrompt'

// const
import { FLOWISE_CREDENTIAL_ID } from '@/store/constant'

const nodeTypes = { customNode: CanvasNode, stickyNote: StickyNote }
const edgeTypes = { buttonedge: ButtonEdge }

// ==============================|| SECURITY HELPERS ||============================== //

/**
 * Checks a string for suspicious/malicious content patterns.
 * Returns true if suspicious content is found.
 */
const containsSuspiciousContent = (str) => {
    if (typeof str !== 'string') return false

    // Hidden/invisible characters (zero-width, control chars, etc.)
    if (/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/.test(str)) return true

    // Base64-encoded content (long base64 strings)
    if (/(?:[A-Za-z0-9+/]{40,}={0,2})/.test(str)) return true

    // Shell commands
    if (/(\b(bash|sh|cmd|powershell|exec|eval|system|popen|subprocess)\b[\s(])/i.test(str)) return true
    if (/(&&|\|\||;)\s*(rm|del|format|mkfs|dd\s+if)/i.test(str)) return true

    // Binary content indicators
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(str)) return true

    // Common prompt injection phrases
    const promptInjectionPatterns = [
        /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
        /disregard\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
        /forget\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
        /you\s+are\s+now\s+(a\s+)?(different|new|another|an?\s+)?(\w+\s+)?(ai|assistant|bot|model|gpt)/i,
        /act\s+as\s+(a\s+)?(different|new|another|an?\s+)?(\w+\s+)?(ai|assistant|bot|model|gpt)/i,
        /pretend\s+(you\s+are|to\s+be)\s/i,
        /jailbreak/i,
        /prompt\s+injection/i,
        /system\s+prompt/i,
        /\[INST\]/i,
        /<\|im_start\|>/i,
        /###\s*(instruction|system|human|assistant)/i
    ]
    for (const pattern of promptInjectionPatterns) {
        if (pattern.test(str)) return true
    }

    // Leetspeak patterns for common injection words
    if (/1gnor3|1nj3ct|3xec|3v4l/i.test(str)) return true

    return false
}

/**
 * Recursively sanitizes an object by checking all string values for suspicious content.
 * Returns null if any suspicious content is found, otherwise returns the object.
 */
const sanitizeFlowData = (obj) => {
    if (typeof obj === 'string') {
        if (containsSuspiciousContent(obj)) return null
        return obj
    }
    if (Array.isArray(obj)) {
        const sanitized = []
        for (const item of obj) {
            const result = sanitizeFlowData(item)
            if (result === null && item !== null) return null
            sanitized.push(result)
        }
        return sanitized
    }
    if (obj !== null && typeof obj === 'object') {
        const sanitized = {}
        for (const key of Object.keys(obj)) {
            const result = sanitizeFlowData(obj[key])
            if (result === null && obj[key] !== null) return null
            sanitized[key] = result
        }
        return sanitized
    }
    return obj
}

/**
 * PII redaction patterns and helper.
 * Redacts email addresses, phone numbers, SSNs, and credit card numbers from strings.
 */
const PII_PATTERNS = [
    // Email addresses
    { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: '[REDACTED_EMAIL]' },
    // US/International phone numbers
    { pattern: /(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})/g, replacement: '[REDACTED_PHONE]' },
    // SSNs (US)
    { pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, replacement: '[REDACTED_SSN]' },
    // Credit card numbers (basic pattern)
    { pattern: /\b(?:\d[ \-]?){13,16}\b/g, replacement: '[REDACTED_CC]' }
]

const redactPII = (str) => {
    if (typeof str !== 'string') return str
    let redacted = str
    for (const { pattern, replacement } of PII_PATTERNS) {
        redacted = redacted.replace(pattern, replacement)
    }
    return redacted
}

const redactPIIFromObject = (obj) => {
    if (typeof obj === 'string') {
        return redactPII(obj)
    }
    if (Array.isArray(obj)) {
        return obj.map((item) => redactPIIFromObject(item))
    }
    if (obj !== null && typeof obj === 'object') {
        const result = {}
        for (const key of Object.keys(obj)) {
            result[key] = redactPIIFromObject(obj[key])
        }
        return result
    }
    return obj
}

/**
 * Singapore PII detection.
 * Detects NRIC/FIN numbers, Singapore phone numbers, and Singapore postal codes.
 * Returns true if Singapore PII is detected.
 */
const containsSingaporePII = (jsonString) => {
    if (typeof jsonString !== 'string') return false

    // Singapore NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    if (/\b[STFG]\d{7}[A-Z]\b/i.test(jsonString)) return true

    // Singapore phone numbers: +65 followed by 8 digits, or 8-digit numbers starting with 6, 8, or 9
    if (/(\+65[\s\-]?)?\b[689]\d{7}\b/.test(jsonString)) return true

    // Singapore postal codes: 6-digit numbers (S followed by 6 digits or standalone 6-digit)
    if (/\bS\d{6}\b/.test(jsonString)) return true

    return false
}

// ==============================|| CANVAS ||============================== //

const Canvas = () => {
    const theme = useTheme()
    const navigate = useNavigate()
    const { hasAssignedWorkspace } = useAuth()

    const { state } = useLocation()
    const templateFlowData = state ? state.templateFlowData : ''

    const URLpath = document.location.pathname.toString().split('/')
    const chatflowId =
        URLpath[URLpath.length - 1] === 'canvas' || URLpath[URLpath.length - 1] === 'agentcanvas' ? '' : URLpath[URLpath.length - 1]
    const isAgentCanvas = URLpath.includes('agentcanvas') ? true : false
    const canvasTitle = URLpath.includes('agentcanvas') ? 'Agent' : 'Chatflow'

    const { confirm } = useConfirm()

    const dispatch = useDispatch()
    const customization = useSelector((state) => state.customization)
    const canvas = useSelector((state) => state.canvas)
    const [canvasDataStore, setCanvasDataStore] = useState(canvas)
    const [chatflow, setChatflow] = useState(null)
    const { reactFlowInstance, setReactFlowInstance } = useContext(flowContext)

    // ==============================|| Snackbar ||============================== //

    useNotifier()
    const enqueueSnackbar = (...args) => dispatch(enqueueSnackbarAction(...args))
    const closeSnackbar = (...args) => dispatch(closeSnackbarAction(...args))

    // ==============================|| ReactFlow ||============================== //

    const [nodes, setNodes, onNodesChange] = useNodesState()
    const [edges, setEdges, onEdgesChange] = useEdgesState()

    const [selectedNode, setSelectedNode] = useState(null)
    const [isUpsertButtonEnabled, setIsUpsertButtonEnabled] = useState(false)
    const [isSyncNodesButtonEnabled, setIsSyncNodesButtonEnabled] = useState(false)
    const [isSnappingEnabled, setIsSnappingEnabled] = useState(false)
    const [isBackgroundEnabled, setIsBackgroundEnabled] = useState(true)

    const reactFlowWrapper = useRef(null)

    const [lastUpdatedDateTime, setLasUpdatedDateTime] = useState('')
    const [chatflowName, setChatflowName] = useState('')
    const [flowData, setFlowData] = useState('')

    // ==============================|| Chatflow API ||============================== //

    const getNodesApi = useApi(nodesApi.getAllNodes)
    const createNewChatflowApi = useApi(chatflowsApi.createNewChatflow)
    const updateChatflowApi = useApi(chatflowsApi.updateChatflow)
    const getSpecificChatflowApi = useApi(chatflowsApi.getSpecificChatflow)
    const getHasChatflowChangedApi = useApi(chatflowsApi.getHasChatflowChanged)

    // ==============================|| Events & Actions ||============================== //

    const onConnect = (params) => {
        const newEdge = {
            ...params,
            type: 'buttonedge',
            id: `${params.source}-${params.sourceHandle}-${params.target}-${params.targetHandle}`
        }

        const targetNodeId = params.targetHandle.split('-')[0]
        const sourceNodeId = params.sourceHandle.split('-')[0]
        const targetInput = params.targetHandle.split('-')[2]

        setNodes((nds) =>
            nds.map((node) => {
                if (node.id === targetNodeId) {
                    setTimeout(() => setDirty(), 0)
                    let value
                    const inputAnchor = node.data.inputAnchors.find((ancr) => ancr.name === targetInput)
                    const inputParam = node.data.inputParams.find((param) => param.name === targetInput)

                    if (inputAnchor && inputAnchor.list) {
                        const newValues = node.data.inputs[targetInput] || []
                        if (targetInput === 'tools') {
                            rearrangeToolsOrdering(newValues, sourceNodeId)
                        } else {
                            newValues.push(`{{${sourceNodeId}.data.instance}}`)
                        }
                        value = newValues
                    } else if (inputParam && inputParam.acceptVariable) {
                        value = node.data.inputs[targetInput] || ''
                    } else {
                        value = `{{${sourceNodeId}.data.instance}}`
                    }
                    node.data = {
                        ...node.data,
                        inputs: {
                            ...node.data.inputs,
                            [targetInput]: value
                        }
                    }
                }
                return node
            })
        )

        setEdges((eds) => addEdge(newEdge, eds))
    }

    const handleLoadFlow = (file) => {
        try {
            // Singapore PII check: abort if Singapore PII detected in raw JSON string
            if (containsSingaporePII(file)) {
                console.warn('Flow data contains Singapore PII. Aborting file processing.')
                return
            }

            const flowData = JSON.parse(file)

            // Redact global PII from parsed flow data
            const piiRedactedFlowData = redactPIIFromObject(flowData)

            const nodes = piiRedactedFlowData.nodes || []
            const edges = piiRedactedFlowData.edges || []

            // Sanitize nodes for suspicious/malicious content
            const sanitizedNodes = sanitizeFlowData(nodes)
            if (sanitizedNodes === null) {
                console.warn('Flow nodes contain suspicious content. Aborting file processing.')
                return
            }

            // Sanitize edges for suspicious/malicious content
            const sanitizedEdges = sanitizeFlowData(edges)
            if (sanitizedEdges === null) {
                console.warn('Flow edges contain suspicious content. Aborting file processing.')
                return
            }

            setNodes(sanitizedNodes)
            setEdges(sanitizedEdges)
            setTimeout(() => setDirty(), 0)
        } catch (e) {
            console.error(e)
        }
    }

    const handleDeleteFlow = async () => {
        const confirmPayload = {
            title: `Delete`,
            description: `Delete ${canvasTitle} ${chatflow.name}?`,
            confirmButtonName: 'Delete',
            cancelButtonName: 'Cancel'
        }
        const isConfirmed = await confirm(confirmPayload)

        if (isConfirmed) {
            try {
                await chatflowsApi.deleteChatflow(chatflow.id)
                localStorage.removeItem(`${chatflow.id}_INTERNAL`)
                navigate(isAgentCanvas ? '/agentflows' : '/')
            } catch (error) {
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
    }

    const handleSaveFlow = async (chatflowName) => {
        if (reactFlowInstance) {
            const nodes = reactFlowInstance.getNodes().map((node) => {
                const nodeData = cloneDeep(node.data)
                if (Object.prototype.hasOwnProperty.call(nodeData.inputs, FLOWISE_CREDENTIAL_ID)) {
                    nodeData.credential = nodeData.inputs[FLOWISE_CREDENTIAL_ID]
                    nodeData.inputs = omit(nodeData.inputs, [FLOWISE_CREDENTIAL_ID])
                }
                node.data = {
                    ...nodeData,
                    selected: false
                }
                return node
            })

            const rfInstanceObject = reactFlowInstance.toObject()
            rfInstanceObject.nodes = nodes
            const flowData = JSON.stringify(rfInstanceObject)

            if (!chatflow.id) {
                const newChatflowBody = {
                    name: chatflowName,
                    deployed: false,
                    isPublic: false,
                    flowData,
                    type: isAgentCanvas ? 'MULTIAGENT' : 'CHATFLOW'
                }
                createNewChatflowApi.request(newChatflowBody)
            } else {
                setChatflowName(chatflowName)
                setFlowData(flowData)
                getHasChatflowChangedApi.request(chatflow.id, lastUpdatedDateTime)
            }
        }
    }

    // eslint-disable-next-line
    const onNodeClick = useCallback((event, clickedNode) => {
        setSelectedNode(clickedNode)
        setNodes((nds) =>
            nds.map((node) => {
                if (node.id === clickedNode.id) {
                    node.data = {
                        ...node.data,
                        selected: true
                    }
                } else {
                    node.data = {
                        ...node.data,
                        selected: false
                    }
                }

                return node
            })
        )
    })

    const onDragOver = useCallback((event) => {
        event.preventDefault()
        event.dataTransfer.dropEffect = 'move'
    }, [])

    const onDrop = useCallback(
        (event) => {
            event.preventDefault()
            const reactFlowBounds = reactFlowWrapper.current.getBoundingClientRect()
            let nodeData = event.dataTransfer.getData('application/reactflow')

            // check if the dropped element is valid
            if (typeof nodeData === 'undefined' || !nodeData) {
                return
            }

            nodeData = JSON.parse(nodeData)

            const position = reactFlowInstance.project({
                x: event.clientX - reactFlowBounds.left - 100,
                y: event.clientY - reactFlowBounds.top - 50
            })

            const newNodeId = getUniqueNodeId(nodeData, reactFlowInstance.getNodes())

            const newNode = {
                id: newNodeId,
                position,
                type: nodeData.type !== 'StickyNote' ? 'customNode' : 'stickyNote',
                data: initNode(nodeData, newNodeId)
            }

            setSelectedNode(newNode)
            setNodes((nds) =>
                nds.concat(newNode).map((node) => {
                    if (node.id === newNode.id) {
                        node.data = {
                            ...node.data,
                            selected: true
                        }
                    } else {
                        node.data = {
                            ...node.data,
                            selected: false
                        }
                    }

                    return node
                })
            )
            setTimeout(() => setDirty(), 0)
        },

        // eslint-disable-next-line
        [reactFlowInstance]
    )

    const syncNodes = () => {
        const componentNodes = canvas.componentNodes

        const cloneNodes = cloneDeep(nodes)
        const cloneEdges = cloneDeep(edges)
        let toBeRemovedEdges = []

        for (let i = 0; i < cloneNodes.length; i++) {
            const node = cloneNodes[i]
            const componentNode = componentNodes.find((cn) => cn.name === node.data.name)
            if (componentNode && componentNode.version > node.data.version) {
                const clonedComponentNode = cloneDeep(componentNode)
                cloneNodes[i].data = updateOutdatedNodeData(clonedComponentNode, node.data)
                toBeRemovedEdges.push(...updateOutdatedNodeEdge(cloneNodes[i].data, cloneEdges))
            }
        }

        setNodes(cloneNodes)
        setEdges(cloneEdges.filter((edge) => !toBeRemovedEdges.includes(edge)))
        setDirty()
        setIsSyncNodesButtonEnabled(false)
    }

    const saveChatflowSuccess = () => {
        dispatch({ type: REMOVE_DIRTY })
        enqueueSnackbar({
            message: `${canvasTitle} saved`,
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

    const errorFailed = (message) => {
        enqueueSnackbar({
            message,
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

    const setDirty = () => {
        dispatch({ type: SET_DIRTY })
    }

    const checkIfUpsertAvailable = (nodes, edges) => {
        const upsertNodeDetails = getUpsertDetails(nodes, edges)
        if (upsertNodeDetails.length) setIsUpsertButtonEnabled(true)
        else setIsUpsertButtonEnabled(false)
    }

    const checkIfSyncNodesAvailable = (nodes) => {
        const componentNodes = canvas.componentNodes

        for (let i = 0; i < nodes.length; i++) {
            const node = nodes[i]
            const componentNode = componentNodes.find((cn) => cn.name === node.data.name)
            if (componentNode && componentNode.version > node.data.version) {
                setIsSyncNodesButtonEnabled(true)
                return
            }
        }

        setIsSyncNodesButtonEnabled(false)
    }

    // ==============================|| useEffect ||============================== //

    // Get specific chatflow successful
    useEffect(() => {
        if (getSpecificChatflowApi.data) {
            const chatflow = getSpecificChatflowApi.data
            const workspaceId = chatflow.workspaceId
            if (!hasAssignedWorkspace(workspaceId)) {
                navigate('/unauthorized')
                return
            }
            const initialFlow = chatflow.flowData ? JSON.parse(chatflow.flowData) : []
            setLasUpdatedDateTime(chatflow.updatedDate)
            setNodes(initialFlow.nodes || [])
            setEdges(initialFlow.edges || [])
            dispatch({ type: SET_CHATFLOW, chatflow })
        } else if (getSpecificChatflowApi.error) {
            errorFailed(`Failed to retrieve ${canvasTitle}: ${getSpecificChatflowApi.error.response.data.message}`)
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [getSpecificChatflowApi.data, getSpecificChatflowApi.error])

    // Create new chatflow successful
    useEffect(() => {
        if (createNewChatflowApi.data) {
            const chatflow = createNewChatflowApi.data
            dispatch({ type: SET_CHATFLOW, chatflow })
            saveChatflowSuccess()
            window.history.replaceState(state, null, `/${isAgentCanvas ? 'agentcanvas' : 'canvas'}/${chatflow.id}`)
        } else if (createNewChatflowApi.error) {
            errorFailed(`Failed to retrieve ${canvasTitle}: ${createNewChatflowApi.error.response.data.message}`)
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [createNewChatflowApi.data, createNewChatflowApi.error])

    // Update chatflow successful
    useEffect(() => {
        if (updateChatflowApi.data) {
            dispatch({ type: SET_CHATFLOW, chatflow: updateChatflowApi.data })
            setLasUpdatedDateTime(updateChatflowApi.data.updatedDate)
            saveChatflowSuccess()
        } else if (updateChatflowApi.error) {
            errorFailed(`Failed to retrieve ${canvasTitle}: ${updateChatflowApi.error.response.data.message}`)
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [updateChatflowApi.data, updateChatflowApi.error])

    // check if chatflow has changed before saving
    useEffect(() => {
        const checkIfHasChanged = async () => {
            if (getHasChatflowChangedApi.data?.hasChanged === true) {
                const confirmPayload = {
                    title: `Confirm Change`,
                    description: `${canvasTitle} ${chatflow.name} has changed since you have opened, overwrite changes?`,
                    confirmButtonName: 'Confirm',
                    cancelButtonName: 'Cancel'
                }
                const isConfirmed = await confirm(confirmPayload)

                if (!isConfirmed) {
                    return
                }
            }
            const updateBody = {
                name: chatflowName,
                flowData
            }
            updateChatflowApi.request(chatflow.id, updateBody)
        }

        if (getHasChatflowChangedApi.data) {
            checkIfHasChanged()
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [getHasChatflowChangedApi.data, getHasChatflowChangedApi.error])

    useEffect(() => {
        setChatflow(canvasDataStore.chatflow)
        if (canvasDataStore.chatflow) {
            const flowData = canvasDataStore.chatflow.flowData ? JSON.parse(canvasDataStore.chatflow.flowData) : []
            checkIfUpsertAvailable(flowData.nodes || [], flowData.edges || [])
            checkIfSyncNodesAvailable(flowData.nodes || [])
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [canvasDataStore.chatflow])

    // Initialization
    useEffect(() => {
        setIsSyncNodesButtonEnabled(false)
        setIsUpsertButtonEnabled(false)
        if (chatflowId) {
            getSpecificChatflowApi.request(chatflowId)
        } else {
            if (localStorage.getItem('duplicatedFlowData')) {
                handleLoadFlow(localStorage.getItem('duplicatedFlowData'))
                setTimeout(() => localStorage.removeItem('duplicatedFlowData'), 0)
            } else {
                setNodes([])
                setEdges([])
            }
            dispatch({
                type: SET_CHATFLOW,
                chatflow: {
                    name: `Untitled ${canvasTitle}`
                }
            })
        }

        getNodesApi.request()

        // Clear dirty state before leaving and remove any ongoing test triggers and webhooks
        return () => {
            setTimeout(() => dispatch({ type: REMOVE_DIRTY }), 0)
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    useEffect(() => {
        setCanvasDataStore(canvas)
    }, [canvas])

    useEffect(() => {
        function handlePaste(e) {
            const pasteData = e.clipboardData.getData('text')
            //TODO: prevent paste event when input focused, temporary fix: catch chatflow syntax
            if (pasteData.includes('{"nodes":[') && pasteData.includes('],"edges":[')) {
                handleLoadFlow(pasteData)
            }
        }

        window.addEventListener('paste', handlePaste)

        return () => {
            window.removeEventListener('paste', handlePaste)
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    useEffect(() => {
        if (templateFlowData && templateFlowData.includes('"nodes":[') && templateFlowData.includes('],"edges":[')) {
            handleLoadFlow(templateFlowData)
        }

        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [templateFlowData])

    usePrompt('You have unsaved changes! Do you want to navigate away?', canvasDataStore.isDirty)

    return (
        <>
            <Box>
                <AppBar
                    enableColorOnDark
                    position='fixed'
                    color='inherit'
                    elevation={1}
                    sx={{
                        bgcolor: theme.palette.background.default
                    }}
                >
                    <Toolbar>
                        <CanvasHeader
                            chatflow={chatflow}
                            handleSaveFlow={handleSaveFlow}
                            handleDeleteFlow={handleDeleteFlow}
                            handleLoadFlow={handleLoadFlow}
                            isAgentCanvas={isAgentCanvas}
                        />
                    </Toolbar>
                </AppBar>
                <Box sx={{ pt: '70px', height: '100vh', width: '100%' }}>
                    <div className='reactflow-parent-wrapper'>
                        <div className='reactflow-wrapper' ref={reactFlowWrapper}>
                            <ReactFlow
                                nodes={nodes}
                                edges={edges}
                                onNodesChange={onNodesChange}
                                onNodeClick={onNodeClick}
                                onEdgesChange={onEdgesChange}
                                onDrop={onDrop}
                                onDragOver={onDragOver}
                                onNodeDragStop={setDirty}
                                nodeTypes={nodeTypes}
                                edgeTypes={edgeTypes}
                                onConnect={onConnect}
                                onInit={setReactFlowInstance}
                                fitView
                                deleteKeyCode={canvas.canvasDialogShow ? null : ['Delete']}
                                minZoom={0.1}
                                snapGrid={[25, 25]}
                                snapToGrid={isSnappingEnabled}
                                className='chatflow-canvas'
                            >
                                <Controls
                                    className={customization.isDarkMode ? 'dark-mode-controls' : ''}
                                    style={{
                                        display: 'flex',
                                        flexDirection: 'row',
                                        left: '50%',
                                        transform: 'translate(-50%, -50%)'
                                    }}
                                >
                                    <button
                                        className='react-flow__controls-button react-flow__controls-interactive'
                                        onClick={() => {
                                            setIsSnappingEnabled(!isSnappingEnabled)
                                        }}
                                        title='toggle snapping'
                                        aria-label='toggle snapping'
                                    >
                                        {isSnappingEnabled ? <IconMagnetFilled /> : <IconMagnetOff />}
                                    </button>
                                    <button
                                        className='react-flow__controls-button react-flow__controls-interactive'
                                        onClick={() => {
                                            setIsBackgroundEnabled(!isBackgroundEnabled)
                                        }}
                                        title='toggle background'
                                        aria-label='toggle background'
                                    >
                                        {isBackgroundEnabled ? <IconArtboard /> : <IconArtboardOff />}
                                    </button>
                                </Controls>
                                {isBackgroundEnabled && <Background color='#aaa' gap={16} />}
                                <AddNodes isAgentCanvas={isAgentCanvas} nodesData={getNodesApi.data} node={selectedNode} />
                                {isSyncNodesButtonEnabled && (
                                    <Fab
                                        sx={{
                                            left: 40,
                                            top: 20,
                                            color: 'white',
                                            background: 'orange',
                                            '&:hover': {
                                                background: 'orange',
                                                backgroundImage: `linear-gradient(rgb(0 0 0/10%) 0 0)`
                                            }
                                        }}
                                        size='small'
                                        aria-label='sync'
                                        title='Sync Nodes'
                                        onClick={() => syncNodes()}
                                    >
                                        <IconRefreshAlert />
                                    </Fab>
                                )}
                                {isUpsertButtonEnabled && <VectorStorePopUp chatflowid={chatflowId} />}
                                <ChatPopUp isAgentCanvas={isAgentCanvas} chatflowid={chatflowId} />
                            </ReactFlow>
                        </div>
                    </div>
                </Box>
                <ConfirmDialog />
            </Box>
        </>
    )
}

export default Canvas
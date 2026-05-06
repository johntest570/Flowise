import client from './client'

const MAX_INPUT_LENGTH = 32000

const DANGEROUS_PATTERNS = [
    /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,
    /[\u200B-\u200D\uFEFF\u00AD\u2060]/g
]

const PROMPT_INJECTION_PATTERNS = [
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /system\s*:\s*you\s+are/i,
    /\[system\]/i,
    /<\s*system\s*>/i,
    /###\s*instruction/i,
    /\bprompt\s*injection\b/i,
    /forget\s+(everything|all|previous)/i,
    /new\s+instructions?\s*:/i,
    /override\s+(previous|prior|all)\s+(instructions?|settings?)/i
]

const BASE64_PROMPT_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/

const LEET_INSTRUCTION_PATTERNS = [
    /1gn0r3|1nstruct10n|pr0mpt|syst3m/i
]

const SHELL_COMMAND_PATTERNS = [
    /\b(exec|eval|system|shell_exec|passthru|popen)\s*\(/i,
    /`[^`]+`/,
    /\$\([^)]+\)/,
    /;\s*(rm|ls|cat|wget|curl|chmod|chown|sudo|bash|sh|python|perl|ruby)\b/i
]

const EXCESSIVE_TOKEN_LENGTH = 10000

function sanitizeAndValidate(body, requiredFields = []) {
    if (!body || typeof body !== 'object') {
        throw new Error('Invalid input: body must be an object')
    }

    for (const field of requiredFields) {
        if (body[field] === undefined || body[field] === null || body[field] === '') {
            throw new Error(`Missing required field: ${field}`)
        }
    }

    const serialized = JSON.stringify(body)
    if (serialized.length > MAX_INPUT_LENGTH) {
        throw new Error('Input exceeds maximum allowed length')
    }

    const sanitized = JSON.parse(serialized)

    function sanitizeValue(val) {
        if (typeof val === 'string') {
            let result = val
            for (const pattern of DANGEROUS_PATTERNS) {
                result = result.replace(pattern, '')
            }
            if (result.length > MAX_INPUT_LENGTH) {
                result = result.substring(0, MAX_INPUT_LENGTH)
            }
            return result
        } else if (Array.isArray(val)) {
            return val.map(sanitizeValue)
        } else if (val && typeof val === 'object') {
            const obj = {}
            for (const key of Object.keys(val)) {
                obj[key] = sanitizeValue(val[key])
            }
            return obj
        }
        return val
    }

    return sanitizeValue(sanitized)
}

function checkForMaliciousContent(body) {
    const serialized = typeof body === 'string' ? body : JSON.stringify(body)

    for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(serialized)) {
            throw new Error('Potentially malicious content detected: prompt injection pattern found')
        }
    }

    for (const pattern of LEET_INSTRUCTION_PATTERNS) {
        if (pattern.test(serialized)) {
            throw new Error('Potentially malicious content detected: obfuscated instruction pattern found')
        }
    }

    for (const pattern of SHELL_COMMAND_PATTERNS) {
        if (pattern.test(serialized)) {
            throw new Error('Potentially malicious content detected: shell command pattern found')
        }
    }

    const tokens = serialized.split(/\s+/)
    for (const token of tokens) {
        if (token.length > EXCESSIVE_TOKEN_LENGTH) {
            if (BASE64_PROMPT_PATTERN.test(token)) {
                try {
                    const decoded = atob(token)
                    for (const pattern of PROMPT_INJECTION_PATTERNS) {
                        if (pattern.test(decoded)) {
                            throw new Error('Potentially malicious content detected: base64-encoded prompt injection found')
                        }
                    }
                } catch (e) {
                    if (e.message.includes('malicious')) throw e
                }
            }
            throw new Error('Potentially malicious content detected: excessively long token found')
        }
    }

    const invisibleCharPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u2028\u2029]/
    if (invisibleCharPattern.test(serialized)) {
        throw new Error('Potentially malicious content detected: invisible/zero-width characters found')
    }
}

const getAllDocumentStores = (params) => client.get('/document-store/store', { params })
const getDocumentLoaders = () => client.get('/document-store/components/loaders')
const getSpecificDocumentStore = (id) => client.get(`/document-store/store/${id}`)
const createDocumentStore = (body) => client.post(`/document-store/store`, body)
const updateDocumentStore = (id, body) => client.put(`/document-store/store/${id}`, body)
const deleteDocumentStore = (id) => client.delete(`/document-store/store/${id}`)
const getDocumentStoreConfig = (storeId, loaderId) => client.get(`/document-store/store-configs/${storeId}/${loaderId}`)

const deleteLoaderFromStore = (id, fileId) => client.delete(`/document-store/loader/${id}/${fileId}`)
const deleteChunkFromStore = (storeId, loaderId, chunkId) => client.delete(`/document-store/chunks/${storeId}/${loaderId}/${chunkId}`)
const editChunkFromStore = (storeId, loaderId, chunkId, body) =>
    client.put(`/document-store/chunks/${storeId}/${loaderId}/${chunkId}`, body)

const getFileChunks = (storeId, fileId, pageNo) => client.get(`/document-store/chunks/${storeId}/${fileId}/${pageNo}`)

const previewChunks = (body) => {
    checkForMaliciousContent(body)
    return client.post('/document-store/loader/preview', body)
}

const processLoader = (body, loaderId) => {
    checkForMaliciousContent(body)
    return client.post(`/document-store/loader/process/${loaderId}`, body)
}

const saveProcessingLoader = (body) => client.post(`/document-store/loader/save`, body)
const refreshLoader = (storeId) => client.post(`/document-store/refresh/${storeId}`)

const insertIntoVectorStore = (body) => {
    const sanitizedBody = sanitizeAndValidate(body)
    return client.post(`/document-store/vectorstore/insert`, sanitizedBody)
}

const saveVectorStoreConfig = (body) => client.post(`/document-store/vectorstore/save`, body)
const updateVectorStoreConfig = (body) => client.post(`/document-store/vectorstore/update`, body)
const deleteVectorStoreDataFromStore = (storeId, docId) => {
    const url = docId ? `/document-store/vectorstore/${storeId}?docId=${docId}` : `/document-store/vectorstore/${storeId}`
    return client.delete(url)
}

const queryVectorStore = (body) => {
    const sanitizedBody = sanitizeAndValidate(body)
    return client.post(`/document-store/vectorstore/query`, sanitizedBody)
}

const getVectorStoreProviders = () => client.get('/document-store/components/vectorstore')
const getEmbeddingProviders = () => client.get('/document-store/components/embeddings')
const getRecordManagerProviders = () => client.get('/document-store/components/recordmanager')

const generateDocStoreToolDesc = (storeId, body) => {
    const sanitizedBody = sanitizeAndValidate(body)
    return client.post('/document-store/generate-tool-desc/' + storeId, sanitizedBody)
}

export default {
    getAllDocumentStores,
    getSpecificDocumentStore,
    createDocumentStore,
    deleteLoaderFromStore,
    getFileChunks,
    updateDocumentStore,
    previewChunks,
    processLoader,
    getDocumentLoaders,
    deleteChunkFromStore,
    editChunkFromStore,
    deleteDocumentStore,
    insertIntoVectorStore,
    getVectorStoreProviders,
    getEmbeddingProviders,
    getRecordManagerProviders,
    saveVectorStoreConfig,
    queryVectorStore,
    deleteVectorStoreDataFromStore,
    updateVectorStoreConfig,
    saveProcessingLoader,
    refreshLoader,
    generateDocStoreToolDesc,
    getDocumentStoreConfig
}
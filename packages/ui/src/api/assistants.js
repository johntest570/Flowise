import client from './client'

// Input sanitization and validation helpers
const MAX_FIELD_LENGTH = 10000

const sanitizeString = (str) => {
    if (typeof str !== 'string') return str
    return str
        .replace(/[<>]/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .substring(0, MAX_FIELD_LENGTH)
}

const sanitizeBody = (body) => {
    if (body === null || typeof body !== 'object') {
        throw new Error('Invalid request body: must be a non-null object')
    }
    const sanitized = {}
    for (const key of Object.keys(body)) {
        const value = body[key]
        if (typeof value === 'string') {
            sanitized[key] = sanitizeString(value)
        } else if (Array.isArray(value)) {
            sanitized[key] = value.map((item) => (typeof item === 'string' ? sanitizeString(item) : item))
        } else {
            sanitized[key] = value
        }
    }
    return sanitized
}

// File content validation helpers (prompt injection, malicious content)
const SUSPICIOUS_PATTERNS = [
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/i,
    /system\s*prompt/i,
    /you\s+are\s+now/i,
    /disregard\s+(all|any|previous)/i,
    /forget\s+(everything|all|previous)/i,
    /new\s+instructions?:/i,
    /\[INST\]/i,
    /<<SYS>>/i,
    /prompt\s*injection/i,
    /jailbreak/i,
    /dan\s+mode/i,
    /developer\s+mode/i,
]

const BINARY_PATTERNS = [
    /^MZ/,
    /^\x7fELF/,
    /^#!(\/usr\/bin\/|\/bin\/)/,
    /\x00[\s\S]{0,100}\x00/,
]

const SHELL_COMMAND_PATTERNS = [
    /\b(rm\s+-rf|chmod\s+777|wget\s+http|curl\s+http|bash\s+-c|sh\s+-c|exec\s*\(|eval\s*\()/i,
    /<\s*script\b/i,
]

const LEETSPEAK_PATTERNS = [
    /1gn0r3|1gnor3|1nstruct10n/i,
    /pr0mpt|syst3m|3x3cut3/i,
]

const BASE64_PROMPT_PATTERN = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/

const INVISIBLE_CHAR_PATTERN = /[\u200B-\u200D\uFEFF\u00AD\u2060]/

const checkFileContentForMalicious = (text) => {
    if (INVISIBLE_CHAR_PATTERN.test(text)) {
        return 'File contains hidden/invisible characters that may indicate prompt injection'
    }
    for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(text)) {
            return 'File contains suspicious prompt injection patterns'
        }
    }
    for (const pattern of LEETSPEAK_PATTERNS) {
        if (pattern.test(text)) {
            return 'File contains leetspeak prompt injection patterns'
        }
    }
    for (const pattern of SHELL_COMMAND_PATTERNS) {
        if (pattern.test(text)) {
            return 'File contains shell commands or script tags'
        }
    }
    if (BASE64_PROMPT_PATTERN.test(text)) {
        try {
            const matches = text.match(/(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g) || []
            for (const match of matches) {
                const decoded = atob(match)
                for (const pattern of SUSPICIOUS_PATTERNS) {
                    if (pattern.test(decoded)) {
                        return 'File contains base64-encoded prompt injection'
                    }
                }
            }
        } catch (e) {
            // not valid base64, ignore
        }
    }
    return null
}

const checkBinaryContent = (text) => {
    for (const pattern of BINARY_PATTERNS) {
        if (pattern.test(text)) {
            return 'File appears to be a binary executable or contains binary content'
        }
    }
    return null
}

// PII redaction helpers
const PII_PATTERNS = {
    email: { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[REDACTED_EMAIL]' },
    phone: { pattern: /\b(\+?1?\s?)?(\(?\d{3}\)?[\s.-]?)(\d{3}[\s.-]?\d{4})\b/g, replacement: '[REDACTED_PHONE]' },
    ssn: { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
    creditCard: { pattern: /\b(?:\d{4}[\s-]?){3}\d{4}\b/g, replacement: '[REDACTED_CC]' },
    fullName: { pattern: /\b([A-Z][a-z]+\s){1,2}[A-Z][a-z]+\b/g, replacement: '[REDACTED_NAME]' },
}

// Singapore-specific PII patterns
const SG_PII_PATTERNS = {
    nric: { pattern: /\b[STFGM]\d{7}[A-Z]\b/gi, replacement: '[REDACTED_NRIC]' },
    sgPhone: { pattern: /\b(\+65[\s-]?)?[689]\d{7}\b/g, replacement: '[REDACTED_SG_PHONE]' },
    sgPostal: { pattern: /\bSingapore\s+\d{6}\b/gi, replacement: '[REDACTED_SG_POSTAL]' },
    sgPostalCode: { pattern: /\b\d{6}\b/g, replacement: '[REDACTED_SG_POSTAL_CODE]' },
    passport: { pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, replacement: '[REDACTED_PASSPORT]' },
    sgUen: { pattern: /\b\d{9}[A-Z]\b/g, replacement: '[REDACTED_UEN]' },
}

const SG_PII_DETECT_PATTERNS = [
    /\b[STFGM]\d{7}[A-Z]\b/i,
    /\b(\+65[\s-]?)?[689]\d{7}\b/,
    /\bSingapore\s+\d{6}\b/i,
    /\b\d{6}\b/,
    /\b[A-Z]{1,2}\d{6,9}\b/,
    /\b\d{9}[A-Z]\b/,
]

const redactPIIFromText = (text) => {
    let redacted = text
    for (const { pattern, replacement } of Object.values(PII_PATTERNS)) {
        redacted = redacted.replace(pattern, replacement)
    }
    for (const { pattern, replacement } of Object.values(SG_PII_PATTERNS)) {
        redacted = redacted.replace(pattern, replacement)
    }
    return redacted
}

const checkSingaporePII = (text) => {
    for (const pattern of SG_PII_DETECT_PATTERNS) {
        if (pattern.test(text)) {
            return 'File contains Singapore PII data which cannot be uploaded'
        }
    }
    return null
}

const readFileAsText = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = (e) => resolve(e.target.result)
        reader.onerror = () => reject(new Error('Failed to read file'))
        reader.readAsText(file)
    })
}

const isTextFile = (file) => {
    const textTypes = ['text/', 'application/json', 'application/xml', 'application/javascript']
    return textTypes.some((t) => file.type.startsWith(t)) || file.name.match(/\.(txt|md|csv|json|xml|js|ts|html|htm|css|yaml|yml)$/i)
}

const validateAndSanitizeFormData = async (formData) => {
    const sanitizedFormData = new FormData()
    const entries = Array.from(formData.entries())

    for (const [key, value] of entries) {
        if (value instanceof File) {
            if (isTextFile(value)) {
                let text
                try {
                    text = await readFileAsText(value)
                } catch (e) {
                    throw new Error(`Failed to read file: ${value.name}`)
                }

                // Check for binary/shell content
                const binaryError = checkBinaryContent(text)
                if (binaryError) {
                    throw new Error(`File "${value.name}": ${binaryError}`)
                }

                // Check for malicious prompt injection content
                const maliciousError = checkFileContentForMalicious(text)
                if (maliciousError) {
                    throw new Error(`File "${value.name}": ${maliciousError}`)
                }

                // Check for Singapore PII
                const sgPiiError = checkSingaporePII(text)
                if (sgPiiError) {
                    throw new Error(`File "${value.name}": ${sgPiiError}`)
                }

                // Redact PII from text content
                const redactedText = redactPIIFromText(text)
                const sanitizedFile = new File([redactedText], value.name, { type: value.type })
                sanitizedFormData.append(key, sanitizedFile)
            } else {
                sanitizedFormData.append(key, value)
            }
        } else {
            sanitizedFormData.append(key, value)
        }
    }

    return sanitizedFormData
}

// OpenAI Assistant
const getAssistantObj = (id, credentialId) => client.get(`/openai-assistants/${id}?credential=${credentialId}`)

const getAllAvailableAssistants = (credentialId) => client.get(`/openai-assistants?credential=${credentialId}`)

// Assistant
const createNewAssistant = (body) => {
    const sanitizedBody = sanitizeBody(body)
    return client.post(`/assistants`, sanitizedBody)
}

const getAllAssistants = (type) => client.get('/assistants?type=' + type)

const getSpecificAssistant = (id) => client.get(`/assistants/${id}`)

const updateAssistant = (id, body) => client.put(`/assistants/${id}`, body)

const deleteAssistant = (id, isDeleteBoth) =>
    isDeleteBoth ? client.delete(`/assistants/${id}?isDeleteBoth=true`) : client.delete(`/assistants/${id}`)

// Vector Store
const getAssistantVectorStore = (id, credentialId) => client.get(`/openai-assistants-vector-store/${id}?credential=${credentialId}`)

const listAssistantVectorStore = (credentialId) => client.get(`/openai-assistants-vector-store?credential=${credentialId}`)

const createAssistantVectorStore = (credentialId, body) => client.post(`/openai-assistants-vector-store?credential=${credentialId}`, body)

const updateAssistantVectorStore = (id, credentialId, body) =>
    client.put(`/openai-assistants-vector-store/${id}?credential=${credentialId}`, body)

const deleteAssistantVectorStore = (id, credentialId) => client.delete(`/openai-assistants-vector-store/${id}?credential=${credentialId}`)

// Vector Store Files
const uploadFilesToAssistantVectorStore = async (id, credentialId, formData) => {
    const sanitizedFormData = await validateAndSanitizeFormData(formData)
    return client.post(`/openai-assistants-vector-store/${id}?credential=${credentialId}`, sanitizedFormData, {
        headers: { 'Content-Type': 'multipart/form-data' }
    })
}

const deleteFilesFromAssistantVectorStore = (id, credentialId, body) =>
    client.patch(`/openai-assistants-vector-store/${id}?credential=${credentialId}`, body)

// Files
const uploadFilesToAssistant = async (credentialId, formData) => {
    const sanitizedFormData = await validateAndSanitizeFormData(formData)
    return client.post(`/openai-assistants-file/upload?credential=${credentialId}`, sanitizedFormData, {
        headers: { 'Content-Type': 'multipart/form-data' }
    })
}

const getChatModels = () => client.get('/assistants/components/chatmodels')
const getDocStores = () => client.get('/assistants/components/docstores')
const getTools = () => client.get('/assistants/components/tools')

const generateAssistantInstruction = (body) => {
    const sanitizedBody = sanitizeBody(body)
    return client.post(`/assistants/generate/instruction`, sanitizedBody)
}

export default {
    getAllAssistants,
    getSpecificAssistant,
    getAssistantObj,
    getAllAvailableAssistants,
    createNewAssistant,
    updateAssistant,
    deleteAssistant,
    getAssistantVectorStore,
    listAssistantVectorStore,
    updateAssistantVectorStore,
    createAssistantVectorStore,
    uploadFilesToAssistant,
    uploadFilesToAssistantVectorStore,
    deleteFilesFromAssistantVectorStore,
    deleteAssistantVectorStore,
    getChatModels,
    getDocStores,
    getTools,
    generateAssistantInstruction
}
import client from './client'

// --- Sanitization helpers ---

/**
 * Strip null bytes, control characters, and other characters that could be
 * used for prompt injection from a string value.
 */
const sanitizeString = (str) => {
    if (typeof str !== 'string') return str
    // Trim whitespace
    let sanitized = str.trim()
    // Strip null bytes and ASCII control characters (except tab/newline/CR which are benign)
    // eslint-disable-next-line no-control-regex
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    return sanitized
}

/**
 * Recursively sanitize all string fields in a plain object.
 */
const sanitizeObject = (obj) => {
    if (obj === null || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(sanitizeObject)
    const result = {}
    for (const key of Object.keys(obj)) {
        const val = obj[key]
        if (typeof val === 'string') {
            result[key] = sanitizeString(val)
        } else if (typeof val === 'object' && val !== null) {
            result[key] = sanitizeObject(val)
        } else {
            result[key] = val
        }
    }
    return result
}

/**
 * Validate that input is a non-null object and sanitize its string fields.
 */
const validateAndSanitizeInput = (input) => {
    if (input === null || input === undefined || typeof input !== 'object' || Array.isArray(input)) {
        throw new Error('Invalid input: expected a non-null object.')
    }
    return sanitizeObject(input)
}

// --- Prompt injection / malicious content detection helpers ---

const ZERO_WIDTH_CHARS_RE = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u200E\u200F]/
const HTML_HIDING_RE = /<[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^>]*>/i
const BASE64_PROMPT_RE = /(?:aWdub3Jl|Zm9yZ2V0|cHJldGVuZA|aW5zdHJ1Y3Rpb24|c3lzdGVt|dXNlcg==|YXNzaXN0YW50)/i
const LEET_PROMPT_RE = /(?:1gn0r3|f0rg3t|pr3t3nd|1nstruct10n|syst3m|4ssist4nt)/i
const INJECTION_KEYWORDS_RE = /(?:ignore\s+(?:previous|above|all)\s+instructions?|forget\s+(?:previous|above|all)\s+instructions?|you\s+are\s+now|pretend\s+(?:you\s+are|to\s+be)|act\s+as\s+(?:a|an|if)|disregard\s+(?:previous|all)\s+instructions?|override\s+(?:previous|all)\s+instructions?|new\s+instructions?:|system\s*:|<\s*system\s*>|<\s*\/\s*system\s*>|\[system\]|\[user\]|\[assistant\])/i
const BINARY_SIGNATURES = [
    [0x4d, 0x5a],           // MZ - Windows PE
    [0x7f, 0x45, 0x4c, 0x46], // ELF
    [0x23, 0x21],           // shebang #!
    [0xca, 0xfe, 0xba, 0xbe], // Java class / Mach-O fat
    [0x50, 0x4b, 0x03, 0x04], // ZIP (could contain executables)
]

const hasBinarySignature = (bytes) => {
    for (const sig of BINARY_SIGNATURES) {
        if (sig.every((b, i) => bytes[i] === b)) return true
    }
    return false
}

const readFileAsArrayBuffer = (file) =>
    new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = (e) => resolve(e.target.result)
        reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`))
        reader.readAsArrayBuffer(file)
    })

const readFileAsText = (file) =>
    new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = (e) => resolve(e.target.result)
        reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`))
        reader.readAsText(file)
    })

const isTextFile = (file) => {
    const textTypes = ['text/', 'application/json', 'application/xml', 'application/javascript', 'application/csv']
    return textTypes.some((t) => file.type.startsWith(t)) || /\.(txt|md|csv|json|xml|js|ts|html|htm|css|yaml|yml|log)$/i.test(file.name)
}

/**
 * Validate a file for malicious content / prompt injection.
 * Throws if the file is suspicious.
 */
const validateFileForMaliciousContent = async (file) => {
    // Check binary signatures
    const buffer = await readFileAsArrayBuffer(file)
    const bytes = new Uint8Array(buffer.slice(0, 8))
    if (hasBinarySignature(bytes)) {
        throw new Error(`File "${file.name}" appears to be a binary executable or archive and cannot be uploaded.`)
    }

    if (!isTextFile(file)) return

    const text = await readFileAsText(file)

    if (ZERO_WIDTH_CHARS_RE.test(text)) {
        throw new Error(`File "${file.name}" contains hidden/invisible characters that may indicate a prompt injection attempt.`)
    }
    if (HTML_HIDING_RE.test(text)) {
        throw new Error(`File "${file.name}" contains HTML/CSS hiding techniques that may indicate a prompt injection attempt.`)
    }
    if (BASE64_PROMPT_RE.test(text)) {
        throw new Error(`File "${file.name}" contains base64-encoded prompt patterns that may indicate a prompt injection attempt.`)
    }
    if (LEET_PROMPT_RE.test(text)) {
        throw new Error(`File "${file.name}" contains leetspeak prompt patterns that may indicate a prompt injection attempt.`)
    }
    if (INJECTION_KEYWORDS_RE.test(text)) {
        throw new Error(`File "${file.name}" contains suspicious prompt-injection keywords and cannot be uploaded.`)
    }
}

// --- PII redaction helpers ---

const PII_PATTERNS = [
    { name: 'email', re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: '[REDACTED_EMAIL]' },
    { name: 'phone', re: /(?:\+?\d[\d\s\-().]{7,}\d)/g, replacement: '[REDACTED_PHONE]' },
    { name: 'ssn', re: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED_SSN]' },
    { name: 'creditCard', re: /\b(?:\d[ -]?){13,16}\b/g, replacement: '[REDACTED_CC]' },
    { name: 'fullName', re: /\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b/g, replacement: '[REDACTED_NAME]' },
]

// Singapore-specific PII patterns
const SG_PII_PATTERNS = [
    { name: 'nric', re: /\b[STFGM]\d{7}[A-Z]\b/gi, replacement: '[REDACTED_NRIC]' },
    { name: 'fin', re: /\b[FG]\d{7}[A-Z]\b/gi, replacement: '[REDACTED_FIN]' },
    { name: 'singpass', re: /\bsingpass\b/gi, replacement: '[REDACTED_SINGPASS]' },
    { name: 'sgPhone', re: /\b(?:\+65[\s-]?)?\d{4}[\s-]?\d{4}\b/g, replacement: '[REDACTED_SG_PHONE]' },
    { name: 'sgPostal', re: /\bSingapore\s+\d{6}\b/gi, replacement: '[REDACTED_SG_POSTAL]' },
    { name: 'sgPassport', re: /\bE\d{7}[A-Z]\b/g, replacement: '[REDACTED_SG_PASSPORT]' },
]

/**
 * Detect Singapore-specific PII in text and throw if found.
 */
const detectSingaporePII = (text, fileName) => {
    for (const pattern of SG_PII_PATTERNS) {
        const re = new RegExp(pattern.re.source, pattern.re.flags)
        if (re.test(text)) {
            throw new Error(
                `File "${fileName}" contains Singapore PII (${pattern.name}) and cannot be uploaded. Please remove all personal identifiable information before uploading.`
            )
        }
    }
}

/**
 * Redact common PII patterns (including Singapore-specific) from a text string.
 */
const redactPII = (text) => {
    let redacted = text
    for (const pattern of [...PII_PATTERNS, ...SG_PII_PATTERNS]) {
        const re = new RegExp(pattern.re.source, pattern.re.flags)
        redacted = redacted.replace(re, pattern.replacement)
    }
    return redacted
}

/**
 * Process all files in a FormData:
 * 1. Validate for malicious content / prompt injection.
 * 2. Detect Singapore PII (reject if found).
 * 3. Redact general PII from text-based files.
 * 4. Sanitize string-valued FormData entries.
 * Returns a new FormData with sanitized/redacted content.
 */
const processFormData = async (formData) => {
    if (!(formData instanceof FormData)) {
        throw new Error('Invalid formData: expected a FormData instance.')
    }

    const newFormData = new FormData()

    for (const [key, value] of formData.entries()) {
        if (value instanceof File) {
            // Validate for malicious content
            await validateFileForMaliciousContent(value)

            if (isTextFile(value)) {
                const text = await readFileAsText(value)

                // Detect Singapore PII — reject if found
                detectSingaporePII(text, value.name)

                // Redact general PII
                const redactedText = redactPII(text)

                const sanitizedFile = new File([redactedText], value.name, { type: value.type, lastModified: value.lastModified })
                newFormData.append(key, sanitizedFile)
            } else {
                newFormData.append(key, value)
            }
        } else if (typeof value === 'string') {
            newFormData.append(key, sanitizeString(value))
        } else {
            newFormData.append(key, value)
        }
    }

    return newFormData
}

// --- API functions ---

const upsertVectorStore = (id, input) => {
    const sanitizedInput = validateAndSanitizeInput(input)
    return client.post(`/vector/internal-upsert/${id}`, sanitizedInput)
}

const upsertVectorStoreWithFormData = async (id, formData) => {
    const sanitizedFormData = await processFormData(formData)
    return client.post(`/vector/internal-upsert/${id}`, sanitizedFormData, {
        headers: { 'Content-Type': 'multipart/form-data' }
    })
}

const getUpsertHistory = (id, params = {}) => client.get(`/upsert-history/${id}`, { params: { order: 'DESC', ...params } })
const deleteUpsertHistory = (ids) => client.patch(`/upsert-history`, { ids })

export default {
    getUpsertHistory,
    upsertVectorStore,
    upsertVectorStoreWithFormData,
    deleteUpsertHistory
}
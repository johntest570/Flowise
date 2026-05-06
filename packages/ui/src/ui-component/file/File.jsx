import { useState } from 'react'
import PropTypes from 'prop-types'
import { useTheme } from '@mui/material/styles'
import { FormControl, Button } from '@mui/material'
import { IconUpload } from '@tabler/icons-react'
import { getFileName } from '@/utils/genericHelper'

// ─── PII redaction ───────────────────────────────────────────────────────────
const redactPII = (text) => {
    if (typeof text !== 'string') return text
    // Email addresses
    let result = text.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
    // Phone numbers (various formats)
    result = result.replace(/(\+?\d[\s\-.]?){7,15}/g, '[REDACTED_PHONE]')
    // US SSNs
    result = result.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, '[REDACTED_SSN]')
    // Credit card numbers (13-19 digits, optionally separated by spaces/dashes)
    result = result.replace(/\b(?:\d[ \-]?){13,19}\b/g, '[REDACTED_CC]')
    return result
}

// ─── Singapore PII detection ─────────────────────────────────────────────────
const containsSingaporePII = (text) => {
    if (typeof text !== 'string') return false
    // NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    const nricPattern = /\b[STFG]\d{7}[A-Z]\b/i
    // SingPass identifier pattern (SingPass ID is typically the NRIC, but also catch explicit mentions)
    const singpassPattern = /singpass\s*[:\-]?\s*[A-Z0-9]{6,}/i
    // Singapore phone numbers (+65 followed by 8 digits)
    const sgPhonePattern = /(\+65[\s\-]?)?\b[689]\d{7}\b/
    return nricPattern.test(text) || singpassPattern.test(text) || sgPhonePattern.test(text)
}

// ─── Malicious content detection ─────────────────────────────────────────────
const BINARY_MAGIC_BYTES = [
    [0x4d, 0x5a],             // PE executable (MZ)
    [0x7f, 0x45, 0x4c, 0x46], // ELF executable
    [0x50, 0x4b, 0x03, 0x04], // ZIP/JAR
    [0xca, 0xfe, 0xba, 0xbe], // Java class
]

const hasBinaryMagicBytes = (base64Data) => {
    try {
        const binary = atob(base64Data.substring(0, 16))
        const bytes = Array.from(binary).map((c) => c.charCodeAt(0))
        return BINARY_MAGIC_BYTES.some((magic) => magic.every((b, i) => bytes[i] === b))
    } catch {
        return false
    }
}

const INVISIBLE_CHAR_PATTERN = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]/g

const SUSPICIOUS_SHELL_PATTERN =
    /(\b(eval|exec|system|passthru|shell_exec|popen|proc_open|base64_decode|cmd\.exe|\/bin\/sh|\/bin\/bash|powershell|wget|curl\s+.*http|chmod\s+[0-7]+|rm\s+-rf)\b)/i

const LEETSPEAK_INJECTION_PATTERN =
    /(\b(1gnor3|1nj3ct|3x3c|syst3m|3v4l|b4s364|sh3ll|c0mm4nd|4dm1n|r00t|p4ssw0rd)\b)/i

const HIDDEN_PROMPT_PATTERN =
    /(\[INST\]|\[\/INST\]|<\|system\|>|<\|user\|>|<\|assistant\|>|###\s*(System|Instruction|Prompt)|ignore previous instructions|disregard (all |prior |previous )?instructions|you are now|act as (a |an )?|jailbreak|DAN mode|developer mode enabled)/i

const isMaliciousContent = (text) => {
    if (typeof text !== 'string') return false
    const stripped = text.replace(INVISIBLE_CHAR_PATTERN, '')
    if (HIDDEN_PROMPT_PATTERN.test(stripped)) return true
    if (SUSPICIOUS_SHELL_PATTERN.test(stripped)) return true
    if (LEETSPEAK_INJECTION_PATTERN.test(stripped)) return true
    // Check for suspicious base64-encoded content within text
    const base64Chunks = stripped.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []
    for (const chunk of base64Chunks) {
        try {
            const decoded = atob(chunk)
            if (HIDDEN_PROMPT_PATTERN.test(decoded) || SUSPICIOUS_SHELL_PATTERN.test(decoded)) return true
        } catch {
            // not valid base64, skip
        }
    }
    return false
}

// ─── Process base64 data URL: sanitize and redact ────────────────────────────
const processDataURL = (dataURL) => {
    // dataURL format: data:<mime>;base64,<data>
    const commaIdx = dataURL.indexOf(',')
    if (commaIdx === -1) return { ok: false, reason: 'Invalid data URL' }
    const header = dataURL.substring(0, commaIdx)
    const base64Data = dataURL.substring(commaIdx + 1)

    // Check for binary executables
    if (hasBinaryMagicBytes(base64Data)) {
        return { ok: false, reason: 'Binary executable files are not allowed.' }
    }

    // For text-based files, decode and inspect
    let decodedText
    try {
        decodedText = atob(base64Data)
    } catch {
        // Cannot decode — treat as binary, skip text checks
        return { ok: true, value: dataURL }
    }

    // Check for Singapore PII
    if (containsSingaporePII(decodedText)) {
        return { ok: false, reason: 'File contains Singapore PII (NRIC/FIN or SingPass identifier). Upload rejected.' }
    }

    // Check for malicious content
    if (isMaliciousContent(decodedText)) {
        return { ok: false, reason: 'File contains potentially malicious content and cannot be uploaded.' }
    }

    // Redact PII
    const redacted = redactPII(decodedText)
    const reEncoded = btoa(redacted)
    return { ok: true, value: `${header},${reEncoded}` }
}

// ─── Process plain text content: sanitize and redact ─────────────────────────
const processTextContent = (text) => {
    if (containsSingaporePII(text)) {
        return { ok: false, reason: 'File contains Singapore PII (NRIC/FIN or SingPass identifier). Upload rejected.' }
    }
    if (isMaliciousContent(text)) {
        return { ok: false, reason: 'File contains potentially malicious content and cannot be uploaded.' }
    }
    return { ok: true, value: redactPII(text) }
}

export const File = ({ value, formDataUpload, fileType, onChange, onFormDataChange, disabled = false }) => {
    const theme = useTheme()

    const [myValue, setMyValue] = useState(value ?? '')

    const handleFileUpload = async (e) => {
        if (!e.target.files) return

        if (e.target.files.length === 1) {
            const file = e.target.files[0]
            const { name } = file

            const reader = new FileReader()
            reader.onload = (evt) => {
                if (!evt?.target?.result) {
                    return
                }
                const { result } = evt.target

                const processed = processDataURL(result)
                if (!processed.ok) {
                    alert(processed.reason)
                    return
                }

                const value = processed.value + `,filename:${name}`

                setMyValue(value)
                onChange(value)
            }
            reader.readAsDataURL(file)
        } else if (e.target.files.length > 0) {
            let files = Array.from(e.target.files).map((file) => {
                const reader = new FileReader()
                const { name } = file

                return new Promise((resolve, reject) => {
                    reader.onload = (evt) => {
                        if (!evt?.target?.result) {
                            return
                        }
                        const { result } = evt.target
                        const processed = processDataURL(result)
                        if (!processed.ok) {
                            reject(new Error(`${name}: ${processed.reason}`))
                            return
                        }
                        const value = processed.value + `,filename:${name}`
                        resolve(value)
                    }
                    reader.readAsDataURL(file)
                })
            })

            let res
            try {
                res = await Promise.all(files)
            } catch (err) {
                alert(err.message)
                return
            }
            setMyValue(JSON.stringify(res))
            onChange(JSON.stringify(res))
        }
    }

    const handleFormDataUpload = async (e) => {
        if (!e.target.files) return

        if (e.target.files.length === 1) {
            const file = e.target.files[0]
            const { name } = file

            // Read as text for inspection
            const text = await file.text()
            const processed = processTextContent(text)
            if (!processed.ok) {
                alert(processed.reason)
                return
            }

            const formData = new FormData()
            const redactedBlob = new Blob([processed.value], { type: file.type })
            formData.append('files', redactedBlob, name)
            setMyValue(`,filename:${name}`)
            onChange(`,filename:${name}`)
            onFormDataChange(formData)
        } else if (e.target.files.length > 0) {
            const formData = new FormData()
            const values = []
            for (let i = 0; i < e.target.files.length; i++) {
                const file = e.target.files[i]
                const { name } = file

                // Read as text for inspection
                const text = await file.text()
                const processed = processTextContent(text)
                if (!processed.ok) {
                    alert(`${name}: ${processed.reason}`)
                    return
                }

                const redactedBlob = new Blob([processed.value], { type: file.type })
                formData.append('files', redactedBlob, name)
                values.push(`,filename:${name}`)
            }
            setMyValue(JSON.stringify(values))
            onChange(JSON.stringify(values))
            onFormDataChange(formData)
        }
    }

    return (
        <FormControl sx={{ mt: 1, width: '100%' }} size='small'>
            {!formDataUpload && (
                <span
                    style={{
                        fontStyle: 'italic',
                        color: theme.palette.grey['800'],
                        marginBottom: '1rem'
                    }}
                >
                    {myValue ? getFileName(myValue) : 'Choose a file to upload'}
                </span>
            )}
            <Button
                disabled={disabled}
                variant='outlined'
                component='label'
                fullWidth
                startIcon={<IconUpload />}
                sx={{ marginRight: '1rem' }}
            >
                {'Upload File'}
                <input
                    type='file'
                    multiple
                    accept={fileType}
                    hidden
                    onChange={(e) => (formDataUpload ? handleFormDataUpload(e) : handleFileUpload(e))}
                />
            </Button>
        </FormControl>
    )
}

File.propTypes = {
    value: PropTypes.string,
    fileType: PropTypes.string,
    formDataUpload: PropTypes.bool,
    onChange: PropTypes.func,
    onFormDataChange: PropTypes.func,
    disabled: PropTypes.bool
}
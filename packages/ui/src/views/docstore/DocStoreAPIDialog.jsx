import { createPortal } from 'react-dom'
import { useState, useEffect } from 'react'
import PropTypes from 'prop-types'
import { MemoizedReactMarkdown } from '@/ui-component/markdown/MemoizedReactMarkdown'
import {
    Typography,
    Stack,
    Card,
    Accordion,
    AccordionSummary,
    AccordionDetails,
    Dialog,
    DialogContent,
    DialogTitle,
    Box
} from '@mui/material'
import { TableViewOnly } from '@/ui-component/table/Table'
import documentstoreApi from '@/api/documentstore'
import useApi from '@/hooks/useApi'
import { useTheme } from '@mui/material/styles'
import { useSelector } from 'react-redux'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import { IconInfoCircle } from '@tabler/icons-react'
import { baseURL } from '@/store/constant'

const DocStoreAPIDialog = ({ show, dialogProps, onCancel }) => {
    const [nodeConfig, setNodeConfig] = useState({})
    const [values, setValues] = useState('')
    const theme = useTheme()
    const customization = useSelector((state) => state.customization)
    const [nodeConfigExpanded, setNodeConfigExpanded] = useState({})

    const getConfigApi = useApi(documentstoreApi.getDocumentStoreConfig)

    const formDataRequest = () => {
        return `With the Upsert API, you can choose an existing document and reuse the same configuration for upserting.

> **Security & Privacy Warning:** Before uploading any file, you must:
> 1. **Scan for hidden prompts / prompt injection**: Check file contents for suspicious instructions, hidden text, or adversarial prompts that could manipulate the AI system.
> 2. **Scan for PII (including Singapore PII)**: Detect and redact Personally Identifiable Information such as NRIC/FIN numbers (e.g. S1234567A), passport numbers, full names, phone numbers, email addresses, and other sensitive data before uploading.
> 3. **Check for binary executables or malicious content**: Ensure the file is not an executable or contains embedded malicious payloads.
> Abort the upload if any of the above are detected.

\`\`\`python
import requests
import json
import re

API_URL = "${baseURL}/api/v1/document-store/upsert/${dialogProps.storeId}"
API_KEY = "your_api_key_here"

# --- Security & PII Validation ---
# Singapore PII patterns
SINGAPORE_PII_PATTERNS = [
    r'\\b[STFGM]\\d{7}[A-Z]\\b',           # NRIC/FIN
    r'\\b[A-Z]{1,2}\\d{7}[A-Z]\\b',         # Passport Number
    r'\\b\\d{3}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b', # Phone numbers
    r'[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}', # Email
    r'\\b(?:full[\\s_]?name|name)\\s*[:\\-]\\s*[A-Z][a-z]+(?:\\s[A-Z][a-z]+)+\\b', # Full Name pattern
]

# Hidden prompt injection patterns
PROMPT_INJECTION_PATTERNS = [
    r'ignore\\s+(all\\s+)?previous\\s+instructions',
    r'disregard\\s+(all\\s+)?previous\\s+instructions',
    r'you\\s+are\\s+now\\s+(?:a|an)',
    r'act\\s+as\\s+(?:a|an)',
    r'system\\s*:\\s*you',
    r'<\\s*/?\\s*(?:system|prompt|instruction)\\s*>',
]

def scan_file_for_issues(file_path):
    """Scan file for PII, hidden prompts, and binary/malicious content."""
    # Check for binary/executable content
    with open(file_path, 'rb') as f:
        header = f.read(8)
        # Check for common executable magic bytes
        executable_signatures = [
            b'\\x7fELF',       # ELF executable
            b'MZ',             # Windows PE executable
            b'\\xca\\xfe\\xba\\xbe', # Mach-O executable
            b'\\x50\\x4b\\x03\\x04', # ZIP (could contain executables)
        ]
        for sig in executable_signatures:
            if header.startswith(sig):
                raise ValueError(f"File appears to be a binary/executable. Upload aborted for security reasons.")

    # Read text content for scanning
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        raise ValueError("Unable to read file content for security scanning. Upload aborted.")

    # Scan for prompt injection
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            raise ValueError(f"Potential prompt injection detected in file. Upload aborted.")

    # Scan for Singapore PII
    pii_found = []
    for pattern in SINGAPORE_PII_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            pii_found.extend(matches)

    if pii_found:
        raise ValueError(f"PII detected in file (found {len(pii_found)} instance(s)). Please redact PII before uploading. Upload aborted.")

    print("File passed security and PII checks.")
    return True

def redact_pii_from_content(content):
    """Redact Singapore PII from text content."""
    for pattern in SINGAPORE_PII_PATTERNS:
        content = re.sub(pattern, '[REDACTED]', content, flags=re.IGNORECASE)
    return content

# Validate file before uploading
file_path = 'my-another-file.pdf'
scan_file_for_issues(file_path)  # Raises ValueError if issues found

API_KEY = "your_api_key_here"

# use form data to upload files
form_data = {
    "files": ('my-another-file.pdf', open('my-another-file.pdf', 'rb'))
}

body_data = {
    "docId": "${dialogProps.loaderId}",
    "metadata": {}, # Add additional metadata to the document chunks
    "replaceExisting": True, # Replace existing document with the new upserted chunks
    "createNewDocStore": False, # Create a new document store
    "loaderName": "Custom Loader Name", # Override the loader name
    "splitter": json.dumps({"config":{"chunkSize":20000}}) # Override existing configuration
    # "loader": "",
    # "vectorStore": "",
    # "embedding": "",
    # "recordManager": "",
    # "docStore": ""
}

headers = {
    "Authorization": f"Bearer {BEARER_TOKEN}"
}

def query(form_data):
    response = requests.post(API_URL, files=form_data, data=body_data, headers=headers)
    print(response)
    return response.json()

output = query(form_data)
print(output)
\`\`\`

\`\`\`javascript
// --- Security & PII Validation ---
// Singapore PII patterns
const SINGAPORE_PII_PATTERNS = [
    /\b[STFGM]\d{7}[A-Z]\b/i,                          // NRIC/FIN
    /\b[A-Z]{1,2}\d{7}[A-Z]\b/i,                        // Passport Number
    /\b\d{3}[-\s]?\d{4}[-\s]?\d{4}\b/,                  // Phone numbers
    /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/, // Email
    /\b(?:full[\s_]?name|name)\s*[:\-]\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)+\b/i, // Full Name
];

// Hidden prompt injection patterns
const PROMPT_INJECTION_PATTERNS = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /disregard\s+(all\s+)?previous\s+instructions/i,
    /you\s+are\s+now\s+(?:a|an)/i,
    /act\s+as\s+(?:a|an)/i,
    /system\s*:\s*you/i,
    /<\s*\/?\s*(?:system|prompt|instruction)\s*>/i,
];

// Executable magic bytes (as hex strings for comparison)
const EXECUTABLE_SIGNATURES = [
    [0x7f, 0x45, 0x4c, 0x46], // ELF
    [0x4d, 0x5a],              // Windows PE (MZ)
    [0xca, 0xfe, 0xba, 0xbe], // Mach-O
    [0x50, 0x4b, 0x03, 0x04], // ZIP
];

async function scanFileForIssues(file) {
    // Check for binary/executable content
    const headerBuffer = await file.slice(0, 8).arrayBuffer();
    const headerBytes = new Uint8Array(headerBuffer);
    for (const sig of EXECUTABLE_SIGNATURES) {
        if (sig.every((byte, i) => headerBytes[i] === byte)) {
            throw new Error("File appears to be a binary/executable. Upload aborted for security reasons.");
        }
    }

    // Read text content
    const textContent = await file.text();

    // Scan for prompt injection
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(textContent)) {
            throw new Error("Potential prompt injection detected in file. Upload aborted.");
        }
    }

    // Scan for Singapore PII
    const piiFound = [];
    for (const pattern of SINGAPORE_PII_PATTERNS) {
        const matches = textContent.match(new RegExp(pattern.source, pattern.flags + 'g'));
        if (matches) piiFound.push(...matches);
    }
    if (piiFound.length > 0) {
        throw new Error(\`PII detected in file (\${piiFound.length} instance(s) found). Please redact PII before uploading. Upload aborted.\`);
    }

    console.log("File passed security and PII checks.");
    return true;
}

// use FormData to upload files
async function query(formData) {
    const response = await fetch(
        "${baseURL}/api/v1/document-store/upsert/${dialogProps.storeId}",
        {
            method: "POST",
            headers: {
                "Authorization": "Bearer <your_api_key_here>"
            },
            body: formData
        }
    );
    const result = await response.json();
    return result;
}

// Validate file before uploading
const file = input.files[0];
try {
    await scanFileForIssues(file); // Throws if issues found
} catch (err) {
    console.error("Upload blocked:", err.message);
    throw err; // Abort upload
}

let formData = new FormData();
formData.append("files", file);
formData.append("docId", "${dialogProps.loaderId}");
formData.append("loaderName", "Custom Loader Name");
formData.append("splitter", JSON.stringify({"config":{"chunkSize":20000}}));
// Add additional metadata to the document chunks
formData.append("metadata", "{}");
// Replace existing document with the new upserted chunks
formData.append("replaceExisting", "true");
// Create a new document store
formData.append("createNewDocStore", "false");
// Override existing configuration
// formData.append("loader", "");
// formData.append("embedding", "");
// formData.append("vectorStore", "");
// formData.append("recordManager", "");
// formData.append("docStore", "");

query(formData).then((response) => {
    console.log(response);
});
\`\`\`

\`\`\`bash
# IMPORTANT: Before uploading, scan your file for:
# 1. Hidden prompt injection (e.g., "ignore previous instructions")
# 2. Singapore PII (NRIC/FIN, passport numbers, full names, phone numbers, emails)
# 3. Binary/executable content
# Use a PII scanning tool or script to redact sensitive data before proceeding.
# Example: grep -iP '[STFGM]\\d{7}[A-Z]' <file-path>  # Check for NRIC/FIN
# Abort upload if any issues are found.

curl -X POST ${baseURL}/api/v1/document-store/upsert/${dialogProps.storeId} \\
  -H "Authorization: Bearer <your_api_key_here>" \\
  -F "files=@<file-path>" \\
  -F "docId=${dialogProps.loaderId}" \\
  -F "loaderName=Custom Loader Name" \\
  -F "splitter={"config":{"chunkSize":20000}}" \\
  -F "metadata={}" \\
  -F "replaceExisting=true" \\
  -F "createNewDocStore=false" \\
  # Override existing configuration:
  # -F "loader=" \\
  # -F "embedding=" \\
  # -F "vectorStore=" \\
  # -F "recordManager=" \\
  # -F "docStore="
\`\`\`
`
    }

    const jsonDataRequest = () => {
        return `With the Upsert API, you can choose an existing document and reuse the same configuration for upserting.

> **Security & Privacy Warning:** Before uploading any content, you must:
> 1. **Scan for hidden prompts / prompt injection**: Check content for suspicious instructions or adversarial prompts that could manipulate the AI system.
> 2. **Scan for PII (including Singapore PII)**: Detect and redact Personally Identifiable Information such as NRIC/FIN numbers, passport numbers, full names, phone numbers, and email addresses before uploading.
> 3. **Check for malicious content**: Ensure the content does not contain embedded malicious payloads.
> Abort the upload if any of the above are detected.
 
\`\`\`python
import requests
import re

API_URL = "${baseURL}/api/v1/document-store/upsert/${dialogProps.storeId}"
API_KEY = "your_api_key_here"

# --- Security & PII Validation ---
SINGAPORE_PII_PATTERNS = [
    r'\\b[STFGM]\\d{7}[A-Z]\\b',
    r'\\b[A-Z]{1,2}\\d{7}[A-Z]\\b',
    r'\\b\\d{3}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b',
    r'[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}',
    r'\\b(?:full[\\s_]?name|name)\\s*[:\\-]\\s*[A-Z][a-z]+(?:\\s[A-Z][a-z]+)+\\b',
]
PROMPT_INJECTION_PATTERNS = [
    r'ignore\\s+(all\\s+)?previous\\s+instructions',
    r'disregard\\s+(all\\s+)?previous\\s+instructions',
    r'you\\s+are\\s+now\\s+(?:a|an)',
    r'act\\s+as\\s+(?:a|an)',
    r'system\\s*:\\s*you',
    r'<\\s*/?\\s*(?:system|prompt|instruction)\\s*>',
]

def scan_text_for_issues(text):
    """Scan text content for PII and hidden prompts."""
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValueError("Potential prompt injection detected. Upload aborted.")
    pii_found = []
    for pattern in SINGAPORE_PII_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            pii_found.extend(matches)
    if pii_found:
        raise ValueError(f"PII detected ({len(pii_found)} instance(s)). Please redact PII before uploading. Upload aborted.")
    print("Content passed security and PII checks.")

headers = {
    "Authorization": f"Bearer {BEARER_TOKEN}"
}

def query(payload):
    # Scan all string values in payload for PII and prompt injection
    for key, value in payload.items():
        if isinstance(value, str):
            scan_text_for_issues(value)
        elif isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, str):
                    scan_text_for_issues(v)
    response = requests.post(API_URL, json=payload, headers=headers)
    return response.json()

output = query({
    "docId": "${dialogProps.loaderId}",
    "metadata": "{}", # Add additional metadata to the document chunks
    "replaceExisting": True, # Replace existing document with the new upserted chunks
    "createNewDocStore": False, # Create a new document store
    "loaderName": "Custom Loader Name", # Override the loader name
    # Override existing configuration
    "loader": {
        "config": {
            "text": "This is a new text"
        }
    },
    "splitter": {
        "config": {
            "chunkSize": 20000
        }
    },
    # embedding: {},
    # vectorStore: {},
    # recordManager: {}
    # docStore: {}
})
print(output)
\`\`\`

\`\`\`javascript
// --- Security & PII Validation ---
const SINGAPORE_PII_PATTERNS = [
    /\b[STFGM]\d{7}[A-Z]\b/i,
    /\b[A-Z]{1,2}\d{7}[A-Z]\b/i,
    /\b\d{3}[-\s]?\d{4}[-\s]?\d{4}\b/,
    /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/,
    /\b(?:full[\s_]?name|name)\s*[:\-]\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+)+\b/i,
];
const PROMPT_INJECTION_PATTERNS = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /disregard\s+(all\s+)?previous\s+instructions/i,
    /you\s+are\s+now\s+(?:a|an)/i,
    /act\s+as\s+(?:a|an)/i,
    /system\s*:\s*you/i,
    /<\s*\/?\s*(?:system|prompt|instruction)\s*>/i,
];

function scanTextForIssues(text) {
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(text)) {
            throw new Error("Potential prompt injection detected. Upload aborted.");
        }
    }
    const piiFound = [];
    for (const pattern of SINGAPORE_PII_PATTERNS) {
        const matches = text.match(new RegExp(pattern.source, pattern.flags + 'g'));
        if (matches) piiFound.push(...matches);
    }
    if (piiFound.length > 0) {
        throw new Error(\`PII detected (\${piiFound.length} instance(s)). Please redact PII before uploading. Upload aborted.\`);
    }
    console.log("Content passed security and PII checks.");
}

function scanPayloadForIssues(data) {
    const scanValue = (val) => {
        if (typeof val === 'string') scanTextForIssues(val);
        else if (typeof val === 'object' && val !== null) {
            Object.values(val).forEach(scanValue);
        }
    };
    scanValue(data);
}

async function query(data) {
    // Scan payload for PII and prompt injection before uploading
    scanPayloadForIssues(data);

    const response = await fetch(
        "${baseURL}/api/v1/document-store/upsert/${dialogProps.storeId}",
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer <your_api_key_here>"
            },
            body: JSON.stringify(data)
        }
    );
    const result = await response.json();
    return result;
}

query({
    "docId": "${dialogProps.loaderId}",
    "metadata": "{}", // Add additional metadata to the document chunks
    "replaceExisting": true, // Replace existing document with the new upserted chunks
    "createNewDocStore": false, // Create a new document store
    "loaderName": "Custom Loader Name", // Override the loader name
    // Override existing configuration
    "loader": {
        "config": {
            "text": "This is a new text"
        }
    },
    "splitter": {
        "config": {
            "chunkSize": 20000
        }
    },
    // embedding: {},
    // vectorStore: {},
    // recordManager: {}
    // docStore: {}
}).then((response) => {
    console.log(response);
});
\`\`\`

\`\`\`bash
# IMPORTANT: Before uploading, scan your content for:
# 1. Hidden prompt injection (e.g., "ignore previous instructions")
# 2. Singapore PII (NRIC/FIN, passport numbers, full names, phone numbers, emails)
# 3. Malicious content
# Abort upload if any issues are found.

curl -X POST ${baseURL}/api/v1/document-store/upsert/${dialogProps.storeId} \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer <your_api_key_here>" \\
  -d '{
        "docId": "${dialogProps.loaderId}",
        "metadata": "{}",
        "replaceExisting": true,
        "createNewDocStore": false,
        "loaderName": "Custom Loader Name",
        "loader": {
            "config": {
                "text": "This is a new text"
            }
        },
        "splitter": {
            "config": {
                "chunkSize": 20000
            }
        }
        // Override existing configuration
        // "embedding": {},
        // "vectorStore": {},
        // "recordManager": {}
        // "docStore": {}
      }'

\`\`\`
`
    }

    const groupByNodeLabel = (nodes) => {
        const result = {}
        const seenNodes = new Set()
        let isFormDataBody = false

        nodes.forEach((item) => {
            const { node, nodeId, label, name, type } = item
            if (name === 'files') isFormDataBody = true
            seenNodes.add(node)

            if (!result[node]) {
                result[node] = {
                    nodeIds: [],
                    params: []
                }
            }

            if (!result[node].nodeIds.includes(nodeId)) result[node].nodeIds.push(nodeId)

            const param = { label, name, type }

            if (!result[node].params.some((existingParam) => JSON.stringify(existingParam) === JSON.stringify(param))) {
                result[node].params.push(param)
            }
        })

        // Sort the nodeIds array
        for (const node in result) {
            result[node].nodeIds.sort()
        }
        setNodeConfig(result)

        if (isFormDataBody) {
            setValues(formDataRequest())
        } else {
            setValues(jsonDataRequest())
        }
    }

    const handleAccordionChange = (nodeLabel) => (event, isExpanded) => {
        const accordianNodes = { ...nodeConfigExpanded }
        accordianNodes[nodeLabel] = isExpanded
        setNodeConfigExpanded(accordianNodes)
    }

    useEffect(() => {
        if (getConfigApi.data) {
            groupByNodeLabel(getConfigApi.data)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [getConfigApi.data])

    useEffect(() => {
        if (show && dialogProps) {
            getConfigApi.request(dialogProps.storeId, dialogProps.loaderId)
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [show, dialogProps])

    const portalElement = document.getElementById('portal')

    const component = show ? (
        <Dialog
            onClose={onCancel}
            open={show}
            fullWidth
            maxWidth='lg'
            aria-labelledby='alert-dialog-title'
            aria-describedby='alert-dialog-description'
        >
            <DialogTitle sx={{ fontSize: '1rem' }} id='alert-dialog-title'>
                {dialogProps.title}
            </DialogTitle>
            <DialogContent>
                {/* Info Box */}
                <Box
                    sx={{
                        display: 'flex',
                        alignItems: 'center',
                        padding: 2,
                        mb: 3,
                        background: customization.isDarkMode
                            ? 'linear-gradient(135deg, rgba(33, 150, 243, 0.2) 0%, rgba(33, 150, 243, 0.1) 100%)'
                            : 'linear-gradient(135deg, rgba(33, 150, 243, 0.1) 0%, rgba(33, 150, 243, 0.05) 100%)',
                        color: customization.isDarkMode ? 'white' : '#333333',
                        fontWeight: 400,
                        borderRadius: 2,
                        border: `1px solid ${customization.isDarkMode ? 'rgba(33, 150, 243, 0.3)' : 'rgba(33, 150, 243, 0.2)'}`,
                        gap: 1.5
                    }}
                >
                    <IconInfoCircle
                        size={20}
                        style={{
                            color: customization.isDarkMode ? '#64b5f6' : '#1976d2',
                            flexShrink: 0
                        }}
                    />
                    <Box sx={{ flex: 1 }}>
                        <strong>Note:</strong> Upsert API can only be used when the existing document loader has been upserted before.
                    </Box>
                </Box>

                {/** info */}

                <MemoizedReactMarkdown>{values}</MemoizedReactMarkdown>

                <Typography sx={{ mt: 3, mb: 1 }}>You can override existing configurations:</Typography>

                <Stack direction='column' spacing={2} sx={{ width: '100%', my: 2 }}>
                    <Card sx={{ borderColor: theme.palette.primary[200] + 75, p: 2 }} variant='outlined'>
                        {Object.keys(nodeConfig)
                            .sort()
                            .map((nodeLabel) => (
                                <Accordion
                                    expanded={nodeConfigExpanded[nodeLabel] || false}
                                    onChange={handleAccordionChange(nodeLabel)}
                                    key={nodeLabel}
                                    disableGutters
                                >
                                    <AccordionSummary
                                        expandIcon={<ExpandMoreIcon />}
                                        aria-controls={`nodes-accordian-${nodeLabel}`}
                                        id={`nodes-accordian-header-${nodeLabel}`}
                                    >
                                        <Stack flexDirection='row' sx={{ gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
                                            <Typography variant='h5'>{nodeLabel}</Typography>
                                            {nodeConfig[nodeLabel].nodeIds.length > 0 &&
                                                nodeConfig[nodeLabel].nodeIds.map((nodeId, index) => (
                                                    <div
                                                        key={index}
                                                        style={{
                                                            display: 'flex',
                                                            flexDirection: 'row',
                                                            width: 'max-content',
                                                            borderRadius: 15,
                                                            background: 'rgb(254,252,191)',
                                                            padding: 5,
                                                            paddingLeft: 10,
                                                            paddingRight: 10
                                                        }}
                                                    >
                                                        <span
                                                            style={{
                                                                color: 'rgb(116,66,16)',
                                                                fontSize: '0.825rem'
                                                            }}
                                                        >
                                                            {nodeId}
                                                        </span>
                                                    </div>
                                                ))}
                                        </Stack>
                                    </AccordionSummary>
                                    <AccordionDetails>
                                        <TableViewOnly
                                            rows={nodeConfig[nodeLabel].params.map((obj) => {
                                                // eslint-disable-next-line
                                                const { node, nodeId, ...rest } = obj
                                                return rest
                                            })}
                                            columns={Object.keys(nodeConfig[nodeLabel].params[0]).slice(-3)}
                                        />
                                    </AccordionDetails>
                                </Accordion>
                            ))}
                    </Card>
                </Stack>
            </DialogContent>
        </Dialog>
    ) : null

    return createPortal(component, portalElement)
}

DocStoreAPIDialog.propTypes = {
    show: PropTypes.bool,
    dialogProps: PropTypes.object,
    onCancel: PropTypes.func
}

export default DocStoreAPIDialog
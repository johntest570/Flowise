import express from 'express'
import exportImportController from '../../controllers/export-import'
import { checkPermission } from '../../enterprise/rbac/PermissionCheck'
const router = express.Router()

function containsMaliciousContent(value: string): boolean {
    // Check for hidden prompt injection patterns
    if (/ignore\s+previous\s+instructions/i.test(value)) return true
    if (/system\s*:/i.test(value)) return true
    if (/\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i.test(value)) return true

    // Check for base64-encoded payloads
    if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) && value.length > 100) {
        try {
            const decoded = Buffer.from(value, 'base64').toString('utf8')
            if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(decoded)) return true
        } catch (e) {
            // ignore
        }
    }

    // Check for invisible/zero-width characters
    if (/[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]/.test(value)) return true

    // Check for leetspeak patterns
    if (/[i1][g9][n][o0][r][e3]\s+[p][r][e3][v][i1][o0][u][s5]/i.test(value)) return true

    // Check for shell command sequences
    if (/(\|\s*\w+|;\s*\w+|&&\s*\w+|\$\(|\`[^`]*\`|>\s*\/|<\s*\/|\/bin\/|\/etc\/passwd|\/etc\/shadow)/i.test(value)) return true

    // Check for binary/executable signatures
    if (/^(MZ|\x7fELF|PK\x03\x04|\xff\xfe|\xfe\xff)/.test(value)) return true
    if (/\x00\x00\x00\x00/.test(value)) return true

    return false
}

function scanObjectForMaliciousContent(obj: unknown): boolean {
    if (typeof obj === 'string') {
        return containsMaliciousContent(obj)
    }
    if (Array.isArray(obj)) {
        return obj.some((item) => scanObjectForMaliciousContent(item))
    }
    if (obj !== null && typeof obj === 'object') {
        return Object.values(obj).some((val) => scanObjectForMaliciousContent(val))
    }
    return false
}

function importPayloadSanitizer(req: express.Request, res: express.Response, next: express.NextFunction): void {
    if (req.body && scanObjectForMaliciousContent(req.body)) {
        res.status(400).json({ error: 'Malicious content detected in import payload' })
        return
    }
    next()
}

router.post('/export', checkPermission('workspace:export'), exportImportController.exportData)

router.post('/chatflow-messages', checkPermission('workspace:export'), exportImportController.exportChatflowMessages)

router.post('/import', checkPermission('workspace:import'), importPayloadSanitizer, exportImportController.importData)

export default router
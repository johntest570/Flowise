import { Request, Response, NextFunction } from 'express'
import logService from '../../services/log'

const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/

// Get logs
const getLogs = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { startDate, endDate } = req.query

        if (typeof startDate !== 'string' || !ISO_DATE_REGEX.test(startDate)) {
            return res.status(400).json({ error: 'Invalid or missing startDate. Expected format: YYYY-MM-DD' })
        }

        if (typeof endDate !== 'string' || !ISO_DATE_REGEX.test(endDate)) {
            return res.status(400).json({ error: 'Invalid or missing endDate. Expected format: YYYY-MM-DD' })
        }

        const apiResponse = await logService.getLogs(startDate, endDate)
        res.send(apiResponse)
    } catch (error) {
        next(error)
    }
}

export default {
    getLogs
}
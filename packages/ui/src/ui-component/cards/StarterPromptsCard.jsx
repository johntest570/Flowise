import Box from '@mui/material/Box'
import PropTypes from 'prop-types'
import { Chip } from '@mui/material'
import './StarterPromptsCard.css'

const MAX_PROMPT_LENGTH = 500

const sanitizePrompt = (prompt) => {
    if (typeof prompt !== 'string') return ''
    let sanitized = prompt.trim()
    sanitized = sanitized.replace(/\0/g, '')
    sanitized = sanitized.replace(/<[^>]*>/g, '')
    sanitized = sanitized.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '')
    sanitized = sanitized.replace(/javascript\s*:/gi, '')
    sanitized = sanitized.replace(/on\w+\s*=/gi, '')
    if (sanitized.length > MAX_PROMPT_LENGTH) {
        sanitized = sanitized.substring(0, MAX_PROMPT_LENGTH)
    }
    return sanitized
}

const StarterPromptsCard = ({ isGrid, starterPrompts, sx, onPromptClick }) => {
    return (
        <Box
            className={'button-container'}
            sx={{ width: '100%', maxWidth: isGrid ? 'inherit' : '400px', p: 1.5, display: 'flex', gap: 1, ...sx }}
        >
            {starterPrompts.map((sp, index) => (
                <Chip
                    label={sp.prompt}
                    className={'button'}
                    key={index}
                    onClick={(e) => {
                        const sanitized = sanitizePrompt(sp.prompt)
                        if (sanitized) onPromptClick(sanitized, e)
                    }}
                />
            ))}
        </Box>
    )
}

StarterPromptsCard.propTypes = {
    isGrid: PropTypes.bool,
    starterPrompts: PropTypes.array,
    sx: PropTypes.object,
    onPromptClick: PropTypes.func
}

export default StarterPromptsCard
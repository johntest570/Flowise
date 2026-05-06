import { Command, Flags } from '@oclif/core'
import dotenv from 'dotenv'
import path from 'path'
import logger from '../utils/logger'

dotenv.config({ path: path.join(__dirname, '..', '..', '.env'), override: true })

enum EXIT_CODE {
    SUCCESS = 0,
    FAILED = 1
}

const ALLOWED_ENV_KEYS = new Set([
    // General Settings
    'FLOWISE_FILE_SIZE_LIMIT',
    'CUSTOM_MCP_TOOLS_MAX_BYTES',
    'CUSTOM_MCP_AUTHORIZE_TIMEOUT_MS',
    'PORT',
    'CORS_ORIGINS',
    'MCP_CORS_ORIGINS',
    'IFRAME_ORIGINS',
    'DEBUG',
    'NUMBER_OF_PROXIES',
    'SHOW_COMMUNITY_NODES',
    'DISABLE_FLOWISE_TELEMETRY',
    'DISABLED_NODES',

    // Logging
    'LOG_PATH',
    'LOG_LEVEL',
    'LOG_SANITIZE_BODY_FIELDS',
    'LOG_SANITIZE_HEADER_FIELDS',

    // Custom tool/function dependencies
    'TOOL_FUNCTION_BUILTIN_DEP',
    'TOOL_FUNCTION_EXTERNAL_DEP',
    'ALLOW_BUILTIN_DEP',

    // Database
    'DATABASE_TYPE',
    'DATABASE_PATH',
    'DATABASE_PORT',
    'DATABASE_HOST',
    'DATABASE_NAME',
    'DATABASE_USER',
    'DATABASE_PASSWORD',
    'DATABASE_SSL',
    'DATABASE_SSL_KEY_BASE64',
    'DATABASE_REJECT_UNAUTHORIZED',

    // Langsmith tracing (non-credential config)
    'LANGCHAIN_TRACING_V2',
    'LANGCHAIN_ENDPOINT',
    'LANGCHAIN_PROJECT',

    // Model list config
    'MODEL_LIST_CONFIG_JSON',

    // Storage
    'STORAGE_TYPE',
    'BLOB_STORAGE_PATH',
    'S3_STORAGE_BUCKET_NAME',
    'S3_STORAGE_ACCESS_KEY_ID',
    'S3_STORAGE_SECRET_ACCESS_KEY',
    'S3_STORAGE_REGION',
    'S3_ENDPOINT_URL',
    'S3_FORCE_PATH_STYLE',
    'GOOGLE_CLOUD_STORAGE_PROJ_ID',
    'GOOGLE_CLOUD_STORAGE_BUCKET_NAME',
    'GOOGLE_CLOUD_UNIFORM_BUCKET_ACCESS',
    'AZURE_BLOB_STORAGE_ACCOUNT_NAME',
    'AZURE_BLOB_STORAGE_CONTAINER_NAME',

    // Credentials / Secret Keys
    'SECRETKEY_STORAGE_TYPE',
    'SECRETKEY_PATH',
    'FLOWISE_SECRETKEY_OVERWRITE',
    'SECRETKEY_AWS_REGION',
    'SECRETKEY_AWS_NAME',

    // Queue
    'MODE',
    'WORKER_CONCURRENCY',
    'QUEUE_NAME',
    'QUEUE_REDIS_EVENT_STREAM_MAX_LEN',
    'REMOVE_ON_AGE',
    'REMOVE_ON_COUNT',
    'REDIS_URL',
    'REDIS_HOST',
    'REDIS_PORT',
    'REDIS_USERNAME',
    'REDIS_PASSWORD',
    'REDIS_TLS',
    'REDIS_CERT',
    'REDIS_KEY',
    'REDIS_CA',
    'REDIS_KEEP_ALIVE',
    'ENABLE_BULLMQ_DASHBOARD',

    // Security
    'CUSTOM_MCP_SECURITY_CHECK',
    'CUSTOM_MCP_PROTOCOL',
    'HTTP_DENY_LIST',
    'HTTP_SECURITY_CHECK',
    'PATH_TRAVERSAL_SAFETY',
    'TRUST_PROXY',
    'OAUTH2_SECURITY_CHECK',
    'OAUTH2_ALLOWED_TOKEN_DOMAINS',

    // Auth
    'APP_URL',
    'SMTP_HOST',
    'SMTP_PORT',
    'SMTP_SECURE',
    'ALLOW_UNAUTHORIZED_CERTS',
    'SENDER_EMAIL',
    'JWT_AUTH_TOKEN_SECRET',
    'JWT_REFRESH_TOKEN_SECRET',
    'JWT_ISSUER',
    'JWT_AUDIENCE',
    'JWT_TOKEN_EXPIRY_IN_MINUTES',
    'JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES',
    'EXPIRE_AUTH_TOKENS_ON_RESTART',
    'EXPRESS_SESSION_SECRET',
    'SECURE_COOKIES',
    'INVITE_TOKEN_EXPIRY_IN_HOURS',
    'PASSWORD_RESET_TOKEN_EXPIRY_IN_MINS',
    'PASSWORD_SALT_HASH_ROUNDS',
    'TOKEN_HASH_SECRET',
    'WORKSPACE_INVITE_TEMPLATE_PATH',

    // Enterprise
    'LICENSE_URL',
    'FLOWISE_EE_LICENSE_KEY',
    'OFFLINE',

    // Metrics
    'POSTHOG_PUBLIC_API_KEY',
    'ENABLE_METRICS',
    'METRICS_PROVIDER',
    'METRICS_INCLUDE_NODE_METRICS',
    'METRICS_SERVICE_NAME',
    'METRICS_OPEN_TELEMETRY_METRIC_ENDPOINT',
    'METRICS_OPEN_TELEMETRY_PROTOCOL',
    'METRICS_OPEN_TELEMETRY_DEBUG',

    // Proxy
    'GLOBAL_AGENT_HTTP_PROXY',
    'GLOBAL_AGENT_HTTPS_PROXY',
    'GLOBAL_AGENT_NO_PROXY',

    // Document Loaders
    'PUPPETEER_EXECUTABLE_FILE_PATH',
    'PLAYWRIGHT_EXECUTABLE_FILE_PATH',

    // Schedule
    'MIN_SCHEDULE_INTERVAL_SECONDS'
])

const ENV_KEY_PATTERN = /^[A-Za-z0-9_]+$/
const MAX_ENV_VALUE_LENGTH = 4096

function sanitizeEnvValue(value: string): string {
    // Strip control characters
    // eslint-disable-next-line no-control-regex
    const stripped = value.replace(/[\x00-\x1F\x7F]/g, '')
    // Enforce maximum length
    return stripped.slice(0, MAX_ENV_VALUE_LENGTH)
}

export abstract class BaseCommand extends Command {
    static flags = {
        // General Settings
        FLOWISE_FILE_SIZE_LIMIT: Flags.string(),
        CUSTOM_MCP_TOOLS_MAX_BYTES: Flags.string(),
        CUSTOM_MCP_AUTHORIZE_TIMEOUT_MS: Flags.string(),
        PORT: Flags.string(),
        CORS_ORIGINS: Flags.string(),
        MCP_CORS_ORIGINS: Flags.string(),
        IFRAME_ORIGINS: Flags.string(),
        DEBUG: Flags.string(),
        NUMBER_OF_PROXIES: Flags.string(),
        SHOW_COMMUNITY_NODES: Flags.string(),
        DISABLE_FLOWISE_TELEMETRY: Flags.string(),
        DISABLED_NODES: Flags.string(),

        // Logging
        LOG_PATH: Flags.string(),
        LOG_LEVEL: Flags.string(),
        LOG_SANITIZE_BODY_FIELDS: Flags.string(),
        LOG_SANITIZE_HEADER_FIELDS: Flags.string(),

        // Custom tool/function dependencies
        TOOL_FUNCTION_BUILTIN_DEP: Flags.string(),
        TOOL_FUNCTION_EXTERNAL_DEP: Flags.string(),
        ALLOW_BUILTIN_DEP: Flags.string(),

        // Database
        DATABASE_TYPE: Flags.string(),
        DATABASE_PATH: Flags.string(),
        DATABASE_PORT: Flags.string(),
        DATABASE_HOST: Flags.string(),
        DATABASE_NAME: Flags.string(),
        DATABASE_USER: Flags.string(),
        DATABASE_PASSWORD: Flags.string(),
        DATABASE_SSL: Flags.string(),
        DATABASE_SSL_KEY_BASE64: Flags.string(),
        DATABASE_REJECT_UNAUTHORIZED: Flags.string(),

        // Langsmith tracing (non-credential config only)
        LANGCHAIN_TRACING_V2: Flags.string(),
        LANGCHAIN_ENDPOINT: Flags.string(),
        LANGCHAIN_PROJECT: Flags.string(),

        // Model list config
        MODEL_LIST_CONFIG_JSON: Flags.string(),

        // Storage
        STORAGE_TYPE: Flags.string(),
        BLOB_STORAGE_PATH: Flags.string(),
        S3_STORAGE_BUCKET_NAME: Flags.string(),
        S3_STORAGE_ACCESS_KEY_ID: Flags.string(),
        S3_STORAGE_SECRET_ACCESS_KEY: Flags.string(),
        S3_STORAGE_REGION: Flags.string(),
        S3_ENDPOINT_URL: Flags.string(),
        S3_FORCE_PATH_STYLE: Flags.string(),
        GOOGLE_CLOUD_STORAGE_PROJ_ID: Flags.string(),
        GOOGLE_CLOUD_STORAGE_BUCKET_NAME: Flags.string(),
        GOOGLE_CLOUD_UNIFORM_BUCKET_ACCESS: Flags.string(),
        AZURE_BLOB_STORAGE_ACCOUNT_NAME: Flags.string(),
        AZURE_BLOB_STORAGE_CONTAINER_NAME: Flags.string(),

        // Credentials / Secret Keys
        SECRETKEY_STORAGE_TYPE: Flags.string(),
        SECRETKEY_PATH: Flags.string(),
        FLOWISE_SECRETKEY_OVERWRITE: Flags.string(),
        SECRETKEY_AWS_REGION: Flags.string(),
        SECRETKEY_AWS_NAME: Flags.string(),

        // Queue
        MODE: Flags.string(),
        WORKER_CONCURRENCY: Flags.string(),
        QUEUE_NAME: Flags.string(),
        QUEUE_REDIS_EVENT_STREAM_MAX_LEN: Flags.string(),
        REMOVE_ON_AGE: Flags.string(),
        REMOVE_ON_COUNT: Flags.string(),
        REDIS_URL: Flags.string(),
        REDIS_HOST: Flags.string(),
        REDIS_PORT: Flags.string(),
        REDIS_USERNAME: Flags.string(),
        REDIS_PASSWORD: Flags.string(),
        REDIS_TLS: Flags.string(),
        REDIS_CERT: Flags.string(),
        REDIS_KEY: Flags.string(),
        REDIS_CA: Flags.string(),
        REDIS_KEEP_ALIVE: Flags.string(),
        ENABLE_BULLMQ_DASHBOARD: Flags.string(),

        // Security
        CUSTOM_MCP_SECURITY_CHECK: Flags.string(),
        CUSTOM_MCP_PROTOCOL: Flags.string(),
        HTTP_DENY_LIST: Flags.string(),
        HTTP_SECURITY_CHECK: Flags.string(),
        PATH_TRAVERSAL_SAFETY: Flags.string(),
        TRUST_PROXY: Flags.string(),
        OAUTH2_SECURITY_CHECK: Flags.string(),
        OAUTH2_ALLOWED_TOKEN_DOMAINS: Flags.string(),

        // Auth
        APP_URL: Flags.string(),
        SMTP_HOST: Flags.string(),
        SMTP_PORT: Flags.string(),
        SMTP_SECURE: Flags.string(),
        ALLOW_UNAUTHORIZED_CERTS: Flags.string(),
        SENDER_EMAIL: Flags.string(),
        JWT_AUTH_TOKEN_SECRET: Flags.string(),
        JWT_REFRESH_TOKEN_SECRET: Flags.string(),
        JWT_ISSUER: Flags.string(),
        JWT_AUDIENCE: Flags.string(),
        JWT_TOKEN_EXPIRY_IN_MINUTES: Flags.string(),
        JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES: Flags.string(),
        EXPIRE_AUTH_TOKENS_ON_RESTART: Flags.string(),
        EXPRESS_SESSION_SECRET: Flags.string(),
        SECURE_COOKIES: Flags.string(),
        INVITE_TOKEN_EXPIRY_IN_HOURS: Flags.string(),
        PASSWORD_RESET_TOKEN_EXPIRY_IN_MINS: Flags.string(),
        PASSWORD_SALT_HASH_ROUNDS: Flags.string(),
        TOKEN_HASH_SECRET: Flags.string(),
        WORKSPACE_INVITE_TEMPLATE_PATH: Flags.string(),

        // Enterprise
        LICENSE_URL: Flags.string(),
        FLOWISE_EE_LICENSE_KEY: Flags.string(),
        OFFLINE: Flags.string(),

        // Metrics
        POSTHOG_PUBLIC_API_KEY: Flags.string(),
        ENABLE_METRICS: Flags.string(),
        METRICS_PROVIDER: Flags.string(),
        METRICS_INCLUDE_NODE_METRICS: Flags.string(),
        METRICS_SERVICE_NAME: Flags.string(),
        METRICS_OPEN_TELEMETRY_METRIC_ENDPOINT: Flags.string(),
        METRICS_OPEN_TELEMETRY_PROTOCOL: Flags.string(),
        METRICS_OPEN_TELEMETRY_DEBUG: Flags.string(),

        // Proxy
        GLOBAL_AGENT_HTTP_PROXY: Flags.string(),
        GLOBAL_AGENT_HTTPS_PROXY: Flags.string(),
        GLOBAL_AGENT_NO_PROXY: Flags.string(),

        // Document Loaders
        PUPPETEER_EXECUTABLE_FILE_PATH: Flags.string(),
        PLAYWRIGHT_EXECUTABLE_FILE_PATH: Flags.string(),

        // Schedule
        MIN_SCHEDULE_INTERVAL_SECONDS: Flags.string()
    }

    protected async stopProcess() {
        // Overridden method by child class
    }

    protected onTerminate() {
        return async () => {
            try {
                // Shut down the app after timeout if it ever stuck removing pools
                setTimeout(async () => {
                    logger.info('Flowise was forced to shut down after 30 secs')
                    await this.failExit()
                }, 30000)

                await this.stopProcess()
            } catch (error) {
                logger.error('There was an error shutting down Flowise...', error)
            }
        }
    }

    protected async gracefullyExit() {
        process.exit(EXIT_CODE.SUCCESS)
    }

    protected async failExit() {
        process.exit(EXIT_CODE.FAILED)
    }

    async init(): Promise<void> {
        await super.init()

        process.on('SIGTERM', this.onTerminate())
        process.on('SIGINT', this.onTerminate())

        // Prevent throw new Error from crashing the app
        // TODO: Get rid of this and send proper error message to ui
        process.on('uncaughtException', (err) => {
            logger.error('uncaughtException: ', err)
        })

        process.on('unhandledRejection', (err) => {
            logger.error('unhandledRejection: ', err)
        })

        const { flags } = await this.parse(this.constructor as any)
        Object.keys(flags).forEach((key) => {
            if (Object.prototype.hasOwnProperty.call(flags, key) && flags[key]) {
                // Validate key: must match alphanumeric/underscore pattern and be in the allowlist
                if (!ENV_KEY_PATTERN.test(key) || !ALLOWED_ENV_KEYS.has(key)) {
                    logger.warn(`Skipping disallowed or invalid environment variable key: ${key}`)
                    return
                }
                // Sanitize value: strip control characters and enforce max length
                process.env[key] = sanitizeEnvValue(flags[key])
            }
        })
    }
}
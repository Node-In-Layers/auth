import attempt from 'lodash/attempt.js'
import isError from 'lodash/isError.js'
import { JsonAble, JsonObj } from 'functional-models'
import { z } from 'zod'
import {
  ApiAuthenticationConfig,
  ApiAuthenticationOAuthConfig,
  AuthClientConfig,
  AuthClientCredentials,
  AuthConfig,
  AuthNamespace,
  OAuthClientCredentialsConfig,
} from '../types.js'
import { DefaultLoginRequestSchema, User } from '../core/types.js'
import {
  ClientAuthResult,
  ClientAuthState,
  ClientLoginProps,
  ClientLoginResult,
  ClientRefreshResult,
} from './types.js'

export const defaultLoginPath = '/login'
export const defaultRefreshPath = '/token/refresh'
export const defaultAuthHeader = 'Authorization'
export const defaultAuthFormatter = (key: string) => `Bearer ${key}`
export const defaultTokenRefreshBufferMs = 60_000
export const base64BlockSize = 4
export const jwtSecondsToMilliseconds = 1000
export const oauth2DefaultExpirySeconds = 3600
export const oauth2LoginApproach = 'oauth2'
export const defaultOAuthUserFirstName = 'OAuth'
export const defaultOAuthUserLastName = 'Client'

export type BuildUrlProps = Readonly<{
  baseUrl: string
  path: string
}>

export type ClientCredentialsArgs = Readonly<{
  tokenEndpoint?: string
  clientId?: string
  clientSecret?: string
  scopes: readonly string[]
}>

export type ResolvedClientCredentialsArgs = Readonly<{
  tokenEndpoint: string
  clientId: string
  clientSecret: string
  scopes: readonly string[]
}>

export type ResolvedClientServiceSettings = Readonly<{
  clientConfig: AuthClientConfig
  authConfig?: ApiAuthenticationConfig
  oauthConfig?: ApiAuthenticationOAuthConfig
  oauthClientCredentials?: OAuthClientCredentialsConfig
  baseUrl: string
  headers?: Readonly<Record<string, string>>
  tokenRefreshBufferMs: number
  loginRequestSchema: z.ZodType<JsonObj>
  loginPath: string
  refreshPath: string
}>

const _firstDefined = <T>(values: readonly (T | undefined)[]): T | undefined =>
  values.find((value): value is T => value !== undefined && value !== '')

export const resolveClientConfig = (config?: AuthConfig): AuthClientConfig => {
  const clientConfig = config?.[AuthNamespace.Client]
  if (!clientConfig) {
    throw new Error(
      `Missing required ${AuthNamespace.Client} configuration for auth/client`
    )
  }
  return clientConfig
}

export const resolveOAuthConfig = (
  clientConfig: AuthClientConfig,
  authConfig?: ApiAuthenticationConfig
): ApiAuthenticationOAuthConfig | undefined =>
  _firstDefined([clientConfig.credentials?.oauth, authConfig?.oauth])

export const resolveTokenRefreshBufferMs = (
  clientConfig: AuthClientConfig
): number =>
  _firstDefined([
    clientConfig.refreshBufferMs,
    defaultTokenRefreshBufferMs,
  ]) as number

export const resolveLoginRequestSchema = (
  authConfig?: ApiAuthenticationConfig
): z.ZodType<JsonObj> =>
  _firstDefined([
    authConfig?.loginPropsSchema,
    DefaultLoginRequestSchema,
  ]) as z.ZodType<JsonObj>

export const resolveLoginPath = (
  clientConfig: AuthClientConfig,
  authConfig?: ApiAuthenticationConfig
): string =>
  _firstDefined([
    clientConfig.loginPath,
    authConfig?.loginPath,
    defaultLoginPath,
  ]) as string

export const resolveRefreshPath = (
  clientConfig: AuthClientConfig,
  authConfig?: ApiAuthenticationConfig
): string =>
  _firstDefined([
    clientConfig.refreshPath,
    authConfig?.refreshPath,
    defaultRefreshPath,
  ]) as string

export const resolveClientServiceSettings = (
  config?: AuthConfig
): ResolvedClientServiceSettings => {
  const clientConfig = resolveClientConfig(config)
  const authConfig = config?.[AuthNamespace.Api]?.authentication
  const oauthConfig = resolveOAuthConfig(clientConfig, authConfig)
  return {
    clientConfig,
    authConfig,
    oauthConfig,
    oauthClientCredentials: oauthConfig?.clientCredentials,
    baseUrl: clientConfig.baseUrl,
    headers: clientConfig.headers,
    tokenRefreshBufferMs: resolveTokenRefreshBufferMs(clientConfig),
    loginRequestSchema: resolveLoginRequestSchema(authConfig),
    loginPath: resolveLoginPath(clientConfig, authConfig),
    refreshPath: resolveRefreshPath(clientConfig, authConfig),
  }
}

export const resolveRefreshTokenValue = (
  props?: { refreshToken?: string },
  state?: ClientAuthState
): string => {
  const refreshToken = _firstDefined([props?.refreshToken, state?.refreshToken])
  if (!refreshToken) {
    throw new Error(
      'No refresh token available. Call login first or pass refreshToken.'
    )
  }
  return refreshToken
}

export const resolveOAuthFallbackExpiresAtMs = (
  expiresIn?: unknown
): number => {
  const expiresInSeconds =
    typeof expiresIn === 'number' ? expiresIn : oauth2DefaultExpirySeconds
  return Date.now() + expiresInSeconds * jwtSecondsToMilliseconds
}

export const buildUrl = (props: BuildUrlProps) => {
  const normalizedBase = props.baseUrl.endsWith('/')
    ? props.baseUrl.slice(0, -1)
    : props.baseUrl
  const normalizedPath = props.path.startsWith('/')
    ? props.path
    : `/${props.path}`
  return `${normalizedBase}${normalizedPath}`
}

export const resolveUrl = (
  baseUrl: string | undefined,
  path: string,
  hasHttpClient: boolean
) => {
  if (baseUrl) {
    return buildUrl({
      baseUrl,
      path,
    })
  }
  if (!hasHttpClient) {
    throw new Error(
      'Auth client requires auth client baseUrl config (or a custom httpClient).'
    )
  }
  return path
}

export const decodeBase64Url = (value: string): string | undefined => {
  const normalized = value.replace(/-/gu, '+').replace(/_/gu, '/')
  const padded =
    normalized +
    '='.repeat(
      (base64BlockSize -
        (normalized.length % base64BlockSize || base64BlockSize)) %
        base64BlockSize
    )
  if (typeof globalThis.atob === 'function') {
    return globalThis.atob(padded)
  }
  const runtimeBuffer = (
    globalThis as {
      Buffer?: {
        from: (
          input: string,
          encoding: string
        ) => {
          toString: (encoding: string) => string
        }
      }
    }
  ).Buffer
  return runtimeBuffer
    ? runtimeBuffer.from(padded, 'base64').toString('utf8')
    : undefined
}

export const parseJwtPayload = (
  token: string
): Record<string, unknown> | undefined => {
  if (!token) {
    return undefined
  }
  const payloadSegment = token.split('.')[1]
  if (!payloadSegment) {
    return undefined
  }
  const decodedPayload = decodeBase64Url(payloadSegment)
  if (!decodedPayload) {
    return undefined
  }
  const parsedPayload = attempt(
    () => JSON.parse(decodedPayload) as Record<string, JsonAble>
  )
  if (
    isError(parsedPayload) ||
    !parsedPayload ||
    typeof parsedPayload !== 'object'
  ) {
    return undefined
  }
  return parsedPayload
}

export const getTokenExpiryMs = (token: string): number | undefined => {
  const parsedPayload = parseJwtPayload(token)
  return typeof parsedPayload?.exp === 'number'
    ? parsedPayload.exp * jwtSecondsToMilliseconds
    : undefined
}

export const resolveTokenExpiryMs = (
  token: string,
  fallbackExpiresAtMs?: number
): number | undefined =>
  _firstDefined([getTokenExpiryMs(token), fallbackExpiresAtMs])

export const claimString = (
  payload: Record<string, unknown> | undefined,
  keys: readonly string[],
  fallback: string
): string => {
  const foundKey = keys.find(key => {
    const val = payload?.[key]
    return typeof val === 'string' && val.trim().length > 0
  })
  return foundKey ? (payload?.[foundKey] as string).trim() : fallback
}

export const buildUserFromOAuthToken = (
  token: string,
  clientId: string
): User => {
  const payload = parseJwtPayload(token)
  const subject = claimString(payload, ['sub', 'client_id'], clientId)
  const email = claimString(
    payload,
    ['email'],
    `${subject}@oauth-passthrough.local`
  )
  const firstName = claimString(
    payload,
    ['given_name', 'firstName'],
    defaultOAuthUserFirstName
  )
  const lastName = claimString(
    payload,
    ['family_name', 'lastName'],
    defaultOAuthUserLastName
  )
  const username = claimString(payload, ['preferred_username', 'username'], '')
  return {
    id: subject,
    email,
    ...(username ? { username } : {}),
    firstName,
    lastName,
    enabled: true,
    npeOrganization: true,
  }
}

export const isExpiredOrNearExpiry = (
  expiresAtMs: number | undefined,
  refreshBufferMs: number
): boolean => {
  if (!expiresAtMs) {
    return false
  }
  return Date.now() >= expiresAtMs - refreshBufferMs
}

export const shouldRefreshAuthState = (
  state: ClientAuthState | undefined,
  refreshBufferMs: number
): boolean => {
  if (!state) {
    return false
  }
  return (
    !state.token ||
    isExpiredOrNearExpiry(state.tokenExpiresAtMs, refreshBufferMs)
  )
}

export const isEmptyLoginProps = (
  props?: ClientLoginProps | Record<string, unknown>
): boolean => {
  if (!props) {
    return true
  }
  return Object.keys(props).filter(k => props[k] !== undefined).length === 0
}

export const extractDirectLoginCredentials = (
  credentials?: AuthClientCredentials
): Record<string, unknown> => {
  if (!credentials) {
    return {}
  }
  return {
    ...(credentials.basicAuth ? { basicAuth: credentials.basicAuth } : {}),
    ...(credentials.apiKeyAuth ? { apiKeyAuth: credentials.apiKeyAuth } : {}),
    ...(credentials.oidcAuth ? { oidcAuth: credentials.oidcAuth } : {}),
    ...(credentials.sharedSecretAuth
      ? { sharedSecretAuth: credentials.sharedSecretAuth }
      : {}),
  }
}

export const hasConfiguredCredentials = (
  credentials?: AuthClientCredentials,
  oauthClientCredentials?: OAuthClientCredentialsConfig
): boolean => {
  const directCreds = extractDirectLoginCredentials(credentials)
  if (Object.keys(directCreds).length > 0) {
    return true
  }
  return Boolean(oauthClientCredentials?.enabled)
}

export const validateClientCredentialsArgs = (
  args: ClientCredentialsArgs
): ResolvedClientCredentialsArgs => {
  if (!args.tokenEndpoint) {
    throw new Error(
      'oauth.clientCredentials.tokenEndpoint is required (or oauth.tokenEndpoint)'
    )
  }
  if (!args.clientId) {
    throw new Error(
      'oauth.clientCredentials.clientId is required (or oauth.clientId)'
    )
  }
  if (!args.clientSecret) {
    throw new Error(
      'oauth.clientCredentials.clientSecret is required (or oauth.clientSecret)'
    )
  }
  if (!args.scopes.length) {
    throw new Error(
      'oauth.clientCredentials.scopes is required (or oauth.scopes)'
    )
  }
  return {
    tokenEndpoint: args.tokenEndpoint,
    clientId: args.clientId,
    clientSecret: args.clientSecret,
    scopes: args.scopes,
  }
}

export const resolveOAuthClientCredentialsArgs = (
  oauthConfig?: ApiAuthenticationOAuthConfig
): ResolvedClientCredentialsArgs &
  Readonly<{ extraParams?: Readonly<Record<string, string>> }> => {
  const oauthClientCredentials = oauthConfig?.clientCredentials
  if (!oauthClientCredentials || !oauthClientCredentials.enabled) {
    throw new Error('OAuth2 client credentials are not enabled')
  }
  const tokenEndpoint = _firstDefined([
    oauthClientCredentials.tokenEndpoint,
    oauthConfig?.tokenEndpoint,
  ])
  const clientId = _firstDefined([
    oauthClientCredentials.clientId,
    oauthConfig?.clientId,
  ])
  const clientSecret = _firstDefined([
    oauthClientCredentials.clientSecret,
    oauthConfig?.clientSecret,
  ])
  const scopes =
    _firstDefined([oauthClientCredentials.scopes, oauthConfig?.scopes]) ??
    ([] as const)
  const resolved = validateClientCredentialsArgs({
    tokenEndpoint,
    clientId,
    clientSecret,
    scopes,
  })
  return {
    ...resolved,
    extraParams: oauthClientCredentials.extraParams,
  }
}

export const buildOAuthFormBody = (
  resolved: ResolvedClientCredentialsArgs &
    Readonly<{ extraParams?: Readonly<Record<string, string>> }>
): URLSearchParams =>
  new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: resolved.clientId,
    client_secret: resolved.clientSecret,
    scope: resolved.scopes.join(' '),
    ...(resolved.extraParams ?? {}),
  })

export const buildAuthStateFromLogin = (
  result: ClientLoginResult,
  previousState?: ClientAuthState,
  fallbackExpiresAtMs?: number
): ClientAuthState | undefined => {
  if (!result.token) {
    return undefined
  }
  return {
    token: result.token,
    refreshToken: result.refreshToken,
    user: result.user,
    loginApproach: result.loginApproach,
    tokenExpiresAtMs: resolveTokenExpiryMs(result.token, fallbackExpiresAtMs),
    header: previousState?.header,
    formatter: previousState?.formatter,
  }
}

export const buildAuthStateFromRefresh = (
  result: ClientRefreshResult,
  previousState?: ClientAuthState
): ClientAuthState | undefined => {
  if (!result.token) {
    return undefined
  }
  return {
    token: result.token,
    refreshToken: result.refreshToken,
    user: result.user,
    loginApproach: previousState?.loginApproach,
    tokenExpiresAtMs: getTokenExpiryMs(result.token),
    header: previousState?.header,
    formatter: previousState?.formatter,
  }
}

export const buildAuthStateFromManualState = (
  state?: ClientAuthState
): ClientAuthState | undefined => {
  if (!state) {
    return undefined
  }
  return {
    ...state,
    tokenExpiresAtMs: resolveTokenExpiryMs(state.token, state.tokenExpiresAtMs),
  }
}

export const authResultFromState = (
  state?: ClientAuthState
): ClientAuthResult | undefined => {
  const stateToken = state?.token
  if (!stateToken) {
    return undefined
  }
  return {
    key: stateToken,
    header: _firstDefined([state?.header, defaultAuthHeader]) as string,
    formatter: _firstDefined([state?.formatter, defaultAuthFormatter]) as (
      key: string
    ) => string,
  }
}

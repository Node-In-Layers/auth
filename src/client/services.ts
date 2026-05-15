import { ServicesContext } from '@node-in-layers/core'
import axios from 'axios'
import attempt from 'lodash/attempt.js'
import isError from 'lodash/isError.js'
import { AuthConfig, AuthNamespace } from '../types.js'
import { DefaultLoginRequestSchema } from '../core/types.js'
import {
  ClientAuthState,
  ClientLoginResult,
  ClientRefreshResult,
  ClientServices,
} from './types.js'

const defaultLoginPath = '/login'
const defaultRefreshPath = '/token/refresh'
const defaultAuthHeader = 'Authorization'
const defaultAuthFormatter = (key: string) => `Bearer ${key}`
const defaultTokenRefreshBufferMs = 60_000
const base64BlockSize = 4
const jwtSecondsToMilliseconds = 1000
const oauth2TokenExpiryBufferMs = 60_000
const oauth2DefaultExpirySeconds = 3600

type _BuildUrlProps = Readonly<{
  baseUrl: string
  path: string
}>

const _buildUrl = (props: _BuildUrlProps) => {
  const normalizedBase = props.baseUrl.endsWith('/')
    ? props.baseUrl.slice(0, -1)
    : props.baseUrl
  const normalizedPath = props.path.startsWith('/')
    ? props.path
    : `/${props.path}`
  return `${normalizedBase}${normalizedPath}`
}

const _decodeBase64Url = (value: string): string | undefined => {
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

const _getTokenExpiryMs = (token: string): number | undefined => {
  if (!token) {
    return undefined
  }
  const payloadSegment = token.split('.')[1]
  if (!payloadSegment) {
    return undefined
  }
  const decodedPayload = _decodeBase64Url(payloadSegment)
  if (!decodedPayload) {
    return undefined
  }
  const parsedPayload = attempt(
    () => JSON.parse(decodedPayload) as { exp?: unknown }
  )
  if (isError(parsedPayload)) {
    return undefined
  }
  return typeof parsedPayload.exp === 'number'
    ? parsedPayload.exp * jwtSecondsToMilliseconds
    : undefined
}

const _isExpiredOrNearExpiry = (
  expiresAtMs: number | undefined,
  refreshBufferMs: number
): boolean => {
  if (!expiresAtMs) {
    return false
  }
  return Date.now() >= expiresAtMs - refreshBufferMs
}

type _ClientCredentialsArgs = Readonly<{
  tokenEndpoint?: string
  clientId?: string
  clientSecret?: string
  scopes: readonly string[]
}>

type _ResolvedClientCredentialsArgs = Readonly<{
  tokenEndpoint: string
  clientId: string
  clientSecret: string
  scopes: readonly string[]
}>

export const create = (
  context: ServicesContext<AuthConfig>
): ClientServices => {
  const authConfig = context.config?.[AuthNamespace.Api]?.authentication
  const clientConfig = context.config?.[AuthNamespace.Client]
  if (!clientConfig) {
    throw new Error(
      `Missing required ${AuthNamespace.Client} configuration for auth/client`
    )
  }
  const oauthConfig = authConfig?.oauth
  const baseUrl = clientConfig.baseUrl
  const headers = clientConfig.headers
  const tokenRefreshBufferMs =
    clientConfig.refreshBufferMs || defaultTokenRefreshBufferMs
  const httpClient = axios.create({
    ...(baseUrl ? { baseURL: baseUrl } : {}),
    ...(headers ? { headers: headers } : {}),
  })
  const loginRequestSchema =
    authConfig?.loginPropsSchema || DefaultLoginRequestSchema
  const loginPath = authConfig?.loginPath || defaultLoginPath
  const refreshPath = authConfig?.refreshPath || defaultRefreshPath
  const oauthClientCredentials = oauthConfig?.clientCredentials
  // eslint-disable-next-line functional/no-let
  let authState: ClientAuthState | undefined
  // eslint-disable-next-line functional/no-let
  let refreshInFlight: Promise<ClientRefreshResult> | undefined
  // eslint-disable-next-line functional/no-let
  let oauthState = {
    accessToken: undefined as string | undefined,
    expiresAtMs: undefined as number | undefined,
    refreshPromise: undefined as Promise<string> | undefined,
  }

  const _applyLoginState = (result: ClientLoginResult) => {
    if (!result.token) {
      authState = undefined
      return
    }
    authState = {
      token: result.token,
      refreshToken: result.refreshToken,
      user: result.user,
      loginApproach: result.loginApproach,
      tokenExpiresAtMs: _getTokenExpiryMs(result.token),
      header: authState?.header,
      formatter: authState?.formatter,
    }
  }

  const _applyRefreshState = (result: ClientRefreshResult) => {
    if (!result.token) {
      authState = undefined
      return
    }
    authState = {
      token: result.token,
      refreshToken: result.refreshToken,
      user: result.user,
      loginApproach: authState?.loginApproach,
      tokenExpiresAtMs: _getTokenExpiryMs(result.token),
      header: authState?.header,
      formatter: authState?.formatter,
    }
  }

  const _resolveUrl = (path: string) => {
    if (baseUrl) {
      return _buildUrl({
        baseUrl,
        path,
      })
    }
    if (!httpClient) {
      throw new Error(
        'Auth client requires auth client baseUrl config (or a custom httpClient).'
      )
    }
    return path
  }

  const _validateClientCredentialsArgs = (
    args: _ClientCredentialsArgs
  ): _ResolvedClientCredentialsArgs => {
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

  const _getOAuthAccessToken = async (): Promise<string | undefined> => {
    if (!oauthClientCredentials || !oauthClientCredentials.enabled) {
      return undefined
    }
    const tokenEndpoint =
      oauthClientCredentials.tokenEndpoint || oauthConfig?.tokenEndpoint
    if (!tokenEndpoint) {
      throw new Error(
        'oauth.clientCredentials.tokenEndpoint is required (or oauth.tokenEndpoint)'
      )
    }
    const clientId = oauthClientCredentials.clientId || oauthConfig?.clientId
    const clientSecret =
      oauthClientCredentials.clientSecret || oauthConfig?.clientSecret
    const scopes =
      oauthClientCredentials.scopes || oauthConfig?.scopes || ([] as const)
    const resolvedClientCredentials = _validateClientCredentialsArgs({
      tokenEndpoint,
      clientId,
      clientSecret,
      scopes,
    })
    if (
      oauthState.accessToken &&
      oauthState.expiresAtMs &&
      Date.now() < oauthState.expiresAtMs - oauth2TokenExpiryBufferMs
    ) {
      return oauthState.accessToken
    }
    if (oauthState.refreshPromise) {
      return oauthState.refreshPromise
    }
    const refreshPromise = httpClient
      .post<{
        access_token?: string
        expires_in?: number
      }>(
        resolvedClientCredentials.tokenEndpoint,
        new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: resolvedClientCredentials.clientId,
          client_secret: resolvedClientCredentials.clientSecret,
          scope: resolvedClientCredentials.scopes.join(' '),
          ...(oauthClientCredentials.extraParams || {}),
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      )
      .then(response => {
        const token = response.data?.access_token
        if (!token) {
          throw new Error('OAuth2 client credentials returned no access_token')
        }
        const expiresInSeconds =
          typeof response.data?.expires_in === 'number'
            ? response.data.expires_in
            : oauth2DefaultExpirySeconds
        oauthState = {
          accessToken: token,
          expiresAtMs: Date.now() + expiresInSeconds * jwtSecondsToMilliseconds,
          refreshPromise: undefined,
        }
        return token
      })
      .catch(error => {
        oauthState = {
          accessToken: undefined,
          expiresAtMs: undefined,
          refreshPromise: undefined,
        }
        throw error
      })
    oauthState = {
      ...oauthState,
      refreshPromise,
    }
    return refreshPromise
  }

  const _refreshWithProps = async (props?: {
    refreshToken?: string
  }): Promise<ClientRefreshResult> => {
    const refreshToken = props?.refreshToken || authState?.refreshToken
    if (!refreshToken) {
      throw new Error(
        'No refresh token available. Call login first or pass refreshToken.'
      )
    }
    const response = await httpClient
      .post<ClientRefreshResult>(_resolveUrl(refreshPath), {
        refreshToken,
      })
      .catch(e => {
        authState = undefined
        throw e
      })
    _applyRefreshState(response.data)
    return response.data
  }

  const _refreshFromStoredState = async () => {
    if (refreshInFlight) {
      return refreshInFlight
    }
    if (!baseUrl && !httpClient) {
      throw new Error(
        'Auth client requires auth client baseUrl config (or custom httpClient) for automatic refresh.'
      )
    }
    refreshInFlight = _refreshWithProps({
      refreshToken: authState?.refreshToken,
    }).then(result => result)
    return refreshInFlight.finally(() => {
      refreshInFlight = undefined
    })
  }

  const login = async props => {
    const parsed = loginRequestSchema.safeParse(props)
    if (!parsed.success) {
      throw new Error('Invalid login request shape for auth client login')
    }
    const response = await httpClient
      .post<ClientLoginResult>(_resolveUrl(loginPath), props)
      .catch(e => {
        authState = undefined
        refreshInFlight = undefined
        throw e
      })
    _applyLoginState(response.data)
    return response.data
  }

  const refresh = _refreshWithProps

  const getAuth = async () => {
    if (
      authState?.refreshToken &&
      (!authState.token ||
        _isExpiredOrNearExpiry(
          authState.tokenExpiresAtMs,
          tokenRefreshBufferMs
        ))
    ) {
      await _refreshFromStoredState()
    }
    const currentState = authState
    const stateToken = currentState?.token
    if (stateToken) {
      return {
        key: stateToken,
        header: currentState?.header || defaultAuthHeader,
        formatter: currentState?.formatter || defaultAuthFormatter,
      }
    }
    const oauthToken = await _getOAuthAccessToken()
    return oauthToken
      ? {
          key: oauthToken,
          header: defaultAuthHeader,
          formatter: defaultAuthFormatter,
        }
      : undefined
  }

  const getState = async () => authState

  const setState = async state => {
    authState = state
      ? {
          ...state,
          tokenExpiresAtMs: _getTokenExpiryMs(state.token),
        }
      : undefined
  }

  const logout = async () => {
    authState = undefined
    refreshInFlight = undefined
    oauthState = {
      accessToken: undefined,
      expiresAtMs: undefined,
      refreshPromise: undefined,
    }
    return {
      loggedOut: true as const,
    }
  }

  return {
    login,
    refresh,
    getAuth,
    getState,
    setState,
    logout,
  }
}

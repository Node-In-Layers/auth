import { ServicesContext } from '@node-in-layers/core'
import axios from 'axios'
import { AuthConfig } from '../types.js'
import {
  authResultFromState,
  buildAuthStateFromLogin,
  buildAuthStateFromManualState,
  buildAuthStateFromRefresh,
  buildOAuthFormBody,
  buildUserFromOAuthToken,
  extractDirectLoginCredentials,
  hasConfiguredCredentials,
  isEmptyLoginProps,
  oauth2LoginApproach,
  resolveClientServiceSettings,
  resolveOAuthClientCredentialsArgs,
  resolveOAuthFallbackExpiresAtMs,
  resolveRefreshTokenValue,
  resolveUrl,
  shouldRefreshAuthState,
} from './libs.js'
import {
  ClientAuthState,
  ClientLoginProps,
  ClientLoginResult,
  ClientRefreshResult,
  ClientServices,
} from './types.js'

export const create = (
  context: ServicesContext<AuthConfig>
): ClientServices => {
  const settings = resolveClientServiceSettings(context.config)
  const {
    clientConfig,
    oauthConfig,
    oauthClientCredentials,
    baseUrl,
    headers,
    tokenRefreshBufferMs,
    loginRequestSchema,
    loginPath,
    refreshPath,
  } = settings
  const httpClient = axios.create({
    ...(baseUrl ? { baseURL: baseUrl } : {}),
    ...(headers ? { headers: headers } : {}),
  })
  // eslint-disable-next-line functional/no-let
  let authState: ClientAuthState | undefined
  // eslint-disable-next-line functional/no-let
  let refreshInFlight: Promise<ClientRefreshResult> | undefined
  // eslint-disable-next-line functional/no-let
  let loginInFlight: Promise<ClientLoginResult> | undefined

  const _loginWithOAuthClientCredentials =
    async (): Promise<ClientLoginResult> => {
      const resolved = resolveOAuthClientCredentialsArgs(oauthConfig)
      const response = await httpClient
        .post<{
          access_token?: string
          expires_in?: number
        }>(resolved.tokenEndpoint, buildOAuthFormBody(resolved), {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        })
        .catch(error => {
          authState = undefined
          throw error
        })
      const token = response.data?.access_token
      if (!token) {
        throw new Error('OAuth2 client credentials returned no access_token')
      }
      const fallbackExpiresAtMs = resolveOAuthFallbackExpiresAtMs(
        response.data?.expires_in
      )
      const result: ClientLoginResult = {
        user: buildUserFromOAuthToken(token, resolved.clientId),
        token,
        loginApproach: oauth2LoginApproach,
      }
      authState = buildAuthStateFromLogin(
        result,
        authState,
        fallbackExpiresAtMs
      )
      return result
    }

  const _refreshWithProps = async (props?: {
    refreshToken?: string
  }): Promise<ClientRefreshResult> => {
    const refreshToken = resolveRefreshTokenValue(props, authState)
    const response = await httpClient
      .post<ClientRefreshResult>(
        resolveUrl(baseUrl, refreshPath, Boolean(httpClient)),
        {
          refreshToken,
        }
      )
      .catch(e => {
        authState = undefined
        throw e
      })
    authState = buildAuthStateFromRefresh(response.data, authState)
    return response.data
  }

  const _refreshFromStoredState = async () => {
    if (refreshInFlight) {
      return refreshInFlight
    }
    refreshInFlight = _refreshWithProps({
      refreshToken: authState?.refreshToken,
    }).then(result => result)
    return refreshInFlight.finally(() => {
      refreshInFlight = undefined
    })
  }

  const _executeLogin = async (
    props: ClientLoginProps
  ): Promise<ClientLoginResult> => {
    const effectiveProps = isEmptyLoginProps(props)
      ? extractDirectLoginCredentials(clientConfig.credentials)
      : props
    if (isEmptyLoginProps(effectiveProps)) {
      if (oauthClientCredentials?.enabled) {
        return _loginWithOAuthClientCredentials()
      }
      throw new Error('Invalid login request shape for auth client login')
    }
    const parsed = loginRequestSchema.safeParse(effectiveProps)
    if (!parsed.success) {
      throw new Error('Invalid login request shape for auth client login')
    }
    const response = await httpClient
      .post<ClientLoginResult>(
        resolveUrl(baseUrl, loginPath, Boolean(httpClient)),
        effectiveProps
      )
      .catch(e => {
        authState = undefined
        refreshInFlight = undefined
        throw e
      })
    authState = buildAuthStateFromLogin(response.data, authState)
    return response.data
  }

  const login = async (props: ClientLoginProps): Promise<ClientLoginResult> => {
    if (isEmptyLoginProps(props)) {
      if (loginInFlight) {
        return loginInFlight
      }
      loginInFlight = _executeLogin(props)
      return loginInFlight.finally(() => {
        loginInFlight = undefined
      })
    }
    return _executeLogin(props)
  }

  const refresh = _refreshWithProps

  const getAuth = async () => {
    const canAutoLogin = hasConfiguredCredentials(
      clientConfig.credentials,
      oauthClientCredentials
    )
    if (shouldRefreshAuthState(authState, tokenRefreshBufferMs)) {
      if (authState?.refreshToken) {
        await _refreshFromStoredState()
      } else if (canAutoLogin) {
        await login({})
      }
    }
    if (!authState?.token && canAutoLogin) {
      await login({})
    }
    return authResultFromState(authState)
  }

  const getState = async () => authState

  const setState = async state => {
    authState = buildAuthStateFromManualState(state)
  }

  const logout = async () => {
    authState = undefined
    refreshInFlight = undefined
    loginInFlight = undefined
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

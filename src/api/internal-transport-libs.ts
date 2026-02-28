import {
  createErrorObject,
  isErrorObject,
  NilAnnotatedFunction,
  type Response,
} from '@node-in-layers/core'
import type { JsonObj } from 'functional-models'
import type { User } from '../core/types.js'
import type {
  ApiMiddleware,
  ApiProtectedRouteRegistration,
  ApiRouteHandler,
  LoginFeatureProps,
  LoginResult,
  RefreshFeatureProps,
  RefreshResult,
} from './types.js'

export const NOT_AUTHORIZED = 401
export const DEFAULT_LOGIN_PATH = '/login'
export const DEFAULT_LOGIN_METHOD = 'POST'
export const DEFAULT_REFRESH_PATH = '/token/refresh'
export const DEFAULT_REFRESH_METHOD = 'POST'

export const normalizeMethod = (method: string): string =>
  method.trim().toUpperCase()

export const getAuthorizationHeader = (
  value: string | readonly string[] | undefined
): string | undefined => (typeof value === 'string' ? value : value?.[0])

export const getBearerToken = (
  authorizationHeader: string | undefined
): string | undefined => {
  if (!authorizationHeader) {
    return undefined
  }
  const [scheme, token] = authorizationHeader.trim().split(/\s+/u, 2)
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') {
    return undefined
  }
  return token
}

export const matchesRoute = (
  reqPath: string,
  reqMethod: string,
  route: Readonly<{ path: string; method: string }>
): boolean =>
  route.path === reqPath && normalizeMethod(route.method) === reqMethod

export const toUnauthorized = (details?: unknown) =>
  createErrorObject(
    'NOT_AUTHORIZED',
    'Unauthorized',
    details ?? 'The request was not authorized.'
  )

export const createProtectedMiddleware =
  (
    unprotectedRoutes: ReadonlyArray<{ path: string; method: string }>,
    authenticate: (token: string) => Promise<Response<User>>
  ): ApiMiddleware =>
  async (req, res, next) => {
    const reqPath = req.path
    const reqMethod = normalizeMethod(req.method)
    const unprotectedRoute = unprotectedRoutes.find(route =>
      matchesRoute(reqPath, reqMethod, route)
    )
    if (unprotectedRoute) {
      next()
      return
    }

    const token = getBearerToken(
      getAuthorizationHeader(req.headers.authorization)
    )
    if (!token) {
      res
        .status(NOT_AUTHORIZED)
        .json(toUnauthorized('Missing or invalid bearer token.'))
      return
    }

    const authResult = await authenticate(token)
    if (isErrorObject(authResult)) {
      res.status(NOT_AUTHORIZED).json(authResult)
      return
    }

    // eslint-disable-next-line require-atomic-updates, functional/immutable-data
    req.user = authResult
    next()
  }

const _isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === 'object'

const _getMcpRpcMethodFromBody = (body: unknown): string | undefined => {
  if (!_isRecord(body) || typeof body.method !== 'string') {
    return undefined
  }
  return body.method
}

const _getMcpToolNameFromBody = (body: unknown): string | undefined => {
  if (!_isRecord(body)) {
    return undefined
  }
  // Some adapters pass callTool payload directly ({ name, arguments }),
  // while JSON-RPC transport uses:
  // - { method: "tools/call", params: { name, arguments } }
  // - { method: "tools/execute", params: { toolName, arguments } }
  if (typeof body.toolName === 'string') {
    return body.toolName
  }
  if (typeof body.name === 'string') {
    return body.name
  }
  const params = body.params
  if (_isRecord(params)) {
    if (typeof params.toolName === 'string') {
      return params.toolName
    }
    if (typeof params.name === 'string') {
      return params.name
    }
  }
  return undefined
}

const _ensureAuthorizedRequest = async (
  req: Parameters<ApiMiddleware>[0],
  res: Parameters<ApiMiddleware>[1],
  next: Parameters<ApiMiddleware>[2],
  authenticate: (token: string) => Promise<Response<User>>
): Promise<void> => {
  const token = getBearerToken(
    getAuthorizationHeader(req.headers.authorization)
  )
  if (!token) {
    res
      .status(NOT_AUTHORIZED)
      .json(toUnauthorized('Missing or invalid bearer token.'))
    return
  }

  const authResult = await authenticate(token)
  if (isErrorObject(authResult)) {
    res.status(NOT_AUTHORIZED).json(authResult)
    return
  }

  // eslint-disable-next-line require-atomic-updates, functional/immutable-data
  req.user = authResult
  next()
}

export const createMcpProtectedMiddleware =
  (
    unprotectedRoutes: ReadonlyArray<{ path: string; method: string }>,
    unprotectedFeatureNames: ReadonlySet<string>,
    authenticate: (token: string) => Promise<Response<User>>
  ): ApiMiddleware =>
  async (req, res, next) => {
    const reqPath = req.path
    const reqMethod = normalizeMethod(req.method)
    const unprotectedRoute = unprotectedRoutes.find(route =>
      matchesRoute(reqPath, reqMethod, route)
    )
    if (unprotectedRoute) {
      next()
      return
    }

    const rpcMethod = _getMcpRpcMethodFromBody(req.body)
    const isToolExecuteMethod =
      rpcMethod === 'tools/execute' || rpcMethod === 'tools/call'

    // For MCP protocol messages that are not tool execution (e.g. resources/read),
    // skip auth and let the MCP server handle them.
    if (rpcMethod && !isToolExecuteMethod) {
      next()
      return
    }

    const toolName = _getMcpToolNameFromBody(req.body)
    if (toolName && unprotectedFeatureNames.has(toolName)) {
      next()
      return
    }

    await _ensureAuthorizedRequest(req, res, next, authenticate)
  }

export const createLoginHandler =
  (
    login: NilAnnotatedFunction<LoginFeatureProps, LoginResult>
  ): ApiRouteHandler =>
  async (req, res) => {
    const request =
      req.body && typeof req.body === 'object' ? (req.body as JsonObj) : {}
    const userAgentRaw = req.headers['user-agent']
    const userAgent =
      typeof userAgentRaw === 'string' ? userAgentRaw : userAgentRaw?.[0]
    const result = await login({
      request,
      ip: req.ip,
      userAgent,
    })
    if (isErrorObject(result)) {
      res.status(NOT_AUTHORIZED).json(result)
      return
    }
    res.json(result)
  }

export const createRefreshHandler =
  (
    refresh: NilAnnotatedFunction<RefreshFeatureProps, RefreshResult>
  ): ApiRouteHandler =>
  async (req, res) => {
    const request =
      req.body && typeof req.body === 'object' ? (req.body as JsonObj) : {}
    const userAgentRaw = req.headers['user-agent']
    const userAgent =
      typeof userAgentRaw === 'string' ? userAgentRaw : userAgentRaw?.[0]
    const result = await refresh({
      request,
      ip: req.ip,
      userAgent,
    })
    if (isErrorObject(result)) {
      res.status(NOT_AUTHORIZED).json(result)
      return
    }
    res.json(result)
  }

export const addProtectedRouteRegistration = (
  protectedRoutes: ApiProtectedRouteRegistration[],
  path: string,
  method: string,
  handler?: ApiRouteHandler
): void => {
  // eslint-disable-next-line functional/immutable-data
  protectedRoutes.push({
    path,
    method: normalizeMethod(method),
    handler,
  })
}

export const addUnprotectedRouteRegistration = (
  unprotectedRoutes: { path: string; method: string }[],
  path: string,
  method: string
): void => {
  // eslint-disable-next-line functional/immutable-data
  unprotectedRoutes.push({
    path,
    method: normalizeMethod(method),
  })
}

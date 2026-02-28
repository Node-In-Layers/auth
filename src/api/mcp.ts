import { Config, FeaturesContext } from '@node-in-layers/core'
import { JsonObj } from 'functional-models'
import { ZodSchema } from 'zod'
import { AuthNamespace, type ApiConfig } from '../types.js'
import type {
  ApiFeaturesLayer,
  ApiHost,
  ApiMcp,
  ApiProtectedRouteRegistration,
} from './types.js'
import {
  DEFAULT_LOGIN_METHOD,
  DEFAULT_LOGIN_PATH,
  DEFAULT_REFRESH_METHOD,
  DEFAULT_REFRESH_PATH,
  addProtectedRouteRegistration,
  addUnprotectedRouteRegistration,
  createMcpProtectedMiddleware,
  createLoginHandler,
  createRefreshHandler,
  normalizeMethod,
} from './internal-transport-libs.js'

const MCP_NAMESPACE = '@node-in-layers/mcp-server'

type _McpContext = FeaturesContext<
  Config,
  object,
  ApiFeaturesLayer,
  Readonly<{ mcp?: Readonly<Record<string, unknown>> }>
>

export const create = (context: _McpContext): ApiMcp => {
  const apiConfig = context.config[AuthNamespace.Api] as ApiConfig | undefined
  const host = context[MCP_NAMESPACE] as ApiHost & {
    addTool: (tool: ServerTool) => void
  }

  const protectedRoutes: ApiProtectedRouteRegistration[] = []
  const unprotectedRoutes: { path: string; method: string }[] = []
  const unprotectedFeatureNames = new Set<string>()
  const protectedFeatureNames = new Set<string>()

  const _protectedMiddleware = createMcpProtectedMiddleware(
    unprotectedRoutes,
    unprotectedFeatureNames,
    async token => context.features[AuthNamespace.Api].authenticate({ token })
  )

  /**
   * Adds a custom route that is protected by authentication.
   * @param path The path of the route.
   * @param method The method of the route.
   * @param authCallback
   * @param handler
   */
  const addCustomProtectedRoute: ApiMcp['addCustomProtectedRoute'] = (
    path,
    method,
    handler
  ) => {
    addProtectedRouteRegistration(protectedRoutes, path, method, handler)
    if (!handler) {
      return
    }
    host.addAdditionalRoute({ path, method: normalizeMethod(method), handler })
  }

  const addUnprotectedRoute: ApiMcp['addUnprotectedRoute'] = (
    path,
    method,
    handler
  ) => {
    addUnprotectedRouteRegistration(unprotectedRoutes, path, method)
    if (!handler) {
      return
    }
    host.addAdditionalRoute({ path, method: normalizeMethod(method), handler })
  }

  type CallToolResult = JsonObj
  type ServerTool = {
    name: string
    description: string
    inputSchema: ZodSchema
    outputSchema?: ZodSchema
    execute: (input: any) => Promise<CallToolResult>
  }

  const addProtectedFeature: ApiMcp['addProtectedFeature'] = (
    annotatedFunction,
    options
  ) => {
    const name = options?.name || annotatedFunction.functionName
    host.addAnnotatedFunction(annotatedFunction, options)
    protectedFeatureNames.add(name)
    unprotectedFeatureNames.delete(name)
  }

  const addUnprotectedFeature: ApiMcp['addUnprotectedFeature'] = (
    annotatedFunction,
    options
  ) => {
    const name = options?.name || annotatedFunction.functionName
    host.addAnnotatedFunction(annotatedFunction, options)
    unprotectedFeatureNames.add(name)
    protectedFeatureNames.delete(name)
  }

  const addPreRouteMiddleware: ApiMcp['addPreRouteMiddleware'] = middleware => {
    // NOTE: This is a loose coupling. The system does NOT have direct dependencies on mcp-server.
    host.addPreRouteMiddleware(middleware)
  }

  const loginHandler = createLoginHandler(
    context.features[AuthNamespace.Api].login
  )
  const refreshHandler = createRefreshHandler(
    context.features[AuthNamespace.Api].refresh
  )

  addUnprotectedRoute(
    apiConfig?.loginPath || DEFAULT_LOGIN_PATH,
    apiConfig?.loginMethod || DEFAULT_LOGIN_METHOD,
    loginHandler
  )
  addUnprotectedRoute(
    apiConfig?.refreshPath || DEFAULT_REFRESH_PATH,
    apiConfig?.refreshMethod || DEFAULT_REFRESH_METHOD,
    refreshHandler
  )

  addUnprotectedFeature(context.features[AuthNamespace.Api].login)
  addProtectedFeature(context.features[AuthNamespace.Api].cleanupRefreshTokens)
  if (!apiConfig?.skipAllAuthentication) {
    addPreRouteMiddleware(_protectedMiddleware)
  }

  return {
    addCustomProtectedRoute,
    addUnprotectedRoute,
    addPreRouteMiddleware,
    addProtectedFeature,
    addUnprotectedFeature,
  }
}

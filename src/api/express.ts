import { Config, FeaturesContext } from '@node-in-layers/core'
import { AuthNamespace, type ApiConfig } from '../types.js'
import type {
  ApiExpress,
  ApiExpressHost,
  ApiFeaturesLayer,
  ApiProtectedRouteRegistration,
} from './types.js'
import {
  DEFAULT_LOGIN_METHOD,
  DEFAULT_LOGIN_PATH,
  DEFAULT_REFRESH_METHOD,
  DEFAULT_REFRESH_PATH,
  addProtectedRouteRegistration,
  addUnprotectedRouteRegistration,
  createLoginHandler,
  createRefreshHandler,
  createProtectedMiddleware,
  normalizeMethod,
} from './internal-transport-libs.js'

const EXPRESS_NAMESPACE = '@node-in-layers/rest-api/express'

type _ExpressContext = FeaturesContext<
  Config,
  object,
  ApiFeaturesLayer,
  Readonly<Record<string, unknown>>
>

export const create = (context: _ExpressContext): ApiExpress => {
  const apiConfig = context.config[AuthNamespace.Api] as ApiConfig | undefined
  const host = context[EXPRESS_NAMESPACE] as ApiExpressHost
  const protectedRoutes: ApiProtectedRouteRegistration[] = []
  const unprotectedRoutes: { path: string; method: string }[] = []

  const _protectedMiddleware = createProtectedMiddleware(
    unprotectedRoutes,
    async token => context.features[AuthNamespace.Api].authenticate({ token })
  )

  const addCustomProtectedRoute: ApiExpress['addCustomProtectedRoute'] = (
    path,
    method,
    handler
  ) => {
    addProtectedRouteRegistration(protectedRoutes, path, method, handler)
    if (!handler) {
      return
    }
    host.addRoute(normalizeMethod(method).toLowerCase(), path, handler)
  }

  const addUnprotectedRoute: ApiExpress['addUnprotectedRoute'] = (
    path,
    method,
    handler
  ) => {
    addUnprotectedRouteRegistration(unprotectedRoutes, path, method)
    if (!handler) {
      return
    }
    host.addRoute(normalizeMethod(method).toLowerCase(), path, handler)
  }

  const addPreRouteMiddleware: ApiExpress['addPreRouteMiddleware'] =
    middleware => {
      // NOTE: This is a loose coupling. The system does NOT have direct dependencies on rest-api.
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

  if (!apiConfig?.skipAllAuthentication) {
    addPreRouteMiddleware(_protectedMiddleware)
  }

  return {
    addCustomProtectedRoute,
    addUnprotectedRoute,
    addPreRouteMiddleware,
  }
}

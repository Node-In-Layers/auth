import express from 'express'
import type { AxiosInstance } from 'axios'
import type { JsonObj } from 'functional-models'
import type {
  LayerFunction,
  ModelCrudsFunctions,
  NilAnnotatedFunction,
  XOR,
  Response,
  CrossLayerProps,
} from '@node-in-layers/core'
import type { Request, Response as ExpressResponse } from 'express'
import { AuthNamespace, type OidcUserLookupIdentifiers } from '../types.js'
import type {
  PolicyContext,
  PolicyEvaluationResponse,
  User,
  SystemJwt,
  LoginResult,
  LoginFeatureProps,
  RefreshFeatureProps,
  RefreshResult,
  RefreshTokenResult,
  CleanupRefreshTokensResult,
  AuthenticateProps,
  TokenExchangeRequest,
  TokenExchangeResult,
} from '../core/types.js'

/**
 * Reference to a custom user model in the form domain.PluralModelName.
 * @interface
 */
export type CustomUserModelReference = Readonly<{
  domain: string
  modelName: string
}>

/** Layer function for a login approach: accepts login props and returns the user if successful. */
export type LoginApproach<T extends JsonObj = JsonObj> = LayerFunction<
  (props: LoginFeatureProps<T>) => Promise<User | undefined>
>

/**
 * API auth services: JWT build/validate, refresh token lifecycle, and login approaches.
 * @interface
 */
export type ApiServices = Readonly<{
  getPassthroughHttpClient: (crossLayerProps: CrossLayerProps) => AxiosInstance
  exchangeAccessToken: LayerFunction<
    (props?: TokenExchangeRequest) => Promise<TokenExchangeResult>
  >
  getOnBehalfOfHttpClient: LayerFunction<
    (props?: TokenExchangeRequest) => Promise<AxiosInstance>
  >
  buildJwt: LayerFunction<(user: User) => SystemJwt>
  buildRefreshToken: LayerFunction<(user: User) => Promise<RefreshTokenResult>>
  cleanupRefreshTokens: LayerFunction<() => Promise<CleanupRefreshTokensResult>>
  refreshToken: LayerFunction<(refreshToken: string) => Promise<RefreshResult>>
  validateJwt: LayerFunction<(token: string) => Promise<User>>
  verifyJwtWithJwks: LayerFunction<(token: string) => Promise<JsonObj>>
  getOidcUserLookupIdentifiers: LayerFunction<
    (payload: JsonObj) => OidcUserLookupIdentifiers
  >
  findUserByOidcIdentifiers: LayerFunction<
    (identifiers: OidcUserLookupIdentifiers) => Promise<User | undefined>
  >
  provisionOidcPassthroughUser: LayerFunction<
    (payload: JsonObj, identifiers: OidcUserLookupIdentifiers) => Promise<User>
  >
  apiKeyAuthLogin: LoginApproach
  oidcAuthLogin: LoginApproach
  basicAuthLogin: LoginApproach
  /**
   * Critical function for getting the user object. If the system replaces the user model, then we/system creators
   * need the ability to get the correct user object.
   * @returns The CRUDS functions for the user model.
   */
  getUserCruds: <TUser extends User = User>(
    crossLayerProps?: CrossLayerProps
  ) => ModelCrudsFunctions<TUser>
}>

/** Layer shape exposing API auth services under the auth API namespace. */
export type ApiServicesLayer = Readonly<{
  [AuthNamespace.Api]: ApiServices
}>

/**
 * API auth features: login, authenticate, refresh, and cleanupRefreshTokens.
 * @interface
 */
export type ApiFeatures = Readonly<{
  login: NilAnnotatedFunction<LoginFeatureProps, LoginResult>
  authenticate: NilAnnotatedFunction<AuthenticateProps, User | void>
  refresh: NilAnnotatedFunction<RefreshFeatureProps, RefreshResult>
  cleanupRefreshTokens: NilAnnotatedFunction<
    JsonObj,
    CleanupRefreshTokensResult
  >
  authorize: LayerFunction<
    (props: PolicyContext) => Promise<Response<PolicyEvaluationResponse>>
  >
}>

/** Layer shape exposing API auth features under the auth API namespace. */
export type ApiFeaturesLayer = Readonly<{
  [AuthNamespace.Api]: ApiFeatures
}>

/** HTTP method string for API routes (e.g. GET, POST). */
export type ApiRouteMethod = string

/** Express-style request handler for an API route. */
export type ApiRouteHandler = (
  req: Request,
  res: ExpressResponse
) => Promise<void> | void

/** Express-style middleware for API routes. */
export type ApiMiddleware = (
  req: Request,
  res: ExpressResponse,
  next: () => void
) => Promise<void> | void

/**
 * Registration for an additional API route (path, method, handler).
 * @interface
 */
export type ApiAdditionalRoute = Readonly<{
  path: string
  method: ApiRouteMethod
  handler: ApiRouteHandler
}>

/**
 * Registration for a protected route; handler is optional when using a default.
 * @interface
 */
export type ApiProtectedRouteRegistration = Readonly<{
  path: string
  method: ApiRouteMethod
  handler?: ApiRouteHandler
}>

type _CrossLayerPropMiddleware = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => Promise<Record<string, any> | void>

/**
 * Host interface for registering annotated functions, middleware, and additional routes.
 * @interface
 */
export type ApiHost = Readonly<{
  addAnnotatedFunction: <TIn extends JsonObj, TOut extends XOR<JsonObj, void>>(
    annotatedFunction: NilAnnotatedFunction<TIn, TOut>,
    options?: object
  ) => void
  addCrossLayerPropMiddleware: (middleware: _CrossLayerPropMiddleware) => void
  addPreRouteMiddleware: (middleware: ApiMiddleware) => void
  addAdditionalRoute: (route: ApiAdditionalRoute) => void
}>

/**
 * Express-specific host: pre-route middleware and raw route registration.
 * @interface
 */
export type ApiExpressHost = Readonly<{
  addPreRouteMiddleware: (middleware: ApiMiddleware) => void
  addRoute: (method: string, route: string, func: ApiRouteHandler) => void
}>

/**
 * MCP host interface: protected/unprotected routes and features, middleware.
 * @interface
 */
export type ApiMcp = Readonly<{
  addCustomProtectedRoute: LayerFunction<
    (path: string, method: string, handler?: ApiRouteHandler) => void
  >
  addUnprotectedRoute: LayerFunction<
    (path: string, method: string, handler?: ApiRouteHandler) => void
  >
  addPreRouteMiddleware: LayerFunction<(middleware: ApiMiddleware) => void>
  addProtectedFeature: <TIn extends JsonObj, TOut extends XOR<JsonObj, void>>(
    annotatedFunction: NilAnnotatedFunction<TIn, TOut>,
    options?: Readonly<{
      name?: string
      description?: string
    }>
  ) => void
  addUnprotectedFeature: <TIn extends JsonObj, TOut extends XOR<JsonObj, void>>(
    annotatedFunction: NilAnnotatedFunction<TIn, TOut>,
    options?: Readonly<{
      name?: string
      description?: string
    }>
  ) => void
}>

/** Layer shape exposing API MCP host under the auth API namespace. */
export type ApiMcpLayer = Readonly<{
  [AuthNamespace.Api]: ApiMcp
}>

/**
 * Express transport: register protected/unprotected routes and pre-route middleware.
 * @interface
 */
export type ApiExpress = Readonly<{
  addCustomProtectedRoute: LayerFunction<
    (path: string, method: string, handler?: ApiRouteHandler) => void
  >
  addUnprotectedRoute: LayerFunction<
    (path: string, method: string, handler?: ApiRouteHandler) => void
  >
  addPreRouteMiddleware: LayerFunction<(middleware: ApiMiddleware) => void>
}>

/** Layer shape exposing API Express transport under the auth API namespace. */
export type ApiExpressLayer = Readonly<{
  [AuthNamespace.Api]: ApiExpress
}>

import type { JsonObj } from 'functional-models'
import type {
  LayerFunction,
  ModelCrudsFunctions,
  NilAnnotatedFunction,
  Response,
  XOR,
} from '@node-in-layers/core'
import { annotationFunctionProps } from '@node-in-layers/core'
import type { Request, Response as ExpressResponse } from 'express'
import { z } from 'zod'
import { AuthNamespace } from '../types.js'
import { UserSchema } from '../core/types.js'
import type { User } from '../core/types.js'

/**
 * Reference to a custom user model in the form domain.PluralModelName.
 * @interface
 */
export type CustomUserModelReference = Readonly<{
  domain: string
  modelName: string
}>

/**
 * Result of a successful login: user, access token, refresh token, and login approach used.
 * @interface
 */
export type LoginResult = Readonly<{
  user: User
  token: string
  refreshToken: string
  loginApproach: string
}>

/**
 * Input for the login feature: request payload plus optional client ip and userAgent.
 * @interface
 */
export type LoginFeatureProps<T extends JsonObj = JsonObj> = Readonly<{
  request: T
  ip?: string
  userAgent?: string
}>

/**
 * Input for the refresh feature: request payload plus optional client ip and userAgent.
 * @interface
 */
export type RefreshFeatureProps<T extends JsonObj = JsonObj> = Readonly<{
  request: T
  ip?: string
  userAgent?: string
}>

/**
 * System-issued JWT access token.
 * @interface
 */
export type SystemJwt = Readonly<{
  token: string
}>

/**
 * Result of creating a refresh token: opaque token value, expiration, and TTL for cleanup.
 * @interface
 */
export type RefreshTokenResult = Readonly<{
  token: string
  expiresAt: string
  ttlSeconds: number
}>

/**
 * Result of refreshing tokens: user, new access token, and new refresh token.
 * @interface
 */
export type RefreshResult = Readonly<{
  user: User
  token: string
  refreshToken: string
}>

/**
 * Result of cleanupRefreshTokens: number of expired refresh tokens deleted.
 * @interface
 */
export type CleanupRefreshTokensResult = Readonly<{
  deletedCount: number
}>

/** Props for the authenticate feature (JWT token). */
export type AuthenticateProps = SystemJwt

/** Layer function for a login approach: accepts login props and returns the user if successful. */
export type LoginApproach<T extends JsonObj = JsonObj> = LayerFunction<
  (props: LoginFeatureProps<T>) => Promise<User | undefined>
>

/**
 * API auth services: JWT build/validate, refresh token lifecycle, and login approaches.
 * @interface
 */
export type ApiServices = Readonly<{
  buildJwt: LayerFunction<(user: User) => SystemJwt>
  buildRefreshToken: LayerFunction<(user: User) => Promise<RefreshTokenResult>>
  cleanupRefreshTokens: LayerFunction<() => Promise<CleanupRefreshTokensResult>>
  refreshToken: LayerFunction<(refreshToken: string) => Promise<RefreshResult>>
  validateJwt: LayerFunction<(token: string) => Promise<User>>
  apiKeyAuthLogin: LoginApproach
  oidcAuthLogin: LoginApproach
  basicAuthLogin: LoginApproach
  /**
   * Critical function for getting the user object. If the system replaces the user model, then we/system creators
   * need the ability to get the correct user object.
   * @returns The CRUDS functions for the user model.
   */
  getUserCruds: <TUser extends User = User>() => ModelCrudsFunctions<TUser>
}>

/** Layer shape exposing API auth services under the auth API namespace. */
export type ApiServicesLayer = Readonly<{
  [AuthNamespace.Api]: ApiServices
}>

export const BasicAuthRequestSchema = z.object({
  basicAuth: z.object({
    identifier: z.string(),
    password: z.string(),
  }),
})

export const ApiKeyAuthRequestSchema = z.object({
  apiKeyAuth: z.object({
    key: z.string(),
  }),
})

export const OidcAuthRequestSchema = z.object({
  oidcAuth: z.object({
    token: z.string(),
  }),
})

/**
 * Default request schema for login feature input.
 * Exactly one built-in login payload should be provided.
 */
export const DefaultLoginRequestSchema = z
  .object({
    basicAuth: BasicAuthRequestSchema.shape.basicAuth.optional(),
    apiKeyAuth: ApiKeyAuthRequestSchema.shape.apiKeyAuth.optional(),
    oidcAuth: OidcAuthRequestSchema.shape.oidcAuth.optional(),
  })
  .refine(
    value =>
      [value.basicAuth, value.apiKeyAuth, value.oidcAuth].filter(
        v => v !== undefined
      ).length === 1,
    {
      message:
        'Exactly one login payload is required: basicAuth, apiKeyAuth, or oidcAuth.',
    }
  )

/**
 * Recursive schema for JSON-serializable values (JsonAble).
 * Used to build a request schema whose output type is JsonObj.
 */
const JsonAbleSchema = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.undefined(),
    z.array(JsonAbleSchema),
    z.record(z.string(), JsonAbleSchema),
  ])
)

/** Request body schema constrained to JsonObj for LoginFeatureProps/RefreshFeatureProps. */
export const RequestSchema = z.record(
  z.string(),
  JsonAbleSchema
) as unknown as z.ZodType<JsonObj>

export const LoginFeaturePropsSchema = z.object({
  request: RequestSchema,
  ip: z.string().optional(),
  userAgent: z.string().optional(),
})

export const LoginResultSchema = z.object({
  user: UserSchema,
  token: z.string(),
  refreshToken: z.string(),
  loginApproach: z.string(),
})

export const LoginSchema = annotationFunctionProps<
  LoginFeatureProps,
  LoginResult
>({
  functionName: 'login',
  domain: AuthNamespace.Api,
  args: LoginFeaturePropsSchema,
  returns: LoginResultSchema,
})

export const AuthenticatePropsSchema = z.object({
  token: z.string(),
})

export const AuthenticateSchema = annotationFunctionProps<
  AuthenticateProps,
  User
>({
  functionName: 'authenticate',
  domain: AuthNamespace.Api,
  args: AuthenticatePropsSchema,
  returns: UserSchema,
})

export const RefreshFeaturePropsSchema = z.object({
  request: RequestSchema,
  ip: z.string().optional(),
  userAgent: z.string().optional(),
})

export const RefreshResultSchema = z.object({
  user: UserSchema,
  token: z.string(),
  refreshToken: z.string(),
})

export const RefreshSchema = annotationFunctionProps<
  RefreshFeatureProps,
  RefreshResult
>({
  functionName: 'refresh',
  domain: AuthNamespace.Api,
  args: RefreshFeaturePropsSchema,
  returns: RefreshResultSchema,
})

export const CleanupRefreshTokensResultSchema = z.object({
  deletedCount: z.number(),
})

export const CleanupRefreshTokensSchema = annotationFunctionProps<
  JsonObj,
  CleanupRefreshTokensResult
>({
  functionName: 'cleanupRefreshTokens',
  domain: AuthNamespace.Api,
  args: z.record(z.string(), z.any()),
  returns: CleanupRefreshTokensResultSchema,
})

/**
 * API auth features: login, authenticate, refresh, and cleanupRefreshTokens.
 * @interface
 */
export type ApiFeatures = Readonly<{
  login: NilAnnotatedFunction<LoginFeatureProps, LoginResult>
  authenticate: NilAnnotatedFunction<AuthenticateProps, User>
  refresh: NilAnnotatedFunction<RefreshFeatureProps, RefreshResult>
  cleanupRefreshTokens: NilAnnotatedFunction<
    JsonObj,
    CleanupRefreshTokensResult
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

/**
 * Host interface for registering annotated functions, middleware, and additional routes.
 * @interface
 */
export type ApiHost = Readonly<{
  addAnnotatedFunction: <TIn extends JsonObj, TOut extends XOR<JsonObj, void>>(
    annotatedFunction: NilAnnotatedFunction<TIn, TOut>,
    options?: object
  ) => void
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

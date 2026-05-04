import { Config, XOR } from '@node-in-layers/core'
import { z } from 'zod'
import {
  DataDescription,
  PrimaryKeyType,
  PropertyConfig,
  PropertyInstance,
  JsonObj,
} from 'functional-models'

/** Policy rule action: allow or deny access. */
export enum PolicyAction {
  Allow = 'ALLOW',
  Deny = 'DENY',
}

/**
 * Policy entity: name, action (allow/deny), resources, and optional attribute constraints.
 * @interface
 */
export type Policy = Readonly<{
  id: PrimaryKeyType
  name: string
  description?: string
  organizationId?: PrimaryKeyType
  action: PolicyAction
  /**
   * Resource policy strings for stating what resources can be accessed.
   */
  resources: ReadonlyArray<string>
  /**
   * Specific users this policy targets directly.
   */
  userIds?: ReadonlyArray<PrimaryKeyType>
  /**
   * Data attribute level controls. "You must have this key:value attribute in order to access this data"
   * If this is not provided, this policy applies to everyone who is associated with the organization.
   * (This happens by the OrganizationAttribute model with a key "member" and the value being the user's id.)
   */
  attributes?: readonly Record<string, string>[]
  createdAt?: string
  updatedAt?: string
}>

/**
 * Factory for creating a property instance with optional config and metadata.
 * Used when overriding or extending user model properties in auth config.
 */
export type PropertyFactory<
  TValue extends PrimaryKeyType,
  TData extends DataDescription = DataDescription,
  TModelExtensions extends object = object,
  TModelInstanceExtensions extends object = object,
> = (
  config?: PropertyConfig<TValue>,
  additionalMetadata?: Record<string, any>
) => PropertyInstance<TValue, TData, TModelExtensions, TModelInstanceExtensions>

/** Auth package namespace identifiers for core and API layers. */
export enum AuthNamespace {
  Core = '@node-in-layers/auth/core',
  Api = '@node-in-layers/auth/api',
  McpClient = '@node-in-layers/auth/mcp-client',
  Client = '@node-in-layers/auth/client',
}

/** Registered login approach service names for the API layer. */
export enum LoginApproachServiceName {
  ApiKeyAuthLogin = `${AuthNamespace.Api}.apiKeyAuthLogin`,
  OidcAuthLogin = `${AuthNamespace.Api}.oidcAuthLogin`,
  BasicAuthLogin = `${AuthNamespace.Api}.basicAuthLogin`,
}

/**
 * How OAuth pass-through treats the incoming Bearer token.
 * - **Jwks**: JWT verified against configured JWKS; user resolved or auto-provisioned.
 * - **Opaque**: Any non-empty Bearer is accepted; no user is set (req.user stays unset).
 */
export enum OAuthPassthroughValidateMode {
  Jwks = 'jwks',
  Opaque = 'opaque',
}

/**
 * OAuth 2.0 token endpoint client authentication method.
 * @interface
 */
export enum TokenExchangeClientAuth {
  ClientSecretBasic = 'client_secret_basic',
  ClientSecretPost = 'client_secret_post',
}

/**
 * Shared OAuth client authentication settings.
 */
export type OAuthClientConfig = Readonly<{
  clientId: string
  clientSecret: string
  clientAuth?: TokenExchangeClientAuth
}>

/**
 * OIDC claims used to look up or match a local user (e.g. from an ID token).
 * @interface
 */
export type OidcUserLookupIdentifiers = Readonly<{
  sub?: string
  iss?: string
}>

/**
 * OIDC settings used by oauth login/passthrough jwt validation.
 * `jwksUris` is required whenever this section is provided.
 */
export type OAuthOidcConfig = Readonly<{
  issuer?: string
  jwksUris: readonly string[]
  parsePayloadIdentifiers?: (payload: JsonObj) => OidcUserLookupIdentifiers
}>

/**
 * OAuth pass-through configuration.
 */
export type OAuthPassthroughDisabledConfig = Readonly<{
  enabled: false
}>

export type OAuthPassthroughEnabledConfig = Readonly<{
  enabled: true
  validateMode?: OAuthPassthroughValidateMode
  autoProvision?: boolean
  claimMapping?: Readonly<{
    email?: string
    firstName?: string
    lastName?: string
    username?: string
  }>
}>

export type OAuthPassthroughConfig = XOR<
  OAuthPassthroughDisabledConfig,
  OAuthPassthroughEnabledConfig
>

/**
 * OAuth token exchange per-target override configuration.
 */
export type OAuthTokenExchangeTargetConfig = Readonly<{
  tokenEndpoint?: string
  audience?: string
  resource?: string
  scope?: string
  extraParams?: Readonly<Record<string, string>>
}>

/**
 * OAuth token exchange configuration.
 * When enabled, client credentials are required.
 */
export type OAuthTokenExchangeDisabledConfig = Readonly<{
  enabled: false
  targets?: Readonly<Record<string, OAuthTokenExchangeTargetConfig>>
  extraParams?: Readonly<Record<string, string>>
  defaultAudience?: string
  defaultResource?: string
  defaultScope?: string
  tokenEndpoint?: string
  clientAuth?: TokenExchangeClientAuth
}>

export type OAuthTokenExchangeEnabledConfig = Readonly<{
  enabled: true
  tokenEndpoint?: string
  clientId?: string
  clientSecret?: string
  clientAuth?: TokenExchangeClientAuth
  defaultAudience?: string
  defaultResource?: string
  defaultScope?: string
  targets?: Readonly<Record<string, OAuthTokenExchangeTargetConfig>>
  extraParams?: Readonly<Record<string, string>>
}>

export type OAuthTokenExchangeConfig = XOR<
  OAuthTokenExchangeDisabledConfig,
  OAuthTokenExchangeEnabledConfig
>

/**
 * OAuth2 client credentials configuration for auth client token acquisition.
 */
export type OAuthClientCredentialsDisabledConfig = Readonly<{
  enabled: false
}>

export type OAuthClientCredentialsEnabledConfig = Readonly<{
  enabled: true
  tokenEndpoint?: string
  clientId?: string
  clientSecret?: string
  clientAuth?: TokenExchangeClientAuth
  scopes?: readonly string[]
  extraParams?: Readonly<Record<string, string>>
}>

export type OAuthClientCredentialsConfig = XOR<
  OAuthClientCredentialsDisabledConfig,
  OAuthClientCredentialsEnabledConfig
>

/**
 * OAuth/OIDC configuration grouping all oauth-related auth settings.
 */
export type ApiAuthenticationOAuthConfig = Readonly<{
  tokenEndpoint?: string
  scopes?: readonly string[]
  clientId?: string
  clientSecret?: string
  clientAuth?: TokenExchangeClientAuth
  oidc?: OAuthOidcConfig
  passthrough?: OAuthPassthroughConfig
  tokenExchange?: OAuthTokenExchangeConfig
  clientCredentials?: OAuthClientCredentialsConfig
}>

/**
 * All API-layer authentication settings: login, JWT, refresh tokens, transport paths, OAuth pass-through.
 * @interface
 */
export type ApiAuthenticationConfig = Readonly<{
  /**
   * If true, bypasses auth middleware (use with caution).
   * NOTE: Bypasses authentication checks only where middleware honors this flag.
   */
  skipAllAuthentication?: boolean
  /**
   * The domain.featureName for each login approach, in order.
   * Use [] only when oauth.passthrough.enabled is true (no password/API-key/OIDC login chain).
   */
  loginApproaches: ReadonlyArray<LoginApproachServiceName | string>
  /**
   * Optional override schema for login request payload (`props.request`).
   */
  loginPropsSchema?: z.ZodType<JsonObj>
  loginPath?: string
  loginMethod?: string
  refreshPath?: string
  refreshMethod?: string
  /**
   * Optional client-side base url for @node-in-layers/auth/client HTTP calls.
   * Example: https://api.example.com/auth
   */
  clientBaseUrl?: string
  /**
   * Optional default headers for @node-in-layers/auth/client HTTP calls.
   */
  clientHeaders?: Readonly<Record<string, string>>
  /**
   * Optional refresh buffer in ms used by @node-in-layers/auth/client.
   * If token expiry is within this window, client will refresh automatically.
   */
  clientRefreshBufferMs?: number
  basicAuthIdentifiers?: ReadonlyArray<'email' | 'username'>
  oauth?: ApiAuthenticationOAuthConfig
  /** Required when core allowPasswordAuthentication is true. */
  passwordHashSecretKey?: string
  noSaveLoginAttempts?: boolean
  jwtSecret?: string
  jwtIssuer?: string
  jwtAudience?: string
  jwtExpiresInSeconds?: number
  refreshTokens?: Readonly<{
    ttlDays?: number
    expiresInMinutes?: number
    cleanupBatchSize?: number
    cleanupMaxQueries?: number
  }>
  jwtAlgorithms?: readonly string[]
}>

/**
 * API-layer config: authorization (policy middleware) and authentication (everything else for authn).
 * @interface
 */
export type ApiConfig = Readonly<{
  authorization?: {
    skipAllAuthorization?: boolean
  }
  authentication: ApiAuthenticationConfig
}>

export type AuthClientConfig = Readonly<{
  baseUrl: string
  headers?: Readonly<Record<string, string>>
  refreshBufferMs?: number
}>

/**
 * Auth configuration keyed by namespace: core (user model, policies) and optional API config.
 * @interface
 */
export type AuthConfigurations = Readonly<{
  [AuthNamespace.Core]: {
    /**
     * A replacement model for the User model.
     * Should be in the format of
     * domain.PluralModelName
     */
    userModel?: string
    systemLevelPolicies: readonly Policy[]
    userPropertyOverrides?: Record<string, PropertyConfig<object>>
    /**
     * If this is true, then the system will require a password hash for a user.
     */
    allowPasswordAuthentication?: boolean
  }
  [AuthNamespace.Client]?: AuthClientConfig
  [AuthNamespace.Api]?: ApiConfig
}>

/**
 * Full application config including auth: core config plus AuthConfigurations.
 * @interface
 */
export type AuthConfig = Config & AuthConfigurations

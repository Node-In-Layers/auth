import { Config } from '@node-in-layers/core'
import { z } from 'zod'
import {
  DataDescription,
  PrimaryKeyType,
  PropertyConfig,
  PropertyInstance,
  JsonObj,
} from 'functional-models'
import { Policy } from './core/types.js'

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
}

/** Registered login approach service names for the API layer. */
export enum LoginApproachServiceName {
  ApiKeyAuthLogin = `${AuthNamespace.Api}.apiKeyAuthLogin`,
  OidcAuthLogin = `${AuthNamespace.Api}.oidcAuthLogin`,
  BasicAuthLogin = `${AuthNamespace.Api}.basicAuthLogin`,
}

/**
 * OIDC claims used to look up or match a local user (e.g. from an ID token).
 * @interface
 */
export type OidcUserLookupIdentifiers = Readonly<{
  sub?: string
  iss?: string
}>

/**
 * API-layer auth configuration: login approaches, JWT/refresh token settings, and transport paths.
 * @interface
 */
export type ApiConfig = Readonly<{
  /**
   * Optional override schema for login request payload (`props.request`).
   * If not provided, the default auth login request schema is used.
   */
  loginPropsSchema?: z.ZodType<JsonObj>
  /**
   * If this is true, then the system will skip all authentication.
   * NOTE: Be careful with this, as it will bypass all authentication and authorization checks.
   */
  skipAllAuthentication?: boolean
  /**
   * The domain.featureName for a function that can be used as a login approach.
   */
  loginApproaches: ReadonlyArray<LoginApproachServiceName | string>
  /**
   * Optional MCP/transport login path.
   * Defaults to '/login'.
   */
  loginPath?: string
  /**
   * Optional MCP/transport login method.
   * Defaults to 'POST'.
   */
  loginMethod?: string
  /**
   * Optional transport token refresh path.
   * Defaults to '/token/refresh'.
   */
  refreshPath?: string
  /**
   * Optional transport token refresh method.
   * Defaults to 'POST'.
   */
  refreshMethod?: string
  /**
   * The identifier search order for basic username/password login.
   * Defaults to ['email', 'username'].
   */
  basicAuthIdentifiers?: ReadonlyArray<'email' | 'username'>
  /**
   * Optional parser for extracting user lookup identifiers from a validated OIDC payload.
   * Returned values should include OIDC iss and sub for local identity resolution.
   */
  parseOidcPayloadIdentifiers?: (payload: JsonObj) => OidcUserLookupIdentifiers
  /**
   * Secret key used as a pepper for password hashing and verification.
   * Required when password authentication is enabled.
   */
  passwordHashSecretKey?: string
  noSaveLoginAttempts?: boolean
  jwtSecret?: string
  jwtIssuer?: string
  jwtAudience?: string
  jwtExpiresInSeconds?: number
  refreshTokens?: Readonly<{
    /**
     * Retention period for expired refresh tokens before cleanup should delete them.
     * Defaults to 30 days.
     */
    ttlDays?: number
    /**
     * Expiration duration for newly issued refresh tokens.
     * Defaults to 600 minutes.
     */
    expiresInMinutes?: number
    /**
     * Maximum number of expired refresh tokens to delete per cleanup call.
     * Defaults to 500.
     */
    cleanupBatchSize?: number
    /**
     * Maximum number of cleanup queries to run per cleanup call.
     * Defaults to 20.
     */
    cleanupMaxQueries?: number
  }>
  jwtAlgorithms?: readonly string[]
  jwksUris?: readonly string[]
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
    userPropertyOverrides?: Record<string, PropertyConfig<any>>
    /**
     * If this is true, then the system will require a password hash for a user.
     */
    allowPasswordAuthentication?: boolean
  }
  [AuthNamespace.Api]?: ApiConfig
}>

/**
 * Full application config including auth: core config plus AuthConfigurations.
 * @interface
 */
export type AuthConfig = Config & AuthConfigurations

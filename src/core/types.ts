import { CrossLayerProps, LayerFunction } from '@node-in-layers/core'
import { JsonObj, PrimaryKeyType } from 'functional-models'
import { z } from 'zod'
import { AuthNamespace, PolicyAction } from '../types.js'

export type CoreAuthConfig = Readonly<{
  caching?: {
    systemAdminCheck: number
  }
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
 * Default request schema for auth login payload.
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
  ) as z.ZodType<JsonObj>

/** Core auth layer services (reserved for future use). */
export type AuthCoreServices = Readonly<{
  isUserSystemAdmin: LayerFunction<(user: User) => Promise<boolean>>
  isOrganizationAdmin: LayerFunction<
    (user: User, organizationId: PrimaryKeyType) => Promise<boolean>
  >
  getUserOrganizationAttributes: LayerFunction<
    (user: User) => Promise<Record<string, string>>
  >
}>

/**
 * Layer shape exposing core auth services.
 * @interface
 */
export type AuthCoreServicesLayer = Readonly<{
  [AuthNamespace.Core]: AuthCoreServices
}>

/** Core auth layer features (reserved for future use). */
export type AuthCoreFeatures = Readonly<object>

/**
 * Layer shape exposing core auth features.
 * @interface
 */
export type CoreFeaturesLayer = Readonly<{
  [AuthNamespace.Core]: AuthCoreFeatures
}>

/**
 * User entity: identity, profile, and auth-related fields (password hash, enabled flag).
 * @interface
 */
export type User = Readonly<{
  id: PrimaryKeyType
  /**
   * Canonical email for the user (expected lowercase).
   */
  email: string
  /**
   * Optional username for the user (expected lowercase).
   */
  username?: string
  firstName: string
  lastName: string
  /**
   * Is this "person" a non-person entity? If so, the organization id that this non-person entity is part of, is placed here.
   * This adds the ability for your system to support having "systems" as a user. This is completely optional, and your system
   * can just make system-system connections using an actual user's credentials.
   * If there is a value here, these non-person entities, should not show up in normal user queries.
   */
  npeOrganization?: boolean
  /**
   * Password hash only if the system accepts password authentication.
   * NOTE: Whether or not this is actually optional depends on the configuration of the system.
   */
  passwordHash?: string
  /**
   * Is this user enabled and allowed to login?
   */
  enabled: boolean
  createdAt?: string
  updatedAt?: string
}>

export const UserSchema = z.object({
  id: z.xor([z.string(), z.number()]),
  email: z.string(),
  username: z.string().optional(),
  firstName: z.string(),
  lastName: z.string(),
  enabled: z.boolean(),
  npeOrganization: z.boolean().optional(),
  passwordHash: z.string().optional(),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
})

/**
 * Organization entity; owner is identified by ownerUserId.
 * @interface
 */
export type Organization = Readonly<{
  id: PrimaryKeyType
  name: string
  ownerUserId: PrimaryKeyType
  createdAt?: string
  updatedAt?: string
}>

/**
 * Links a user to an organization with admin role.
 * @interface
 */
export type OrganizationAdmin = Readonly<{
  id: PrimaryKeyType
  organizationId: PrimaryKeyType
  userId: PrimaryKeyType
  createdAt?: string
  updatedAt?: string
}>

/**
 * Key-value attribute on an organization (e.g. membership, custom data).
 * @interface
 */
export type OrganizationAttribute = Readonly<{
  id: PrimaryKeyType
  organizationId: PrimaryKeyType
  userId: PrimaryKeyType
  key: string
  value: string
  createdAt?: string
  updatedAt?: string
}>

export enum ResourceTypeForPolicy {
  Models = 'models',
  Features = 'features',
  Functions = 'functions',
}

/**
 * Standard actions for resources used in policies.
 */
export enum ActionForPolicy {
  Create = 'Create',
  Retrieve = 'Retrieve',
  Update = 'Update',
  Delete = 'Delete',
  Search = 'Search',
  Execute = 'Execute',
}

/**
 * The contextual information for evaluating policies.
 * @interface
 */
export type PolicyContext = Readonly<{
  /**
   * The domain the resource belongs to.
   */
  domain: string
  /**
   * The type of resource.
   */
  resourceType: ResourceTypeForPolicy
  /**
   * The resource name (e.g. plural model name or feature name).
   */
  resource: string
  /**
   * The action being attempted.
   */
  action: ActionForPolicy | string
  /**
   * The ID of the user attempting the action.
   */
  userId: PrimaryKeyType
  /**
   * The ID of the organization if this is an organization-scoped resource.
   */
  organizationId?: PrimaryKeyType
  /**
   * Data of the row being accessed, for row-level policies.
   */
  rowData?: Record<string, any>
  /**
   * IP address of the request
   */
  ip?: string
  /**
   * Request ID for the request
   */
  requestId?: string
}>

/**
 * The response from a policy evaluation.
 */
export type PolicyEvaluationResponse = Readonly<{
  action: PolicyAction
  reason?: string
}>

export type PolicyEngineContext = Readonly<{
  request: PolicyContext
  isSystemAdmin: boolean
  isOrgAdmin: boolean
  /**
   * User attributes mapped to a dictionary for easy lookup.
   * If the request is org-scoped, this should contain org attributes.
   * Otherwise, it can contain system-level attributes if applicable.
   */
  userAttributes: Record<string, string>
}>

/** Outcome of a single login attempt. */
export enum LoginAttemptResult {
  Success = 'success',
  Failure = 'failure',
}

/**
 * Record of one login attempt: timing, client info, user resolution, and result.
 * @interface
 */
export type LoginAttempt = Readonly<{
  id: PrimaryKeyType
  /** When the login attempt started. */
  startedAt: string
  /** When the attempt finished (set on update). */
  endedAt?: string
  /** Client IP from request metadata. */
  ip?: string
  /** User-Agent or similar from request metadata. */
  userAgent?: string
  /** Resolved user id once an approach succeeds. */
  userId?: PrimaryKeyType
  /** Set when flow completes. */
  result?: LoginAttemptResult
  /**
   * The login method that was successful.
   */
  loginApproach?: string
  createdAt?: string
  updatedAt?: string
}>

/**
 * API key entity: key value, owning user, optional name/description and expiration.
 * @interface
 */
export type ApiKey = Readonly<{
  /**
   * The primary key for the api key.
   */
  id: PrimaryKeyType
  /**
   * The user associated with the api key.
   */
  userId: string
  /**
   * The api key (uuid).
   */
  key: string
  /**
   * A user generated name for the api key.
   */
  name?: string
  /**
   * A useful description for the api key.
   */
  description?: string
  /**
   * (Optional): The date of expiration of the api key.
   */
  expiresAt?: string
  createdAt?: string
  updatedAt?: string
}>

/**
 * External identity (e.g. OIDC) linked to a local user via iss/sub.
 * @interface
 */
export type UserAuthIdentity = Readonly<{
  id: PrimaryKeyType
  /**
   * The local user this external identity maps to.
   */
  userId: PrimaryKeyType
  /**
   * OIDC issuer claim.
   */
  iss: string
  /**
   * OIDC subject claim.
   */
  sub: string
  /**
   * Optional OIDC email claim.
   */
  email?: string
  /**
   * Optional OIDC username claim.
   */
  username?: string
  createdAt?: string
  updatedAt?: string
}>

/**
 * Refresh token entity: opaque token, user, expiration, and optional rotation/revocation timestamps.
 * @interface
 */
export type RefreshToken = Readonly<{
  /**
   * Internal primary key for numeric-primary-key backends.
   * Optional because some backends use `token` as the model primary key.
   */
  id?: PrimaryKeyType
  /**
   * Opaque refresh token value sent to clients.
   * This should always be unique.
   */
  token: string
  /**
   * The user associated with this refresh token.
   */
  userId: PrimaryKeyType
  /**
   * Token expiration timestamp for auth checks.
   */
  expiresAt: string
  /**
   * Retention TTL in seconds for cleanup workflows.
   */
  ttlSeconds: number
  /**
   * Set once this refresh token is used for rotation.
   */
  usedAt?: string
  /**
   * Set when this token is explicitly revoked.
   */
  revokedAt?: string
  createdAt?: string
  updatedAt?: string
}>

/**
 * The cross layer props provided by the auth module.
 */
export type AuthCrossLayerProps = CrossLayerProps & {
  user?: User
}

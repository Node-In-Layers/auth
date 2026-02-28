import { PrimaryKeyType } from 'functional-models'
import { z } from 'zod'

/** Core auth layer services (reserved for future use). */
export type CoreServices = Readonly<object>

/**
 * Layer shape exposing core auth services.
 * @interface
 */
export type CoreServicesLayer = Readonly<{
  core: CoreServices
}>

/** Core auth layer features (reserved for future use). */
export type CoreFeatures = Readonly<object>

/**
 * Layer shape exposing core auth features.
 * @interface
 */
export type CoreFeaturesLayer = Readonly<{
  core: CoreFeatures
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
   * Data attribute level controls. "You must have this key:value attribute in order to access this data"
   * If this is not provided, this policy applies to everyone who is associated with the organization.
   * (This happens by the OrganizationAttribute model with a key "member" and the value being the user's id.)
   */
  attributes?: readonly Record<string, string>[]
  createdAt?: string
  updatedAt?: string
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

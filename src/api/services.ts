import { v4 as randomUUID } from 'uuid'
import type { ModelCrudsFunctions, ServicesContext } from '@node-in-layers/core'
import jwt from 'jsonwebtoken'
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'
import { getModel } from '@node-in-layers/core'
import { asyncMap } from 'modern-async'
import {
  DatastoreValueType,
  EqualitySymbol,
  OrmModelInstance,
  queryBuilder,
  JsonObj,
} from 'functional-models'
import {
  AuthConfig,
  AuthNamespace,
  type ApiConfig,
  type OidcUserLookupIdentifiers,
} from '../types.js'
import type {
  ApiKey,
  RefreshToken,
  User,
  UserAuthIdentity,
} from '../core/types.js'
import { parseCustomUserModelReference } from './libs.js'
import {
  getUserFromPayload,
  requirePasswordHashSecretKey,
  verifyPasswordHash,
  type _JwtPayload,
} from './internal-libs.js'
import type { ApiServices, LoginApproach } from './types.js'

const DEFAULT_REFRESH_TOKEN_TTL_DAYS = 30
const HOURS_PER_DAY = 24
const MINUTES_PER_HOUR = 60
const SECONDS_PER_MINUTE = 60
const MS_PER_SECOND = 1000
const DEFAULT_REFRESH_TOKEN_EXPIRES_IN_MINUTES = 600
const DEFAULT_REFRESH_TOKEN_CLEANUP_BATCH_SIZE = 500
const DEFAULT_REFRESH_TOKEN_CLEANUP_MAX_QUERIES = 20

type _LoginRequest = Readonly<{
  oidcAuth?: Readonly<{ token?: string }>
  apiKeyAuth?: Readonly<Record<string, string | undefined> & { key?: string }>
  basicAuth?: Readonly<{
    identifier?: string
    username?: string
    email?: string
    password?: string
  }>
}>

const _isJwtPayload = (payload: unknown): payload is JWTPayload =>
  Boolean(payload) && typeof payload === 'object'

const _nowMillis = (): number => Date.now()

const _isExpired = (expiresAt?: string): boolean => {
  if (!expiresAt) {
    return false
  }
  return new Date(expiresAt).getTime() <= _nowMillis()
}

const _normalizeIdentifier = (value?: string): string | undefined => {
  if (!value) {
    return undefined
  }
  const normalized = value.trim().toLowerCase()
  return normalized.length ? normalized : undefined
}

const _normalizeOpaqueIdentifier = (value?: string): string | undefined => {
  if (!value) {
    return undefined
  }
  const normalized = value.trim()
  return normalized.length ? normalized : undefined
}

const verifyWithSecret = async (
  token: string,
  apiConfig: ApiConfig
): Promise<_JwtPayload> => {
  const jwtSecret = apiConfig.jwtSecret
  if (!jwtSecret) {
    throw new Error('jwtSecret is required when verifying with secret')
  }
  const verified = jwt.verify(token, jwtSecret, {
    issuer: apiConfig.jwtIssuer,
    audience: apiConfig.jwtAudience,
    algorithms: apiConfig.jwtAlgorithms as jwt.Algorithm[] | undefined,
  }) as _JwtPayload
  return verified
}

const verifyWithJwks = async (
  token: string,
  apiConfig: ApiConfig
): Promise<_JwtPayload> => {
  const jwksUris = apiConfig.jwksUris ?? []
  if (!jwksUris.length) {
    throw new Error('jwksUris is required when validating jwt via jwks')
  }
  const options = {
    issuer: apiConfig.jwtIssuer,
    audience: apiConfig.jwtAudience,
  }
  const jwkSets = jwksUris.map(uri => createRemoteJWKSet(new URL(uri)))
  const failed = new Error('could not validate token with configured jwksUris')
  return jwkSets
    .reduce(
      (accP, jwkSet) =>
        accP.catch(() =>
          jwtVerify(token, jwkSet, options).then(
            result => result.payload as _JwtPayload
          )
        ),
      Promise.reject<_JwtPayload>(failed)
    )
    .catch(() => {
      throw failed
    })
}

const verifyTokenPayload = async (
  token: string,
  apiConfig: ApiConfig
): Promise<_JwtPayload> => {
  if (apiConfig.jwtSecret) {
    return verifyWithSecret(token, apiConfig)
  }
  return verifyWithJwks(token, apiConfig)
}

const getRefreshTokenSettings = (apiConfig: ApiConfig) => {
  const config = apiConfig.refreshTokens
  const ttlDays =
    config?.ttlDays && config.ttlDays > 0
      ? config.ttlDays
      : DEFAULT_REFRESH_TOKEN_TTL_DAYS
  const expiresInMinutes =
    config?.expiresInMinutes && config.expiresInMinutes > 0
      ? config.expiresInMinutes
      : DEFAULT_REFRESH_TOKEN_EXPIRES_IN_MINUTES
  const cleanupBatchSize =
    config?.cleanupBatchSize && config.cleanupBatchSize > 0
      ? config.cleanupBatchSize
      : DEFAULT_REFRESH_TOKEN_CLEANUP_BATCH_SIZE
  const cleanupMaxQueries =
    config?.cleanupMaxQueries && config.cleanupMaxQueries > 0
      ? config.cleanupMaxQueries
      : DEFAULT_REFRESH_TOKEN_CLEANUP_MAX_QUERIES
  return {
    ttlDays,
    expiresInMinutes,
    cleanupBatchSize,
    cleanupMaxQueries,
  }
}

export const create = (context: ServicesContext<AuthConfig>): ApiServices => {
  const apiConfig = context.config[AuthNamespace.Api]
  const coreConfig = context.config[AuthNamespace.Core]
  if (!apiConfig) {
    throw new Error(`${AuthNamespace.Api} configuration not found`)
  }
  if (!coreConfig) {
    throw new Error(`${AuthNamespace.Core} configuration not found`)
  }

  const UserAuthIdentities = getModel<UserAuthIdentity>(
    context,
    AuthNamespace.Core,
    'UserAuthIdentities'
  )
  const ApiKeys = getModel<ApiKey>(context, AuthNamespace.Core, 'ApiKeys')
  const RefreshTokens = getModel<RefreshToken>(
    context,
    AuthNamespace.Core,
    'RefreshTokens'
  )
  const apiKeyPrimaryKeyName = ApiKeys.getModelDefinition().primaryKeyName
  const refreshTokenPrimaryKeyName =
    RefreshTokens.getModelDefinition().primaryKeyName
  const passwordHashSecretKey = coreConfig.allowPasswordAuthentication
    ? requirePasswordHashSecretKey(apiConfig)
    : undefined

  const getUserCruds = <
    TUser extends User = User,
  >(): ModelCrudsFunctions<TUser> => {
    const customUserModel = context.config[AuthNamespace.Core].userModel
    if (customUserModel) {
      const { domain, modelName } =
        parseCustomUserModelReference(customUserModel)
      const domainObj = context.services.getServices(domain)
      if (!domainObj) {
        throw new Error(`Domain "${domain}" not found`)
      }
      const domainCruds = (domainObj as any).cruds
      if (!domainCruds) {
        throw new Error(`Domain "${domain}" does not expose cruds`)
      }
      const modelCruds = domainCruds[modelName]
      if (!modelCruds) {
        throw new Error(`Model "${modelName}" not found in domain "${domain}"`)
      }
      return modelCruds as ModelCrudsFunctions<TUser>
    }
    const authCoreCruds = context.services.getServices(
      AuthNamespace.Core
    )?.cruds
    if (!authCoreCruds?.Users) {
      throw new Error(`Default auth core Users cruds not found`)
    }
    return authCoreCruds.Users as ModelCrudsFunctions<TUser>
  }

  const _toUser = async (
    instance: OrmModelInstance<User> | undefined
  ): Promise<User | undefined> => {
    if (!instance) {
      return undefined
    }
    const enabled = await instance.get.enabled()
    if (!enabled) {
      return undefined
    }
    return instance.toObj<User>()
  }

  const _retrieveUserById = async (
    id: string | number
  ): Promise<User | undefined> => {
    const Users = getUserCruds<User>()
    const instance = await Users.retrieve(id)
    return _toUser(instance)
  }

  const _searchUserByBasicIdentifier = async (
    identifier: string
  ): Promise<User | undefined> => {
    const Users = getUserCruds<User>()
    const configured = apiConfig.basicAuthIdentifiers
    const keys: ReadonlyArray<'email' | 'username'> =
      configured && configured.length ? configured : ['email', 'username']
    if (!keys.length) {
      return undefined
    }
    const query = keys
      .slice(1)
      .reduce(
        (acc, key) => acc.or().property(key, identifier),
        queryBuilder().property(keys[0], identifier)
      )
    const result = await Users.search(query.take(1).compile())
    return _toUser(result.instances[0])
  }

  const _parseOidcIdentifiers = (
    payload: _JwtPayload
  ): OidcUserLookupIdentifiers => {
    const parsed = apiConfig.parseOidcPayloadIdentifiers
      ? apiConfig.parseOidcPayloadIdentifiers(payload as unknown as JsonObj)
      : {
          sub: typeof payload.sub === 'string' ? payload.sub : undefined,
          iss: typeof payload.iss === 'string' ? payload.iss : undefined,
        }
    return {
      sub: _normalizeOpaqueIdentifier(parsed.sub),
      iss: _normalizeIdentifier(parsed.iss),
    }
  }

  const _resolveEnabledUserFromIdentifiers = async (
    identifiers: OidcUserLookupIdentifiers
  ): Promise<User | undefined> => {
    const bySub = identifiers.sub
    const byIss = identifiers.iss
    if (!byIss || !bySub) {
      return undefined
    }
    const query = queryBuilder()
      .property('sub', bySub)
      .and()
      .property('iss', byIss)
    const result = await UserAuthIdentities.search<UserAuthIdentity>(
      query.take(1).compile()
    )
    const instance = result.instances[0]
    if (!instance) {
      return undefined
    }
    const identity = await instance.toObj<UserAuthIdentity>()
    return _retrieveUserById(identity.userId)
  }

  const _findApiKeyByKey = async (key: string): Promise<ApiKey | undefined> => {
    if (apiKeyPrimaryKeyName === 'key') {
      const instance = await ApiKeys.retrieve(key)
      if (!instance) {
        return undefined
      }
      return instance.toObj<ApiKey>()
    }
    const result = await ApiKeys.search<ApiKey>(
      queryBuilder().property('key', key).take(1).compile()
    )
    const first = result.instances[0]
    if (!first) {
      return undefined
    }
    return first.toObj<ApiKey>()
  }

  const _findRefreshTokenByToken = async (
    token: string
  ): Promise<RefreshToken | undefined> => {
    if (refreshTokenPrimaryKeyName === 'token') {
      const instance = await RefreshTokens.retrieve(token)
      if (!instance) {
        return undefined
      }
      return instance.toObj<RefreshToken>()
    }
    const result = await RefreshTokens.search<RefreshToken>(
      queryBuilder().property('token', token).take(1).compile()
    )
    const first = result.instances[0]
    if (!first) {
      return undefined
    }
    return first.toObj<RefreshToken>()
  }

  const buildJwt: ApiServices['buildJwt'] = (user: User) => {
    const jwtSecret = apiConfig.jwtSecret
    if (!jwtSecret) {
      throw new Error('auth api jwtSecret is required to build jwt')
    }
    if (!apiConfig.jwtIssuer) {
      throw new Error('auth api jwtIssuer is required to build jwt')
    }
    if (!apiConfig.jwtAudience) {
      throw new Error('auth api jwtAudience is required to build jwt')
    }
    if (!apiConfig.jwtExpiresInSeconds) {
      throw new Error('auth api jwtExpiresInSeconds is required to build jwt')
    }
    const token = jwt.sign({ user }, jwtSecret, {
      issuer: apiConfig.jwtIssuer,
      audience: apiConfig.jwtAudience,
      expiresIn: apiConfig.jwtExpiresInSeconds,
      algorithm:
        (apiConfig.jwtAlgorithms?.[0] as jwt.Algorithm | undefined) ?? 'HS256',
    })
    return { token }
  }

  const buildRefreshToken: ApiServices['buildRefreshToken'] = async (
    user: User
  ) => {
    const token = randomUUID()
    const refreshTokenSettings = getRefreshTokenSettings(apiConfig)
    const ttlSeconds =
      refreshTokenSettings.ttlDays *
      HOURS_PER_DAY *
      MINUTES_PER_HOUR *
      SECONDS_PER_MINUTE
    const expiresInMillis =
      refreshTokenSettings.expiresInMinutes * MINUTES_PER_HOUR * MS_PER_SECOND
    const expiresAt = new Date(_nowMillis() + expiresInMillis).toISOString()
    await RefreshTokens.create({
      token,
      userId: user.id,
      expiresAt,
      ttlSeconds,
    }).save()
    return { token, expiresAt, ttlSeconds }
  }

  const cleanupRefreshTokens: ApiServices['cleanupRefreshTokens'] =
    async () => {
      const refreshTokenSettings = getRefreshTokenSettings(apiConfig)
      const cleanUpBefore = new Date(
        _nowMillis() -
          refreshTokenSettings.ttlDays *
            HOURS_PER_DAY *
            MINUTES_PER_HOUR *
            SECONDS_PER_MINUTE *
            MS_PER_SECOND
      ).toISOString()
      const querySlots = Array.from(
        { length: refreshTokenSettings.cleanupMaxQueries },
        (_v, idx) => idx
      )
      const deletedCounts = await asyncMap(
        querySlots,
        async () => {
          const result = await RefreshTokens.search(
            queryBuilder()
              .property('expiresAt', cleanUpBefore, {
                type: DatastoreValueType.date,
                equalitySymbol: EqualitySymbol.lte,
              })
              .take(refreshTokenSettings.cleanupBatchSize)
              .compile()
          )
          const primaryKeys = result.instances.map(instance =>
            instance.getPrimaryKey()
          )
          if (!primaryKeys.length) {
            return 0
          }
          await RefreshTokens.bulkDelete(primaryKeys)
          return primaryKeys.length
        },
        1
      )
      const deletedCount = deletedCounts.reduce((acc, count) => acc + count, 0)
      return { deletedCount }
    }

  const refreshToken: ApiServices['refreshToken'] = async (token: string) => {
    const existing = await _findRefreshTokenByToken(token)
    if (!existing) {
      throw new Error('refresh token not found')
    }
    if (_isExpired(existing.expiresAt)) {
      throw new Error('refresh token expired')
    }
    const user = await _retrieveUserById(existing.userId)
    if (!user) {
      throw new Error('user not found for refresh token')
    }
    await RefreshTokens.bulkDelete([existing.id ?? existing.token])
    const nextRefreshToken = await buildRefreshToken(user)
    const nextJwt = buildJwt(user)
    return {
      user,
      token: nextJwt.token,
      refreshToken: nextRefreshToken.token,
    }
  }

  const validateJwt: ApiServices['validateJwt'] = async (token: string) => {
    const payload = await verifyTokenPayload(token, apiConfig)
    return getUserFromPayload(payload)
  }

  const apiKeyAuthLogin: LoginApproach = async ({ request }) => {
    const apiKeyRequest = (request as _LoginRequest).apiKeyAuth
    const key = apiKeyRequest?.key
    if (!key) {
      return undefined
    }
    const apiKey = await _findApiKeyByKey(key)
    if (!apiKey || _isExpired(apiKey.expiresAt)) {
      return undefined
    }
    return _retrieveUserById(apiKey.userId)
  }

  const basicAuthLogin: LoginApproach = async ({ request }) => {
    const basicAuth = (request as _LoginRequest).basicAuth
    const identifier = _normalizeIdentifier(
      basicAuth?.identifier ?? basicAuth?.email ?? basicAuth?.username
    )
    const password = basicAuth?.password
    if (!coreConfig.allowPasswordAuthentication || !identifier || !password) {
      return undefined
    }
    const user = await _searchUserByBasicIdentifier(identifier)
    if (!user || !passwordHashSecretKey) {
      return undefined
    }
    const matches = await verifyPasswordHash(
      password,
      user.passwordHash,
      passwordHashSecretKey
    )
    if (!matches) {
      return undefined
    }
    return user
  }

  const oidcAuthLogin: LoginApproach = async ({ request }, CrossLayerProps) => {
    const log = context.log.getInnerLogger('oidcAuthLogin', CrossLayerProps)
    const token = (request as _LoginRequest).oidcAuth?.token
    if (!token) {
      return undefined
    }
    return Promise.resolve()
      .then(async () => {
        // Login flow should validate external provider tokens against provider JWKS.
        // Local system-token validation remains in validateJwt().
        const payload = await verifyWithJwks(token, apiConfig)
        if (!_isJwtPayload(payload)) {
          return undefined
        }
        const identifiers = _parseOidcIdentifiers(payload)
        const user = await _resolveEnabledUserFromIdentifiers(identifiers)
        return user
      })
      .catch(e => {
        log.warn('Exception thrown while logging in with oidc', e)
        return undefined
      })
  }

  return {
    buildJwt,
    buildRefreshToken,
    cleanupRefreshTokens,
    refreshToken,
    validateJwt,
    apiKeyAuthLogin,
    oidcAuthLogin,
    basicAuthLogin,
    getUserCruds,
  }
}

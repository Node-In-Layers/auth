import { pbkdf2, randomBytes, timingSafeEqual } from 'node:crypto'
import get from 'lodash/get.js'
import { FeaturesContext, isErrorObject } from '@node-in-layers/core'
import { JWTPayload } from 'jose'
import { JsonAble, JsonObj } from 'functional-models'
import {
  AuthConfig,
  AuthNamespace,
  type ApiAuthenticationConfig,
  type ApiConfig,
  TokenExchangeClientAuth,
} from '../types.js'
import type {
  TokenExchangeRequest,
  TokenExchangeResult,
  User,
} from '../core/types.js'
import type { LoginApproach } from './types.js'

type _ResolvedLoginApproach = Readonly<{
  loginApproach: string
  fn: LoginApproach
}>

type _UnpackedAuth = Readonly<{
  apiConfig: ApiConfig
  loginApproaches: readonly _ResolvedLoginApproach[]
}>

const parseId = (
  id: string
): readonly [domainKey: string, serviceName: string] => {
  const i = id.lastIndexOf('.')
  if (i === -1) {
    throw new Error(
      `Invalid login approach id "${id}": expected "domain.serviceName".`
    )
  }
  const [domainKey, serviceName] = [id.slice(0, i), id.slice(i + 1)]
  if (!domainKey) {
    throw new Error(
      `Invalid login approach id "${id}": expected "domain.serviceName".`
    )
  }
  if (!serviceName) {
    throw new Error(
      `Invalid login approach id "${id}": expected "domain.serviceName".`
    )
  }
  return [domainKey, serviceName]
}

const getLoginApproachFn = (
  context: FeaturesContext<AuthConfig>,
  id: string
): LoginApproach => {
  const [domainKey, serviceName] = parseId(id)
  return ((...args: Parameters<LoginApproach>) => {
    const services =
      context.services.getServices<Record<string, unknown>>(domainKey)
    if (!services) {
      throw new Error(
        `Could not find domain "${domainKey}" for login approach "${id}".`
      )
    }
    const fn = services[serviceName]
    if (typeof fn !== 'function') {
      throw new Error(
        `Could not find function "${serviceName}" in domain "${domainKey}".`
      )
    }
    return (fn as LoginApproach)(...args)
  }) as LoginApproach
}

const ensureApiLoaded = (context: FeaturesContext<AuthConfig>): void => {
  const api = context.services[AuthNamespace.Api] as Record<string, unknown>
  if (!api) {
    throw new Error(
      `Api auth domain "${AuthNamespace.Api}" not found in context.services. Likely not loaded.`
    )
  }
}

export const unpackAuthentication = (
  context: FeaturesContext<AuthConfig>
): _UnpackedAuth => {
  const apiConfig = context.config[AuthNamespace.Api] as ApiConfig | undefined
  const auth = apiConfig?.authentication

  const passthroughOnly = auth?.oauthPassthrough?.enabled === true
  if (!auth?.loginApproaches?.length && !passthroughOnly) {
    throw new Error(
      `Auth api config not found or loginApproaches empty. Likely not included in config (${AuthNamespace.Api}).`
    )
  }

  ensureApiLoaded(context)

  if (!apiConfig) {
    throw new Error(
      `Auth api config not found. Likely not included in config (${AuthNamespace.Api}).`
    )
  }

  const approachIds = auth?.loginApproaches ?? []
  return {
    apiConfig,
    loginApproaches: approachIds.map(id => ({
      loginApproach: id,
      fn: getLoginApproachFn(context, id),
    })),
  }
}

export type _JwtPayload = JWTPayload & Readonly<{ user?: User }>

export const getUserFromPayload = (payload: _JwtPayload): User => {
  if (!payload.user) {
    throw new Error('jwt payload does not contain user')
  }
  return payload.user
}

const _PASSWORD_HASH_PREFIX = 'pbkdf2'
const _PASSWORD_HASH_SEPARATOR = '$'
const _PASSWORD_HASH_PARTS_COUNT = 6
const _PASSWORD_HASH_PART_INDEX_DIGEST = 1
const _PASSWORD_HASH_PART_INDEX_ITERATIONS = 2
const _PASSWORD_HASH_PART_INDEX_KEY_LENGTH = 3
const _PASSWORD_HASH_PART_INDEX_SALT = 4
const _PASSWORD_HASH_PART_INDEX_STORED_HASH = 5
const _PASSWORD_SALT_BYTES = 16
const _DEFAULT_PASSWORD_HASH_ITERATIONS = 210_000
const _DEFAULT_PASSWORD_HASH_KEY_LENGTH = 64
const _DEFAULT_PASSWORD_HASH_DIGEST = 'sha512'

export type PasswordHashOptions = Readonly<{
  iterations?: number
  keyLength?: number
  digest?: string
}>

const _pbkdf2 = async (
  password: string,
  salt: string,
  iterations: number,
  keyLength: number,
  digest: string
): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    pbkdf2(password, salt, iterations, keyLength, digest, (err, value) =>
      err ? reject(err) : resolve(value)
    )
  })

export const requirePasswordHashSecretKey = (
  authentication: ApiAuthenticationConfig
): string => {
  const secret = authentication.passwordHashSecretKey
  if (!secret) {
    throw new Error(
      'auth api passwordHashSecretKey is required when password authentication is enabled'
    )
  }
  return secret
}

export const hashPassword = async (
  password: string,
  secretKey: string,
  options?: PasswordHashOptions
): Promise<string> => {
  const iterations = options?.iterations ?? _DEFAULT_PASSWORD_HASH_ITERATIONS
  const keyLength = options?.keyLength ?? _DEFAULT_PASSWORD_HASH_KEY_LENGTH
  const digest = options?.digest ?? _DEFAULT_PASSWORD_HASH_DIGEST
  const salt = randomBytes(_PASSWORD_SALT_BYTES).toString('base64')
  const pepperedPassword = `${secretKey}:${password}`
  const derived = await _pbkdf2(
    pepperedPassword,
    salt,
    iterations,
    keyLength,
    digest
  )
  const hash = derived.toString('base64')
  return [
    _PASSWORD_HASH_PREFIX,
    digest,
    iterations.toString(),
    keyLength.toString(),
    salt,
    hash,
  ].join(_PASSWORD_HASH_SEPARATOR)
}

export const verifyPasswordHash = async (
  password: string,
  encodedHash: string | undefined,
  secretKey: string
): Promise<boolean> => {
  if (!encodedHash) {
    return false
  }
  const parts = encodedHash.split(_PASSWORD_HASH_SEPARATOR)
  if (
    parts.length !== _PASSWORD_HASH_PARTS_COUNT ||
    parts[0] !== _PASSWORD_HASH_PREFIX
  ) {
    return false
  }
  const digest = parts[_PASSWORD_HASH_PART_INDEX_DIGEST]
  const iterations = Number(parts[_PASSWORD_HASH_PART_INDEX_ITERATIONS])
  const keyLength = Number(parts[_PASSWORD_HASH_PART_INDEX_KEY_LENGTH])
  const salt = parts[_PASSWORD_HASH_PART_INDEX_SALT]
  const storedHash = parts[_PASSWORD_HASH_PART_INDEX_STORED_HASH]
  if (!Number.isFinite(iterations) || !Number.isFinite(keyLength)) {
    return false
  }
  const pepperedPassword = `${secretKey}:${password}`
  const derived = await _pbkdf2(
    pepperedPassword,
    salt,
    iterations,
    keyLength,
    digest
  )
  const stored = Buffer.from(storedHash, 'base64')
  return stored.length === derived.length && timingSafeEqual(stored, derived)
}

export const createMcpResponse = <T extends JsonAble>(
  result: T,
  opts?: { isError?: boolean }
): JsonObj => {
  const isError = opts?.isError || isErrorObject(result)
  return {
    ...(isError ? { isError: true } : {}),
    content: [
      {
        type: 'text',
        text: JSON.stringify(result !== undefined ? result : '""'),
      },
    ],
  }
}

export const getHeaders = (crossLayerProps: any): Record<string, string> => {
  const authorization =
    get(crossLayerProps, 'requestInfo.headers.Authorization') ||
    get(crossLayerProps, 'requestInfo.headers.authorization')
  if (authorization) {
    return {
      Authorization: authorization as string,
    }
  }
  return {}
}

/** Bearer value from an `Authorization` header, or undefined if not Bearer. */
export const getBearerFromAuthorization = (
  authorization?: string
): string | undefined => {
  if (!authorization) {
    return undefined
  }
  const [scheme, token] = authorization.trim().split(/\s+/u, 2)
  if (!scheme || !token || scheme.toLowerCase() !== 'bearer') {
    return undefined
  }
  return token
}

type _TokenExchangeConfig = NonNullable<
  ApiAuthenticationConfig['tokenExchange']
>

type _TokenExchangeTargetConfig = NonNullable<
  _TokenExchangeConfig['targets']
>[string]

export const requireEnabledTokenExchange = (
  authentication: ApiAuthenticationConfig
): _TokenExchangeConfig => {
  const tokenExchange = authentication.tokenExchange
  if (!tokenExchange?.enabled) {
    throw new Error('tokenExchange is not enabled')
  }
  return tokenExchange
}

export const resolveTokenExchangeTarget = (
  tokenExchange: _TokenExchangeConfig,
  targetName?: string
): Readonly<{ target: _TokenExchangeTargetConfig | undefined }> => {
  const target = targetName ? tokenExchange.targets?.[targetName] : undefined
  if (targetName && !target) {
    throw new Error(`tokenExchange target not found: "${targetName}"`)
  }
  return { target }
}

export const resolveTokenExchangeTokenEndpoint = (
  props: TokenExchangeRequest | undefined,
  target: _TokenExchangeTargetConfig | undefined,
  tokenExchange: _TokenExchangeConfig
): string => {
  const tokenEndpoint =
    props?.tokenEndpoint ?? target?.tokenEndpoint ?? tokenExchange.tokenEndpoint
  if (!tokenEndpoint) {
    throw new Error('tokenExchange.tokenEndpoint is required')
  }
  return tokenEndpoint
}

export const resolveTokenExchangeSubjectToken = (
  props: TokenExchangeRequest | undefined,
  authorizationHeader: string | undefined
): string => {
  const subjectToken =
    props?.subjectToken ?? getBearerFromAuthorization(authorizationHeader)
  if (!subjectToken) {
    throw new Error(
      'tokenExchange requires a subject token (props.subjectToken or incoming Authorization bearer)'
    )
  }
  return subjectToken
}

export const resolveTokenExchangeAudienceResourceScope = (
  props: TokenExchangeRequest | undefined,
  target: _TokenExchangeTargetConfig | undefined,
  tokenExchange: _TokenExchangeConfig
): Readonly<{ audience?: string; resource?: string; scope?: string }> => ({
  audience:
    props?.audience ?? target?.audience ?? tokenExchange.defaultAudience,
  resource:
    props?.resource ?? target?.resource ?? tokenExchange.defaultResource,
  scope: props?.scope ?? target?.scope ?? tokenExchange.defaultScope,
})

export const mergeTokenExchangeExtraParams = (
  tokenExchange: _TokenExchangeConfig,
  target: _TokenExchangeTargetConfig | undefined,
  props: TokenExchangeRequest | undefined
): Readonly<Record<string, string>> => ({
  ...(tokenExchange.extraParams ?? {}),
  ...(target?.extraParams ?? {}),
  ...(props?.extraParams ?? {}),
})

export const requireTokenExchangeClientCredentials = (
  tokenExchange: _TokenExchangeConfig
): Readonly<{
  clientId: string
  clientSecret: string
  clientAuth: TokenExchangeClientAuth
}> => {
  const clientAuth =
    tokenExchange.clientAuth ?? TokenExchangeClientAuth.ClientSecretBasic
  const clientId = tokenExchange.clientId
  const clientSecret = tokenExchange.clientSecret
  if (!clientId) {
    throw new Error('tokenExchange.clientId is required')
  }
  if (!clientSecret) {
    throw new Error('tokenExchange.clientSecret is required')
  }
  return { clientId, clientSecret, clientAuth }
}

export const buildTokenExchangeFormEntries = (
  input: Readonly<{
    subjectToken: string
    audience?: string
    resource?: string
    scope?: string
    extraParams: Readonly<Record<string, string>>
    clientAuth: TokenExchangeClientAuth
    clientId: string
    clientSecret: string
  }>
): ReadonlyArray<readonly [string, string]> => {
  const base: ReadonlyArray<readonly [string, string]> = [
    ['grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange'],
    ['subject_token', input.subjectToken],
    ['subject_token_type', 'urn:ietf:params:oauth:token-type:access_token'],
  ]
  const audience = input.audience
    ? ([['audience', input.audience]] as const)
    : ([] as const)
  const resource = input.resource
    ? ([['resource', input.resource]] as const)
    : ([] as const)
  const scope = input.scope
    ? ([['scope', input.scope]] as const)
    : ([] as const)
  const extraParamEntries = Object.entries(input.extraParams)
    .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
    .map(([k, v]) => [k, v] as const)
  const clientSecretPost =
    input.clientAuth === TokenExchangeClientAuth.ClientSecretPost
      ? ([
          ['client_id', input.clientId],
          ['client_secret', input.clientSecret],
        ] as const)
      : ([] as const)
  return [
    ...base,
    ...audience,
    ...resource,
    ...scope,
    ...extraParamEntries,
    ...clientSecretPost,
  ]
}

export const buildTokenExchangeRequestHeaders = (
  clientAuth: TokenExchangeClientAuth,
  clientId: string,
  clientSecret: string
): Record<string, string> => {
  const contentType: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  }
  if (clientAuth === TokenExchangeClientAuth.ClientSecretBasic) {
    return {
      ...contentType,
      Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
    }
  }
  if (clientAuth === TokenExchangeClientAuth.ClientSecretPost) {
    return contentType
  }
  throw new Error(`Unsupported tokenExchange.clientAuth: ${clientAuth}`)
}

export const encodeTokenExchangeFormAsUrlSearchParams = (
  entries: ReadonlyArray<readonly [string, string]>
): URLSearchParams => new URLSearchParams(entries as [string, string][])

export const parseTokenExchangeResponseData = (
  data: unknown
): TokenExchangeResult => {
  const d = data as Record<string, unknown>
  const accessToken =
    typeof d?.access_token === 'string' ? d.access_token : undefined
  if (!accessToken) {
    throw new Error('token exchange response missing access_token')
  }
  const expiresInSeconds =
    typeof d?.expires_in === 'number' ? d.expires_in : undefined
  const tokenType = typeof d?.token_type === 'string' ? d.token_type : undefined
  const resultScope = typeof d?.scope === 'string' ? d.scope : undefined
  return {
    accessToken,
    tokenType,
    expiresInSeconds,
    scope: resultScope,
  }
}

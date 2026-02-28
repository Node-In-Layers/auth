import { pbkdf2, randomBytes, timingSafeEqual } from 'node:crypto'
import { FeaturesContext, isErrorObject } from '@node-in-layers/core'
import { JWTPayload } from 'jose'
import { JsonAble, JsonObj } from 'functional-models'
import { AuthConfig, AuthNamespace, type ApiConfig } from '../types.js'
import type { User } from '../core/types.js'
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
  if (
    typeof api.buildJwt !== 'function' ||
    typeof api.validateJwt !== 'function'
  ) {
    throw new Error(
      `Api "${AuthNamespace.Api}" must provide buildJwt and validateJwt.`
    )
  }
}

export const unpackAuthentication = (
  context: FeaturesContext<AuthConfig>
): _UnpackedAuth => {
  const apiConfig = context.config[AuthNamespace.Api] as ApiConfig | undefined

  if (!apiConfig?.loginApproaches?.length) {
    throw new Error(
      `Auth api config not found or loginApproaches empty. Likely not included in config (${AuthNamespace.Api}).`
    )
  }

  ensureApiLoaded(context)

  return {
    apiConfig,
    loginApproaches: apiConfig.loginApproaches.map(id => ({
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

export const requirePasswordHashSecretKey = (apiConfig: ApiConfig): string => {
  const secret = apiConfig.passwordHashSecretKey
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

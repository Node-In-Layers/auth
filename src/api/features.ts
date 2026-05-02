import { z } from 'zod'
import { PrimaryKeyType } from 'functional-models'
import {
  type ErrorObject,
  FeaturesContext,
  createErrorObject,
  isErrorObject,
  getModel,
  type CrossLayerProps,
  memoizeValueSync,
  annotatedFunction,
  ModelCrudsFunctions,
} from '@node-in-layers/core'
import {
  AuthConfig,
  AuthNamespace,
  OAuthPassthroughValidateMode,
  type ApiConfig,
  type Policy,
} from '../types.js'
import {
  AuthenticateProps,
  AuthenticateSchema,
  CleanupRefreshTokensSchema,
  DefaultLoginRequestSchema,
  LoginFeatureProps,
  LoginResult,
  LoginSchema,
  LoginAttemptResult,
  PolicyEngineContext,
  RefreshSchema,
  type LoginAttempt,
  type User,
  AuthCoreServicesLayer,
  PolicyContext,
} from '../core/types.js'
import { policyEngine } from '../core/libs/policy-engine.js'
import { unpackAuthentication } from './internal-libs.js'
import {
  ApiFeaturesLayer,
  ApiServices,
  ApiServicesLayer,
  ApiFeatures,
} from './types.js'

type _LoginApproachResult = Readonly<{
  user: User
  loginApproach: string
}>

const _tryLoginApproaches = (
  approaches: ReturnType<typeof unpackAuthentication>['loginApproaches'],
  props: LoginFeatureProps,
  crossLayerProps?: CrossLayerProps
): Promise<_LoginApproachResult | undefined> =>
  approaches.reduce(
    (accP, approach) =>
      accP.then(acc =>
        acc
          ? acc
          : Promise.resolve(approach.fn(props, crossLayerProps))
              .then(user =>
                user
                  ? {
                      user,
                      loginApproach: approach.loginApproach,
                    }
                  : undefined
              )
              .catch(() => undefined)
      ),
    Promise.resolve(undefined as _LoginApproachResult | undefined)
  )

type _RefreshRequest = Readonly<{
  refreshToken?: string
}>

export const create = (
  context: FeaturesContext<
    AuthConfig,
    ApiServicesLayer & AuthCoreServicesLayer,
    ApiFeaturesLayer
  >
): ApiFeatures => {
  const apiServices = context.services[AuthNamespace.Api] as ApiServices
  const LoginAttempts = getModel<LoginAttempt>(
    context,
    AuthNamespace.Core,
    'LoginAttempts'
  )

  const _getUnpacked = memoizeValueSync(() => {
    return unpackAuthentication(context)
  })

  const _saveLoginAttempt = (
    props: LoginFeatureProps,
    startedAt: string,
    endedAt: string,
    result: LoginAttemptResult,
    loginApproach?: string,
    userId?: string | number
  ): Promise<void> => {
    const unpacked = _getUnpacked()
    return unpacked.apiConfig.authentication.noSaveLoginAttempts ||
      !LoginAttempts
      ? Promise.resolve()
      : Promise.resolve(
          LoginAttempts.create<'id'>({
            startedAt,
            endedAt,
            ip: props.ip,
            userAgent: props.userAgent,
            userId,
            result,
            loginApproach,
          }).save()
        )
          .then(() => undefined)
          .catch(() => undefined)
  }

  /** ZodTypeAny avoids TS2589 (excessively deep instantiation) at safeParse inside annotatedFunction. */
  const loginRequestSchema: z.ZodTypeAny = (context.config[AuthNamespace.Api]
    ?.authentication?.loginPropsSchema ??
    DefaultLoginRequestSchema) as z.ZodTypeAny

  const login = annotatedFunction(
    LoginSchema,
    async (props, crossLayerProps) => {
      const startedAt = new Date().toISOString()
      return Promise.resolve()
        .then(async () => {
          const unpacked = _getUnpacked()
          const parsedLoginRequest = loginRequestSchema.safeParse(
            props.request as unknown
          )
          if (!parsedLoginRequest.success) {
            const endedAt = new Date().toISOString()
            await _saveLoginAttempt(
              props,
              startedAt,
              endedAt,
              LoginAttemptResult.Failure
            )
            return createErrorObject(
              'LOGIN_SCHEMA_INVALID',
              'Invalid login request',
              z.treeifyError(parsedLoginRequest.error)
            )
          }
          const approachResult = await _tryLoginApproaches(
            unpacked.loginApproaches,
            props,
            crossLayerProps
          )
          if (!approachResult) {
            const endedAt = new Date().toISOString()
            await _saveLoginAttempt(
              props,
              startedAt,
              endedAt,
              LoginAttemptResult.Failure
            )
            return createErrorObject('LOGIN_FAILED', 'No approach succeeded')
          }

          const token = apiServices.buildJwt(
            approachResult.user,
            crossLayerProps
          ).token
          const refreshToken = (
            await apiServices.buildRefreshToken(
              approachResult.user,
              crossLayerProps
            )
          ).token
          const endedAt = new Date().toISOString()
          const loginResult: LoginResult = {
            user: approachResult.user,
            token,
            refreshToken,
            loginApproach: approachResult.loginApproach,
          }
          await _saveLoginAttempt(
            props,
            startedAt,
            endedAt,
            LoginAttemptResult.Success,
            approachResult.loginApproach,
            approachResult.user.id
          )
          return loginResult
        })
        .catch(async err => {
          const endedAt = new Date().toISOString()
          await _saveLoginAttempt(
            props,
            startedAt,
            endedAt,
            LoginAttemptResult.Failure
          )
          return isErrorObject(err)
            ? err
            : createErrorObject('LOGIN_ERROR', 'Failed to login', err)
        })
    }
  )

  const authenticate = annotatedFunction(AuthenticateSchema, ((
    props,
    crossLayerProps
  ) => {
    const log = context.log.getInnerLogger('authenticate', crossLayerProps)
    const apiConfig = context.config[AuthNamespace.Api] as ApiConfig
    const passthrough = apiConfig?.authentication?.oauthPassthrough

    const tryLocalJwt = () =>
      apiServices.validateJwt(props.token, crossLayerProps)

    const authFailed = (err: ErrorObject | Error | undefined) =>
      createErrorObject('AUTH_FAILED', 'Failed to authenticate token', err)

    if (!passthrough?.enabled) {
      return tryLocalJwt().catch(authFailed)
    }

    const mode = passthrough.validateMode ?? OAuthPassthroughValidateMode.Jwks

    if (mode === OAuthPassthroughValidateMode.Opaque) {
      return Promise.resolve(
        typeof props.token === 'string' && props.token.trim().length > 0
          ? undefined
          : authFailed(
              new Error('OAuth passthrough opaque requires non-empty token')
            )
      )
    }

    if (mode === OAuthPassthroughValidateMode.Jwks) {
      return apiServices
        .verifyJwtWithJwks(props.token, crossLayerProps)
        .then(payload => {
          const identifiers = apiServices.getOidcUserLookupIdentifiers(
            payload,
            crossLayerProps
          )
          return apiServices
            .findUserByOidcIdentifiers(identifiers, crossLayerProps)
            .then(existing => {
              if (existing) {
                return existing
              }
              if (passthrough.autoProvision) {
                return apiServices.provisionOidcPassthroughUser(
                  payload,
                  identifiers,
                  crossLayerProps
                )
              }
              const internalError = createErrorObject(
                'AUTH_FAILED',
                'OAuth passthrough: user not linked and autoProvision is false'
              )
              log.warn(
                'OAuth passthrough: user not linked and autoProvision is false',
                internalError
              )
              return authFailed(undefined)
            })
        })
        .catch((jwksErr: unknown) =>
          apiConfig?.authentication?.jwtSecret
            ? tryLocalJwt().catch(() => Promise.reject(jwksErr))
            : Promise.reject(jwksErr)
        )
        .catch(authFailed)
    }

    const internalError = createErrorObject(
      'AUTH_FAILED',
      'OAuth passthrough validateMode is not supported',
      mode
    )
    log.warn('OAuth passthrough validateMode is not supported', internalError)
    return Promise.resolve(authFailed(undefined))
  }) as unknown as Parameters<
    typeof annotatedFunction<AuthenticateProps, User>
  >[1]) as ApiFeatures['authenticate']

  const refresh = annotatedFunction(RefreshSchema, (props, crossLayerProps) =>
    Promise.resolve().then(async () => {
      const refreshToken = (props.request as _RefreshRequest).refreshToken
      if (!refreshToken) {
        return createErrorObject(
          'REFRESH_TOKEN_MISSING',
          'Refresh token is required'
        )
      }
      return Promise.resolve(
        apiServices.refreshToken(refreshToken, crossLayerProps)
      ).catch(err =>
        createErrorObject('REFRESH_FAILED', 'Failed to refresh token', err)
      )
    })
  )

  const cleanupRefreshTokens = annotatedFunction(
    CleanupRefreshTokensSchema,
    (props, crossLayerProps) =>
      Promise.resolve(apiServices.cleanupRefreshTokens(crossLayerProps)).catch(
        err =>
          createErrorObject(
            'REFRESH_TOKEN_CLEANUP_FAILED',
            'Failed to cleanup refresh tokens',
            err
          )
      )
  )

  const authorize = async (
    props: PolicyContext,
    crossLayerProps?: CrossLayerProps
  ) => {
    const Users = context.services[AuthNamespace.Api].getUserCruds(
      crossLayerProps
    ) as ModelCrudsFunctions<User>

    const userInstance = await Users.retrieve(props.userId)
    if (!userInstance) {
      return createErrorObject('USER_NOT_FOUND', 'User not found')
    }
    if (!userInstance.get.enabled()) {
      return createErrorObject('USER_NOT_ENABLED', 'User is not enabled')
    }

    const user = await userInstance.toObj<User>()
    const isSystemAdmin =
      await context.services[AuthNamespace.Core].isUserSystemAdmin(user)
    const userAttributes =
      await context.services[AuthNamespace.Core].getUserOrganizationAttributes(
        user
      )
    const isOrgAdmin = await (props.organizationId
      ? context.services[AuthNamespace.Core].isOrganizationAdmin(
          user,
          props.organizationId as PrimaryKeyType
        )
      : Promise.resolve(false))

    const policies: Policy[] = []
    const policyEngineContext: PolicyEngineContext = {
      request: props,
      isSystemAdmin,
      isOrgAdmin,
      userAttributes,
    }
    const action = policyEngine(policies, policyEngineContext)
    return {
      action,
    }
  }

  return { login, authenticate, refresh, cleanupRefreshTokens, authorize }
}

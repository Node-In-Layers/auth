import { z } from 'zod'
import {
  FeaturesContext,
  createErrorObject,
  isErrorObject,
  getModel,
  type CrossLayerProps,
  memoizeValueSync,
  annotatedFunction,
} from '@node-in-layers/core'
import { AuthConfig, AuthNamespace } from '../types.js'
import {
  LoginAttemptResult,
  type LoginAttempt,
  type User,
} from '../core/types.js'
import { unpackAuthentication } from './internal-libs.js'
import {
  ApiFeaturesLayer,
  ApiServices,
  ApiServicesLayer,
  DefaultLoginRequestSchema,
  LoginFeatureProps,
  LoginResult,
  ApiFeatures,
  AuthenticateSchema,
  CleanupRefreshTokensSchema,
  LoginSchema,
  RefreshSchema,
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
  context: FeaturesContext<AuthConfig, ApiServicesLayer, ApiFeaturesLayer>
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
    return unpacked.apiConfig.noSaveLoginAttempts || !LoginAttempts
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

  const loginRequestSchema =
    context.config[AuthNamespace.Api]?.loginPropsSchema ??
    DefaultLoginRequestSchema

  const login = annotatedFunction(
    LoginSchema,
    async (props, crossLayerProps) => {
      const startedAt = new Date().toISOString()
      return Promise.resolve()
        .then(async () => {
          const unpacked = _getUnpacked()
          const parsedLoginRequest = loginRequestSchema.safeParse(props.request)
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

  const authenticate = annotatedFunction(
    AuthenticateSchema,
    (props, crossLayerProps) =>
      Promise.resolve(
        apiServices.validateJwt(props.token, crossLayerProps)
      ).catch(err =>
        createErrorObject('AUTH_FAILED', 'Failed to authenticate token', err)
      )
  )

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
  return { login, authenticate, refresh, cleanupRefreshTokens }
}

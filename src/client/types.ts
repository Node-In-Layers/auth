import {
  LayerFunction,
  NilAnnotatedFunction,
  annotationFunctionProps,
} from '@node-in-layers/core'
import { JsonObj } from 'functional-models'
import { z } from 'zod'
import { DefaultLoginRequestSchema, User, UserSchema } from '../core/types.js'
import { AuthNamespace } from '../types.js'

export type ClientAuthResult = Readonly<{
  key: string
  header?: string
  formatter?: (key: string) => string
}>

export type ClientAuthState = Readonly<{
  token: string
  refreshToken?: string
  user?: User
  loginApproach?: string
  tokenExpiresAtMs?: number
  header?: string
  formatter?: (key: string) => string
}>

export type ClientLoginRequest = z.infer<typeof DefaultLoginRequestSchema>
export type ClientLoginProps = ClientLoginRequest

export type ClientRefreshRequest = Readonly<{
  refreshToken?: string
}>

export type ClientRefreshProps = ClientRefreshRequest

export type ClientLoginResult = Readonly<{
  user: User
  token: string
  refreshToken: string
  loginApproach: string
}>

export const ClientLoginResultSchema = z.object({
  user: UserSchema,
  token: z.string(),
  refreshToken: z.string(),
  loginApproach: z.string(),
})

export type ClientRefreshResult = Readonly<{
  user: User
  token: string
  refreshToken: string
}>

export const ClientLoginPropsSchema =
  DefaultLoginRequestSchema as z.ZodType<ClientLoginProps>

export const ClientRefreshPropsSchema = z.object({
  refreshToken: z.string().optional(),
})

export const ClientRefreshResultSchema = z.object({
  user: UserSchema,
  token: z.string(),
  refreshToken: z.string(),
})

export type ClientLogoutResult = Readonly<{
  loggedOut: true
}>

export const ClientLogoutResultSchema = z.object({
  loggedOut: z.literal(true),
})

export const ClientLoginSchema = annotationFunctionProps<
  ClientLoginProps,
  ClientLoginResult
>({
  functionName: 'login',
  domain: AuthNamespace.Core,
  args: ClientLoginPropsSchema,
  returns: ClientLoginResultSchema,
})

export const ClientRefreshSchema = annotationFunctionProps<
  ClientRefreshProps,
  ClientRefreshResult
>({
  functionName: 'refresh',
  domain: AuthNamespace.Core,
  args: ClientRefreshPropsSchema,
  returns: ClientRefreshResultSchema,
})

export const ClientLogoutSchema = annotationFunctionProps<
  JsonObj,
  ClientLogoutResult
>({
  functionName: 'logout',
  domain: AuthNamespace.Core,
  args: z.record(z.string(), z.any()),
  returns: ClientLogoutResultSchema,
})

export type ClientServices = Readonly<{
  login: LayerFunction<(props: ClientLoginProps) => Promise<ClientLoginResult>>
  refresh: LayerFunction<
    (props: ClientRefreshProps) => Promise<ClientRefreshResult>
  >
  getAuth: LayerFunction<() => Promise<ClientAuthResult | undefined>>
  getState: LayerFunction<() => Promise<ClientAuthState | undefined>>
  setState: LayerFunction<(state?: ClientAuthState) => Promise<void>>
  logout: LayerFunction<() => Promise<ClientLogoutResult>>
}>

export type ClientServicesLayer = Readonly<{
  client: ClientServices
}>

export type ClientFeatures = Readonly<{
  login: NilAnnotatedFunction<ClientLoginProps, ClientLoginResult>
  refresh: NilAnnotatedFunction<ClientRefreshProps, ClientRefreshResult>
  logout: NilAnnotatedFunction<JsonObj, ClientLogoutResult>
  getState: LayerFunction<() => Promise<ClientAuthState | undefined>>
  setState: LayerFunction<(state?: ClientAuthState) => Promise<void>>
}>

export type ClientFeaturesLayer = Readonly<{
  client: ClientFeatures
}>

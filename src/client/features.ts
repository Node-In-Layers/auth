import {
  annotatedFunction,
  Config,
  FeaturesContext,
} from '@node-in-layers/core'
import { AuthNamespace } from '../types.js'
import {
  ClientFeatures,
  ClientServicesLayer,
  ClientLoginSchema,
  ClientRefreshSchema,
  ClientLogoutSchema,
} from './types.js'

export const create = (
  context: FeaturesContext<Config, ClientServicesLayer>
): ClientFeatures => {
  const login = annotatedFunction(ClientLoginSchema, (props, crossLayerProps) =>
    context.services[AuthNamespace.Client].login(props, crossLayerProps)
  )

  const refresh = annotatedFunction(
    ClientRefreshSchema,
    (props, crossLayerProps) =>
      context.services[AuthNamespace.Client].refresh(props, crossLayerProps)
  )

  const logout = annotatedFunction(ClientLogoutSchema, (_, crossLayerProps) =>
    context.services[AuthNamespace.Client].logout(crossLayerProps)
  )

  const getState = async crossLayerProps => {
    return context.services[AuthNamespace.Client].getState(crossLayerProps)
  }

  const setState = async (state, crossLayerProps) => {
    await context.services[AuthNamespace.Client].setState(
      state,
      crossLayerProps
    )
  }

  return {
    login,
    refresh,
    logout,
    getState,
    setState,
  }
}

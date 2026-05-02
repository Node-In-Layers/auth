import {
  annotatedFunction,
  Config,
  FeaturesContext,
} from '@node-in-layers/core'
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
    context.services.client.login(props, crossLayerProps)
  )

  const refresh = annotatedFunction(
    ClientRefreshSchema,
    (props, crossLayerProps) =>
      context.services.client.refresh(props, crossLayerProps)
  )

  const logout = annotatedFunction(ClientLogoutSchema, (_, crossLayerProps) =>
    context.services.client.logout(crossLayerProps)
  )

  const getState = async crossLayerProps => {
    return context.services.client.getState(crossLayerProps)
  }

  const setState = async (state, crossLayerProps) => {
    await context.services.client.setState(state, crossLayerProps)
  }

  return {
    login,
    refresh,
    logout,
    getState,
    setState,
  }
}

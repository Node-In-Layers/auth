import { PropertyConfig } from 'functional-models'
import { CommonContext } from '@node-in-layers/core'
import { AuthConfig, AuthNamespace } from '../types.js'

export const getUserPropertyOverride = (
  context: CommonContext<AuthConfig>,
  propertyKey: string,
  defaultValue?: PropertyConfig<any>
) => {
  return (
    context.config[AuthNamespace.Core].userPropertyOverrides?.[propertyKey] ||
    defaultValue ||
    {}
  )
}

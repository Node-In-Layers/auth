import get from 'lodash/get.js'
import { Arrayable, DataValue, PropertyConfig } from 'functional-models'
import {
  CommonContext,
  CrossLayerProps,
  isCrossLayerLoggingProps,
} from '@node-in-layers/core'
import { AuthConfig, AuthNamespace } from '../../types.js'
import { AuthCrossLayerProps } from '../types.js'
import { isRequestCrossLayerProps } from './internal-libs.js'

export const getUserPropertyOverride = <T extends Arrayable<DataValue>>(
  context: CommonContext<AuthConfig>,
  propertyKey: string,
  defaultValue?: PropertyConfig<any>
): PropertyConfig<T> => {
  return (context.config[AuthNamespace.Core].userPropertyOverrides?.[
    propertyKey
  ] ||
    defaultValue ||
    {}) as PropertyConfig<T>
}

export const getAuthorization = (
  crossLayerProps: CrossLayerProps & { requestInfo?: any },
  header?: string
): string | undefined => {
  if (!isRequestCrossLayerProps(crossLayerProps)) {
    return undefined
  }
  const { requestInfo } = crossLayerProps
  // NOTE: We need to see authInfo in the wild to see if we should use it.
  const authorization = get(requestInfo, `headers.${header || 'authorization'}`)
  return authorization as string | undefined
}

export * from './resource-strings.js'
export * from './policy-engine.js'

export const isAuthCrossLayerProps = (
  crossLayerProps?: CrossLayerProps
): crossLayerProps is AuthCrossLayerProps => {
  if (isCrossLayerLoggingProps(crossLayerProps)) {
    return Boolean(get(crossLayerProps, 'user'))
  }
  return false
}

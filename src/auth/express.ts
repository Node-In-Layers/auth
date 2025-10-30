import { Config, FeaturesContext } from '@node-in-layers/core'
import { ExpressContext } from '@node-in-layers/rest-api'
import { AuthNamespace } from '../types.js'
import { AuthFeaturesLayer } from './types.js'

export const create = (
  context: ExpressContext &
    FeaturesContext<Config, object, AuthFeaturesLayer>
) => {
  // Add the auth middleware to the express app
  context.express['@node-in-layers/rest-api/express'].addPreRouteMiddleware(
    context.features[AuthNamespace].authMiddleware
  )

  return {}
}

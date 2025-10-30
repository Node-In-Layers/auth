import type { Request, Response, NextFunction } from 'express'
import { Config, FeaturesContext, createErrorObject, isErrorObject } from '@node-in-layers/core'
import { AuthServicesLayer, AuthFeaturesLayer, AuthNamespace } from './types.js'
import { AuthConfig } from '../types.js'

export const create = (
  context: FeaturesContext<AuthConfig, AuthServicesLayer, AuthFeaturesLayer>
) => {
  const authMiddleware = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    const r = await Promise.resolve()
      .then(async () => {
        const result = context.services[AuthNamespace].standardJwtAuthorization(req.headers)
        if (isErrorObject(result.error)) {
          if (result.error.code === 'HTTP_UNAUTHORIZED') {
            res.status(HTTP_UNAUTHORIZED).json(result)
            return
          }
          res.status(500).json(result)
          return 'Unauthorized access'
        }
        req.user = result
      })
      .catch(e => {
        res
          .status(HTTP_UNAUTHORIZED)
          .json(createErrorObject('UNAUTHORIZED_ACCESS', 'Unauthorized access', e))
        return 'Unauthorized access'
      })
    if (r !== 'Unauthorized access') {
      next()
    }
    return
  }

  return {
    authMiddleware
  }
}

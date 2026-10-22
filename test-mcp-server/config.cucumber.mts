import { Config } from '@node-in-layers/core'
import merge from 'lodash/merge.js'
import * as config from './config.base.mjs'

export default async (): Promise<Config> => {
  const instance = await config.default()
  return merge(instance, {
    environment: 'cucumber',
  })
}

import { AuthNamespace } from '@node-in-layers/auth'
import { McpNamespace } from '@node-in-layers/mcp-server'
import {} from '@node-in-layers/auth/api/index.js'

export const create = (context: any) => {
  const unprotectedFeature = context.features.unprotected.myUnprotectedFeature
  context.mcp[AuthNamespace.Api].addUnprotectedFeature(unprotectedFeature)
  return {}
}

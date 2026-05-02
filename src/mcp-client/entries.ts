import { App } from '@node-in-layers/core'
import { createClient as createMcpClient } from '@node-in-layers/mcp-client/client/entries.js'
import { McpClientNamespace } from '@node-in-layers/mcp-client/types.js'
import * as authClient from '../client/index.js'
import { AuthMcpClientConfig, AuthClient } from './types.js'

const _mergeDomains = (domains: readonly App[]) => {
  const hasAuthClientDomain = domains.some(
    domain => domain.name === authClient.name
  )
  return hasAuthClientDomain
    ? domains
    : domains.concat([authClient as unknown as App])
}

export const createClient = async <T extends Record<string, any>>(
  config: AuthMcpClientConfig
): Promise<AuthClient<T>> => {
  const mcpConfig = config[McpClientNamespace.client]
  if (!mcpConfig) {
    throw new Error(
      `Missing required ${McpClientNamespace.client} configuration for auth/mcp-client`
    )
  }
  const mergedConfig = {
    ...config,
    [McpClientNamespace.client]: {
      ...mcpConfig,
      domains: _mergeDomains(mcpConfig.domains),
      authAdapter: {
        ...mcpConfig.authAdapter,
        // Sets our auth client, unless otherwise specified
        module: mcpConfig.authAdapter?.module || authClient.name,
      },
    },
  }
  const mcpClient = await createMcpClient<T>(mergedConfig)
  const authFeaturesInstance = mcpClient[authClient.name] || {}
  return {
    ...mcpClient,
    ...authFeaturesInstance,
  }
}

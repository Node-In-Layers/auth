import type { Client } from '@node-in-layers/mcp-client/client/types.js'
import type { ClientBasicConfig } from '@node-in-layers/mcp-client/types.js'
import { AuthConfig } from '../types.js'
import { ClientFeatures } from '../client/types.js'

export type MCPConfig = ClientBasicConfig

export type AuthMcpClientConfig = MCPConfig & Partial<AuthConfig>

export type AuthClient<T extends Record<string, any>> = Client<T> &
  ClientFeatures

export type AuthMcpClientEntries = Readonly<{
  createClient: <T extends Record<string, any>>(
    config: AuthMcpClientConfig
  ) => Promise<AuthClient<T>>
}>

import { Config, CoreNamespace, LogFormat } from '@node-in-layers/core'
import { DataNamespace } from '@node-in-layers/data'
import { LogLevelNames } from '@node-in-layers/core'
import {
  AuthConfig,
  auth as authCore,
  AuthNamespace,
  LoginApproachServiceName,
} from '@node-in-layers/auth'
import * as authApi from '@node-in-layers/auth/api/index.js'
import {
  McpNamespace,
  HttpConnection,
  McpServerConfig,
} from '@node-in-layers/mcp-server'
import {
  config as secretsConfig,
  SecretsConfig,
  SecretsNamespace,
} from '@node-in-layers/secrets'
import * as unprotected from './src/unprotected/index.js'
import * as protectedDomain from './src/protected/index.js'
import * as dataDomain from '@node-in-layers/data'
import * as mcpServerDomain from '@node-in-layers/mcp-server'

export default async (): Promise<Config> => {
  return {
    environment: 'base',
    systemName: 'test-mcp-server',
    [CoreNamespace.root]: {
      // @ts-ignore
      apps: await Promise.all([
        secretsConfig,
        dataDomain,
        mcpServerDomain,
        authCore,
        authApi,
        unprotected,
        protectedDomain,
      ]),
      layerOrder: ['services', 'features', ['entries', 'mcp']],
      logging: {
        logLevel: LogLevelNames.trace,
        logFormat: LogFormat.json,
        ignoreLayerFunctions: {
          'logging.services': true,
          'logging.features': true,
          '@node-in-layers/data.express': true,
          '@node-in-layers/data.services': true,
          '@node-in-layers/data.features': true,
          '@node-in-layers/mcp-server.mcp': true,
        },
      },
      modelFactory: '@node-in-layers/data',
      modelCruds: true,
    },
    [DataNamespace.root]: {
      databases: {
        default: {
          datastoreType: 'json',
          filePath: 'test-data/default.json',
          databaseMode: true,
        },
      },
    },
    [SecretsNamespace.Core]: {
      // Setting undefined uses json/json5
      secretServiceFactory: undefined,
    } as SecretsConfig,
    [AuthNamespace.Core]: {
      systemLevelPolicies: [],
      allowPasswordAuthentication: true,
    } as AuthConfig[AuthNamespace.Core],
    [AuthNamespace.Api]: {
      authentication: {
        loginApproaches: [LoginApproachServiceName.BasicAuthLogin],
        passwordHashSecretKey: 'test-mcp-server-secret',
        jwtSecret: 'test-mcp-server-jwt-secret',
        jwtIssuer: 'test-mcp-server',
        jwtAudience: 'test-mcp-server',
        jwtExpiresInSeconds: 5000,
      },
    } as AuthConfig[AuthNamespace.Api],
    [McpNamespace]: {
      stateless: true,
      server: {
        connection: {
          type: 'http',
          url: 'http://localhost',
          port: 3000,
        } as HttpConnection,
      },
    } as McpServerConfig['@node-in-layers/mcp-server'],
  }
}

import sinon from 'sinon'
import merge from 'lodash/merge.js'
import { decodeJwt } from 'jose'
import express from 'express'
import supertest from 'supertest'
import {
  Given,
  When,
  Then,
  AfterAll,
  setDefaultTimeout,
} from '@cucumber/cucumber'
import {
  CoreNamespace,
  createErrorObject,
  loadSystem,
  LogFormat,
  LogLevelNames,
  ModelCrudsFunctions,
} from '@node-in-layers/core'
import {
  api,
  auth,
  AuthConfig,
  AuthNamespace,
  LoginApproachServiceName,
} from '../../src'
import { DataConfig, DataNamespace } from '@node-in-layers/data/types'
import { createMcpResponse, hashPassword } from '../../src/api/internal-libs.js'
import {
  queryBuilder,
  EmailProperty,
  TextProperty,
  BooleanProperty,
  DatetimeProperty,
  LastModifiedDateProperty,
} from 'functional-models'
import { User, ApiKey } from '../../src/core/types'
import { GenericContainer, StartedTestContainer, Wait } from 'testcontainers'
import { create as createMcpAuth } from '../../src/api/mcp'
import { create as createExpressAuth } from '../../src/api/express'
import { z } from 'zod'

setDefaultTimeout(120_000)

type _World = {
  context?: any
  result?: any
  mcpState?: _McpState
  expressState?: _ExpressState
}

type _ContextFactory = () => Promise<any>
type _SeedFactory = (context: any) => Promise<void>
type _DataFactory = () => Promise<any> | any
type _TokenFactory = () => string
type _Assertion = (world: _World) => Promise<void> | void
type _McpRequestFactory = () => {
  path: string
  method: string
  headers?: Record<string, string>
  body?: any
}

type _ExpressRequestFactory = () => {
  path: string
  method: string
  headers?: Record<string, string>
  body?: any
}

type _McpState = {
  requester: any
}

type _ExpressState = {
  requester: any
}

type _OidcProvider = {
  container: StartedTestContainer
  baseUrl: string
  tokenEndpoint: string
  issuer: string
  jwksUri: string
}

const _OIDC_SUB = 'oidc-sub-123'
let _oidcProvider: _OidcProvider | undefined
let _oidcTokenCache: string | undefined
let _oidcTokenSubCache: string | undefined

const _createMockMcp = () => {
  const expressApp = express()
  expressApp.use(express.json())
  const tools = new Map<string, any>()
  const preRouteMiddlewares: any[] = []
  const runPreRouteMiddlewares = async (
    req: any,
    res: any
  ): Promise<boolean> => {
    for (const middleware of preRouteMiddlewares) {
      let nextCalled = false
      await Promise.resolve(
        middleware(req, res, () => {
          nextCalled = true
        })
      )
      if (!nextCalled) {
        // Middleware ended the request (e.g. unauthorized)
        return false
      }
    }
    return true
  }
  expressApp.post('/', async (req, res) => {
    const shouldContinue = await runPreRouteMiddlewares(req, res)
    if (!shouldContinue) {
      return
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {}
    const rpcMethod = typeof body.method === 'string' ? body.method : undefined
    const params =
      body.params && typeof body.params === 'object' ? body.params : body
    const isToolExecuteMethod =
      rpcMethod === 'tools/call' || rpcMethod === 'tools/execute' || !rpcMethod
    if (!isToolExecuteMethod) {
      res.json({
        jsonrpc: body.jsonrpc || '2.0',
        id: body.id || null,
        result: { ok: 'non-execute' },
      })
      return
    }
    const toolName =
      typeof params.toolName === 'string'
        ? params.toolName
        : typeof params.name === 'string'
          ? params.name
          : undefined
    if (!toolName) {
      res
        .status(400)
        .json(
          createErrorObject(
            'INVALID_MCP_CALL',
            'Missing tool name in MCP request.',
            body
          )
        )
      return
    }
    const tool = tools.get(toolName)
    if (!tool || typeof tool.execute !== 'function') {
      res
        .status(404)
        .json(
          createErrorObject(
            'MCP_TOOL_NOT_FOUND',
            `Tool "${toolName}" not found.`,
            body
          )
        )
      return
    }
    const args =
      params.arguments && typeof params.arguments === 'object'
        ? params.arguments
        : params.input && typeof params.input === 'object'
          ? params.input
          : {}
    const result = await tool.execute(args)
    res.json(result)
  })
  const mockMcp = {
    addAnnotatedFunction: sinon
      .stub()
      .callsFake((annotatedFunction: any, options: any) => {
        tools.set(options?.name || annotatedFunction.functionName, {
          name: options?.name || annotatedFunction.functionName,
          description:
            options?.description || annotatedFunction.schema?.description,
          inputSchema: undefined,
          outputSchema: undefined,
          execute: sinon.stub().callsFake(async (input: any) => {
            const r = await annotatedFunction(input)
            return createMcpResponse(r)
          }),
        })
      }),
    addPreRouteMiddleware: sinon.stub().callsFake((middleware: any) => {
      preRouteMiddlewares.push(middleware)
    }),
    addTool: sinon.stub().callsFake((tool: any) => {
      tools.set(tool.name, tool)
    }),
    addAdditionalRoute: sinon
      .stub()
      .callsFake(({ path, method, handler }: any) => {
        ;(expressApp as any)[method.toLowerCase()](
          path,
          async (req: any, res: any) => {
            const shouldContinue = await runPreRouteMiddlewares(req, res)
            if (!shouldContinue) {
              return
            }
            await Promise.resolve(handler(req, res))
          }
        )
      }),
  }

  return {
    mockMcp,
    expressApp,
    mcp: {
      create: () => mockMcp,
    },
    name: '@node-in-layers/mcp-server',
    features: {
      create: () => ({}),
    },
    services: {
      create: () => ({}),
    },
  }
}

const _createMockRestApi = () => {
  const expressApp = express()
  expressApp.use(express.json())
  const mockExpress = {
    addPreRouteMiddleware: sinon.stub().callsFake((middleware: any) => {
      expressApp.use(middleware)
    }),
    addRoute: sinon
      .stub()
      .callsFake((method: string, route: string, func: any) => {
        ;(expressApp as any)[method.toLowerCase()](route, func)
      }),
  }
  const expressLayer = {
    create: () => mockExpress,
  }
  const features = {
    create: () => ({}),
  }
  const services = {
    create: () => ({}),
  }
  return {
    mockExpress,
    expressApp,
    express: expressLayer,
    features,
    services,
    name: '@node-in-layers/rest-api/express',
  }
}

const _createCustomUsersApp = () => ({
  name: 'custom-users',
  features: {
    create: () => ({}),
  },
  services: {
    create: () => ({}),
  },
  models: {
    AnotherUsers: {
      create: ({ Model, getPrimaryKeyProperty }: any) =>
        Model({
          pluralName: 'AnotherUsers',
          singularName: 'AnotherUser',
          namespace: 'custom-users',
          primaryKeyName: 'id',
          properties: {
            id: getPrimaryKeyProperty('custom-users', 'AnotherUsers', {
              required: true,
            }),
            email: EmailProperty({ required: true }),
            firstName: TextProperty({ required: true }),
            lastName: TextProperty({ required: true }),
            npeOrganization: BooleanProperty({ required: false }),
            username: TextProperty({ required: false }),
            passwordHash: TextProperty({ required: true }),
            enabled: BooleanProperty({ required: true, defaultValue: true }),
            createdAt: DatetimeProperty({ autoNow: true }),
            updatedAt: LastModifiedDateProperty({ autoNow: true }),
          },
        }),
    },
  },
})

const _createCustomAuthApp = () => ({
  name: 'custom-auth',
  features: {
    create: () => ({}),
  },
  services: {
    create: (context: any) => ({
      customAuthLogin: async ({ request }: any) => {
        const customKey = request?.customAuth?.customKey
        if (customKey !== 'custom-auth-valid-key') {
          return undefined
        }
        const Users = context.services.getServices(AuthNamespace.Core)?.cruds
          ?.Users
        if (!Users) {
          return undefined
        }
        const searchResult = await Users.search(
          queryBuilder().take(1).compile()
        )
        const user = searchResult?.instances?.[0]
        if (!user) {
          return undefined
        }
        return user.toObj()
      },
    }),
  },
})

const _createSystem = async (
  overrides?: Record<string, any>,
  extraApps: any[] = [],
  transport: 'rest' | 'mcp' = 'rest'
): Promise<any> => {
  const transportApp =
    transport === 'mcp' ? _createMockMcp() : _createMockRestApi()
  const config: AuthConfig = merge(
    {
      systemName: '@node-in-layers/auth/features-test',
      environment: 'cucumber-test',
      [CoreNamespace.root]: {
        apps: [
          // Provides us data backbone.
          await import('@node-in-layers/data/index.js'),
          transportApp,
          // Provides us models.
          auth,
          // Provides api features (login/authenticate).
          api,
          ...extraApps,
        ],
        layerOrder: ['services', 'features', ['express', 'mcp']],
        logging: {
          logFormat: LogFormat.json,
          logLevel: LogLevelNames.silent,
        },
        modelFactory: '@node-in-layers/data',
        modelCruds: true,
      },
      [DataNamespace.root]: {
        databases: {
          default: {
            datastoreType: 'memory',
          },
        },
      } as DataConfig[DataNamespace.root],
      [AuthNamespace.Core]: {
        systemLevelPolicies: [],
        allowPasswordAuthentication: false,
      },
      [AuthNamespace.Api]: {
        loginApproaches: [],
        passwordHashSecretKey: 'feature-test-password-pepper',
        jwtSecret: 'feature-test-jwt-secret',
        jwtIssuer: 'feature-tests',
        jwtAudience: 'feature-tests',
        jwtExpiresInSeconds: 5000,
      },
    } as AuthConfig,
    overrides ?? {}
  )
  const system = await loadSystem({
    environment: 'cucumber-test',
    config,
  })
  return system
}

const _ensureOidcProvider = async (): Promise<_OidcProvider> => {
  if (_oidcProvider) {
    return _oidcProvider
  }
  const issuer = 'http://dex:5556/dex'
  const dexConfig = `
issuer: ${issuer}
storage:
  type: memory
web:
  http: 0.0.0.0:5556
oauth2:
  skipApprovalScreen: true
  passwordConnector: local
enablePasswordDB: true
staticClients:
  - id: feature-test-client
    secret: feature-test-client-secret
    name: Feature Test Client
    redirectURIs:
      - http://localhost/callback
staticPasswords:
  - email: "admin@example.com"
    # bcrypt hash for plaintext "password"
    hash: "$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"
    username: "admin"
    userID: "${_OIDC_SUB}"
`.trim()
  const container = await new GenericContainer('ghcr.io/dexidp/dex:v2.41.1')
    .withExposedPorts(5556)
    .withCopyContentToContainer([
      {
        content: dexConfig,
        target: '/etc/dex/config.yaml',
      },
    ])
    .withCommand(['dex', 'serve', '/etc/dex/config.yaml'])
    .withWaitStrategy(
      Wait.forHttp('/dex/.well-known/openid-configuration', 5556)
    )
    .withStartupTimeout(90_000)
    .start()
  const baseUrl = `http://${container.getHost()}:${container.getMappedPort(5556)}`
  _oidcProvider = {
    container,
    baseUrl,
    tokenEndpoint: `${baseUrl}/dex/token`,
    issuer,
    jwksUri: `${baseUrl}/dex/keys`,
  }
  return _oidcProvider
}

const _getOidcToken = async (): Promise<string> => {
  if (_oidcTokenCache) {
    return _oidcTokenCache
  }
  const provider = await _ensureOidcProvider()
  const body = new URLSearchParams({
    grant_type: 'password',
    username: 'admin@example.com',
    password: 'password',
    scope: 'openid profile email',
    client_id: 'feature-test-client',
    client_secret: 'feature-test-client-secret',
  })
  const response = await fetch(provider.tokenEndpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
    },
    body,
  })
  if (!response.ok) {
    const text = await response.text()
    throw new Error(`Dex token request failed (${response.status}): ${text}`)
  }
  const tokenResponse = (await response.json()) as {
    id_token?: string
    access_token?: string
  }
  const token = tokenResponse.id_token ?? tokenResponse.access_token
  if (!token) {
    throw new Error('Dex token response missing id_token/access_token')
  }
  const payload = decodeJwt(token)
  if (typeof payload.sub !== 'string') {
    throw new Error('Dex token payload missing string sub claim')
  }
  _oidcTokenCache = token
  _oidcTokenSubCache = payload.sub
  return token
}

const _CONTEXT: Record<string, _ContextFactory> = {
  'basic-default': () =>
    _createSystem({
      [AuthNamespace.Core]: {
        allowPasswordAuthentication: true,
      },
      [AuthNamespace.Api]: {
        loginApproaches: [LoginApproachServiceName.BasicAuthLogin],
      },
    }),
  'oidc-default': async () => {
    const provider = await _ensureOidcProvider()
    const system = await _createSystem({
      [AuthNamespace.Api]: {
        loginApproaches: [LoginApproachServiceName.OidcAuthLogin],
        jwksUris: [provider.jwksUri],
        jwtIssuer: provider.issuer,
        jwtAudience: 'feature-test-client',
        jwtSecret: undefined,
      },
    })
    // buildJwt depends on jwtSecret. In this OIDC context we purposely disable jwtSecret
    // so oidcAuthLogin uses JWKS, so provide a minimal token builder for login response.
    system.services[AuthNamespace.Api].buildJwt = () => ({
      token: 'oidc-system-token',
    })
    return system
  },
  'api-key-default': () =>
    _createSystem({
      [AuthNamespace.Api]: {
        loginApproaches: [LoginApproachServiceName.ApiKeyAuthLogin],
      },
    }),
  'api-key-then-basic': () =>
    _createSystem({
      [AuthNamespace.Core]: {
        allowPasswordAuthentication: true,
      },
      [AuthNamespace.Api]: {
        loginApproaches: [
          LoginApproachServiceName.ApiKeyAuthLogin,
          LoginApproachServiceName.BasicAuthLogin,
        ],
        // Fallthrough tests intentionally submit both payloads.
        // Override default XOR login schema for this context.
        loginPropsSchema: z.object({
          basicAuth: z
            .object({
              identifier: z.string(),
              password: z.string(),
            })
            .optional(),
          apiKeyAuth: z
            .object({
              key: z.string(),
            })
            .optional(),
        }),
      },
    }),
  'custom-login-default-schema': () =>
    _createSystem(
      {
        [AuthNamespace.Api]: {
          loginApproaches: ['custom-auth.customAuthLogin'],
        },
      },
      [_createCustomAuthApp()]
    ),
  'custom-login-custom-schema': () =>
    _createSystem(
      {
        [AuthNamespace.Api]: {
          loginApproaches: ['custom-auth.customAuthLogin'],
          loginPropsSchema: z.object({
            customAuth: z.object({
              customKey: z.string(),
            }),
          }),
        },
      },
      [_createCustomAuthApp()]
    ),
  'custom-user-basic-default': () =>
    _createSystem(
      {
        [AuthNamespace.Core]: {
          allowPasswordAuthentication: true,
          userModel: 'custom-users.AnotherUsers',
        },
        [AuthNamespace.Api]: {
          loginApproaches: [LoginApproachServiceName.BasicAuthLogin],
        },
      },
      [_createCustomUsersApp()]
    ),
  'express-default': () =>
    _createSystem({
      [AuthNamespace.Core]: {
        allowPasswordAuthentication: true,
      },
      [AuthNamespace.Api]: {
        loginApproaches: [LoginApproachServiceName.BasicAuthLogin],
      },
    }),
  'mcp-default': () =>
    _createSystem(
      {
        [AuthNamespace.Core]: {
          allowPasswordAuthentication: true,
        },
        [AuthNamespace.Api]: {
          loginApproaches: [LoginApproachServiceName.BasicAuthLogin],
        },
      },
      [],
      'mcp'
    ),
}

const _getCruds = (context: any, modelName: string): any => {
  const candidates = [
    context?.features?.[AuthNamespace.Core]?.cruds,
    context?.services?.[AuthNamespace.Core]?.cruds,
  ]
  for (const candidate of candidates) {
    if (candidate?.[modelName]) {
      return candidate[modelName]
    }
  }
  throw new Error(`Could not resolve cruds for model "${modelName}"`)
}

const _seedBasicUserEnabled: _SeedFactory = async context => {
  const Users = _getCruds(context, 'Users') as ModelCrudsFunctions<User>
  const passwordHash = await hashPassword(
    'basic-password-1',
    'feature-test-password-pepper'
  )
  await Users.create<'id'>({
    email: 'basic@example.com',
    username: 'basic-user',
    firstName: 'Basic',
    lastName: 'User',
    enabled: true,
    passwordHash,
  })
}

const _seedOidcUserIdentity: _SeedFactory = async context => {
  const provider = await _ensureOidcProvider()
  await _getOidcToken()
  if (!_oidcTokenSubCache) {
    throw new Error('OIDC token subject cache not set')
  }
  const Users = _getCruds(context, 'Users') as ModelCrudsFunctions<User>
  const UserAuthIdentities = _getCruds(context, 'UserAuthIdentities')
  const user = await Users.create<'id'>({
    email: 'oidc@example.com',
    username: 'oidc-user',
    firstName: 'Oidc',
    lastName: 'User',
    enabled: true,
  })
  await UserAuthIdentities.create({
    userId: user.getPrimaryKey(),
    iss: provider.issuer,
    sub: _oidcTokenSubCache,
    email: 'oidc@example.com',
    username: 'oidc-user',
  })
}

const _seedApiKeyActive: _SeedFactory = async context => {
  const Users = _getCruds(context, 'Users') as ModelCrudsFunctions<User>
  const ApiKeys = _getCruds(context, 'ApiKeys') as ModelCrudsFunctions<ApiKey>
  const allowPasswordAuthentication =
    !!context?.config?.[AuthNamespace.Core]?.allowPasswordAuthentication
  const passwordHash = allowPasswordAuthentication
    ? await hashPassword('api-key-password-1', 'feature-test-password-pepper')
    : undefined
  const user = await Users.create<'id'>({
    email: 'apikey@example.com',
    username: 'apikey-user',
    firstName: 'Api',
    lastName: 'Key',
    enabled: true,
    passwordHash,
  })
  await ApiKeys.create<'id'>({
    userId: String(user.getPrimaryKey()),
    key: 'api-key-valid-1',
    name: 'Feature API key',
  })
}

const _seedApiKeyAndBasicActive: _SeedFactory = async context => {
  await _seedBasicUserEnabled(context)
  await _seedApiKeyActive(context)
}

const _seedCustomUserBasicEnabled: _SeedFactory = async context => {
  const Users = context.services[
    AuthNamespace.Api
  ].getUserCruds() as ModelCrudsFunctions<User>
  const passwordHash = await hashPassword(
    'custom-password-1',
    'feature-test-password-pepper'
  )
  await Users.create<'id'>({
    email: 'custom@example.com',
    username: 'custom-user',
    firstName: 'Custom',
    lastName: 'User',
    enabled: true,
    passwordHash,
  })
}

const _seedCustomAuthUserEnabled: _SeedFactory = async context => {
  const Users = _getCruds(context, 'Users') as ModelCrudsFunctions<User>
  await Users.create<'id'>({
    email: 'customauth@example.com',
    username: 'customauth-user',
    firstName: 'CustomAuth',
    lastName: 'User',
    enabled: true,
  })
}

const _SEED: Record<string, _SeedFactory> = {
  'basic-user-enabled': _seedBasicUserEnabled,
  'oidc-user-identity': _seedOidcUserIdentity,
  'api-key-active': _seedApiKeyActive,
  'api-key-and-basic-active': _seedApiKeyAndBasicActive,
  'custom-user-basic-enabled': _seedCustomUserBasicEnabled,
  'custom-auth-user-enabled': _seedCustomAuthUserEnabled,
}

const _DATA: Record<string, _DataFactory> = {
  'basic-valid-login': () => ({
    request: {
      basicAuth: {
        identifier: 'basic@example.com',
        password: 'basic-password-1',
      },
    },
  }),
  'basic-invalid-password': () => ({
    request: {
      basicAuth: {
        identifier: 'basic@example.com',
        password: 'wrong-password',
      },
    },
  }),
  'api-key-valid-login': () => ({
    request: {
      apiKeyAuth: {
        key: 'api-key-valid-1',
      },
    },
  }),
  'api-key-invalid-login': () => ({
    request: {
      apiKeyAuth: {
        key: 'api-key-invalid',
      },
    },
  }),
  'oidc-valid-login': async () => {
    const token = await _getOidcToken()
    return {
      request: {
        oidcAuth: {
          token,
        },
      },
    }
  },
  'fallthrough-api-key-invalid-basic-valid': () => ({
    request: {
      apiKeyAuth: {
        key: 'api-key-invalid',
      },
      basicAuth: {
        identifier: 'basic@example.com',
        password: 'basic-password-1',
      },
    },
  }),
  'fallthrough-api-key-valid-basic-invalid': () => ({
    request: {
      apiKeyAuth: {
        key: 'api-key-valid-1',
      },
      basicAuth: {
        identifier: 'basic@example.com',
        password: 'wrong-password',
      },
    },
  }),
  'custom-basic-valid-login': () => ({
    request: {
      basicAuth: {
        identifier: 'custom@example.com',
        password: 'custom-password-1',
      },
    },
  }),
  'invalid-login-request-shape': () => ({
    request: {
      nope: {
        value: true,
      },
    },
  }),
  'custom-auth-valid-login': () => ({
    request: {
      customAuth: {
        customKey: 'custom-auth-valid-key',
      },
    },
  }),
}

const _TOKENS: Record<string, _TokenFactory> = {
  'malformed-token': () => 'not-a-jwt',
}

const _MCP_REQUESTS: Record<string, _McpRequestFactory> = {
  'health-no-auth': () => ({
    path: '/health',
    method: 'GET',
  }),
  'protected-no-auth': () => ({
    path: '/protected',
    method: 'GET',
  }),
  'login-no-auth': () => ({
    path: '/login',
    method: 'POST',
    body: {
      basicAuth: {
        identifier: 'basic@example.com',
        password: 'basic-password-1',
      },
    },
  }),
  'tool-login-no-auth': () => ({
    path: '/',
    method: 'POST',
    body: {
      jsonrpc: '2.0',
      id: 'test-1',
      method: 'tools/call',
      params: {
        name: 'login',
        arguments: {
          request: {
            basicAuth: {
              identifier: 'basic@example.com',
              password: 'basic-password-1',
            },
          },
        },
      },
    },
  }),
  'tool-cleanup-no-auth': () => ({
    path: '/',
    method: 'POST',
    body: {
      jsonrpc: '2.0',
      id: 'test-2',
      method: 'tools/execute',
      params: {
        toolName: 'cleanupRefreshTokens',
        arguments: {},
      },
    },
  }),
  'resources-read-no-auth': () => ({
    path: '/',
    method: 'POST',
    body: {
      jsonrpc: '2.0',
      id: 'test-3',
      method: 'resources/read',
      params: {
        uri: 'resource://sample',
      },
    },
  }),
}

const _EXPRESS_REQUESTS: Record<string, _ExpressRequestFactory> = {
  'health-no-auth': () => ({
    path: '/health',
    method: 'GET',
  }),
  'protected-no-auth': () => ({
    path: '/protected',
    method: 'GET',
  }),
  'login-no-auth': () => ({
    path: '/login',
    method: 'POST',
    body: {
      basicAuth: {
        identifier: 'basic@example.com',
        password: 'basic-password-1',
      },
    },
  }),
}

const _isErrorObject = (value: any): boolean => {
  return !!value && typeof value === 'object' && !!value.error
}

const _assert = (condition: unknown, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const _assertLoginSuccess = (result: any, expectedApproach: string): void => {
  if (_isErrorObject(result)) {
    console.error(JSON.stringify(result, null, 2))
  }
  _assert(
    !_isErrorObject(result),
    'Expected successful login result, got error'
  )
  _assert(
    typeof result?.token === 'string' && result.token.length > 0,
    'Expected non-empty token on login result'
  )
  _assert(!!result?.user, 'Expected user on login result')
  _assert(
    result?.loginApproach === expectedApproach,
    `Expected loginApproach "${expectedApproach}", got "${result?.loginApproach}"`
  )
}

const _assertFailure = (result: any): void => {
  _assert(_isErrorObject(result), 'Expected error result, got success')
}

const _assertAuthenticateSuccess = (result: any): void => {
  _assert(!_isErrorObject(result), 'Expected authenticate success, got error')
  _assert(
    typeof result?.email === 'string',
    'Expected authenticated user object'
  )
}

const _assertAuthenticateFailure = (result: any): void => {
  _assert(_isErrorObject(result), 'Expected authenticate failure, got success')
}

const _assertMcpUnprotectedSuccess = (result: any): void => {
  _assert(result?.statusCode === 200, `Expected 200, got ${result?.statusCode}`)
  _assert(
    result?.body?.ok === 'health',
    'Expected unprotected route handler response'
  )
}

const _assertMcpProtectedUnauthorized = (result: any): void => {
  _assert(result?.statusCode === 401, `Expected 401, got ${result?.statusCode}`)
  _assert(
    result?.body?.error?.code === 'NOT_AUTHORIZED',
    'Expected NOT_AUTHORIZED error for protected route'
  )
}

const _assertMcpLoginUnprotected = (world: _World): void => {
  const result = world.result
  _assert(result?.statusCode === 200, `Expected 200, got ${result?.statusCode}`)
  _assert(
    typeof result?.body?.token === 'string',
    'Expected login token in response body'
  )
}

const _getMcpToolPayload = (result: any): any => {
  const text = result?.body?.content?.[0]?.text
  if (typeof text !== 'string') {
    throw new Error('Expected MCP tool response body.content[0].text')
  }
  return JSON.parse(text)
}

const _assertMcpToolLoginUnprotected = (world: _World): void => {
  const result = world.result
  _assert(result?.statusCode === 200, `Expected 200, got ${result?.statusCode}`)
  const payload = _getMcpToolPayload(result)
  _assert(
    typeof payload?.token === 'string',
    'Expected login token from MCP tool'
  )
}

const _assertMcpToolProtectedWithAuth = (world: _World): void => {
  const result = world.result
  _assert(result?.statusCode === 200, `Expected 200, got ${result?.statusCode}`)
  const payload = _getMcpToolPayload(result)
  _assert(
    typeof payload?.deletedCount === 'number',
    'Expected cleanupRefreshTokens response from protected MCP tool'
  )
}

const _assertMcpNonExecuteUnprotected = (world: _World): void => {
  const result = world.result
  _assert(result?.statusCode === 200, `Expected 200, got ${result?.statusCode}`)
  _assert(
    result?.body?.result?.ok === 'non-execute',
    'Expected non-execute MCP message to pass through'
  )
}

const _assertExpressUnprotectedSuccess = (result: any): void => {
  _assert(result?.statusCode === 200, `Expected 200, got ${result?.statusCode}`)
  _assert(
    result?.body?.ok === 'health',
    'Expected unprotected route handler response'
  )
}

const _assertExpressProtectedUnauthorized = (result: any): void => {
  _assert(result?.statusCode === 401, `Expected 401, got ${result?.statusCode}`)
  _assert(
    result?.body?.error?.code === 'NOT_AUTHORIZED',
    'Expected NOT_AUTHORIZED error for protected route'
  )
}

const _assertExpressLoginUnprotected = (world: _World): void => {
  const result = world.result
  _assert(result?.statusCode === 200, `Expected 200, got ${result?.statusCode}`)
  _assert(
    typeof result?.body?.token === 'string',
    'Expected login token in response body'
  )
}

const _assertLoginAttemptResult = async (
  context: any,
  expectedResult: 'success' | 'failure'
): Promise<void> => {
  const LoginAttempts = _getCruds(context, 'LoginAttempts')
  const searchResult = await LoginAttempts.search(
    queryBuilder().take(10).compile()
  )
  const instances = (searchResult?.instances ?? []) as any[]
  _assert(instances.length > 0, 'Expected at least one LoginAttempts record')
  const attempts = await Promise.all(instances.map(i => i.toObj()))
  _assert(
    attempts.some(a => a?.result === expectedResult),
    `Expected a LoginAttempts row with result "${expectedResult}"`
  )
}

const _ASSERTIONS: Record<string, _Assertion> = {
  'login-success-basic': async world => {
    _assertLoginSuccess(world.result, LoginApproachServiceName.BasicAuthLogin)
    await _assertLoginAttemptResult(world.context, 'success')
  },
  'login-success-api-key': async world => {
    _assertLoginSuccess(world.result, LoginApproachServiceName.ApiKeyAuthLogin)
    await _assertLoginAttemptResult(world.context, 'success')
  },
  'login-success-oidc': async world => {
    _assertLoginSuccess(world.result, LoginApproachServiceName.OidcAuthLogin)
    await _assertLoginAttemptResult(world.context, 'success')
  },
  'login-failure': async world => {
    _assertFailure(world.result)
    await _assertLoginAttemptResult(world.context, 'failure')
  },
  'login-schema-invalid': async world => {
    _assertFailure(world.result)
    _assert(
      world.result?.error?.code === 'LOGIN_SCHEMA_INVALID',
      `Expected LOGIN_SCHEMA_INVALID, got "${world.result?.error?.code}"`
    )
    await _assertLoginAttemptResult(world.context, 'failure')
  },
  'authenticate-success': async world => {
    _assertAuthenticateSuccess(world.result)
    await _assertLoginAttemptResult(world.context, 'success')
  },
  'authenticate-failure': async world => {
    _assertAuthenticateFailure(world.result)
  },
  'mcp-unprotected-success': async world => {
    _assertMcpUnprotectedSuccess(world.result)
  },
  'mcp-protected-unauthorized': async world => {
    _assertMcpProtectedUnauthorized(world.result)
  },
  'mcp-login-unprotected': async world => {
    _assertMcpLoginUnprotected(world)
  },
  'mcp-tool-login-unprotected': async world => {
    _assertMcpToolLoginUnprotected(world)
  },
  'mcp-tool-protected-with-auth': async world => {
    _assertMcpToolProtectedWithAuth(world)
  },
  'mcp-non-execute-unprotected': async world => {
    _assertMcpNonExecuteUnprotected(world)
  },
  'express-unprotected-success': async world => {
    _assertExpressUnprotectedSuccess(world.result)
  },
  'express-protected-unauthorized': async world => {
    _assertExpressProtectedUnauthorized(world.result)
  },
  'express-login-unprotected': async world => {
    _assertExpressLoginUnprotected(world)
  },
}

Given(
  'we use {string} context',
  async function (this: _World, contextKey: string) {
    const createContext = _CONTEXT[contextKey]
    if (!createContext) {
      throw new Error(`Unknown context key "${contextKey}"`)
    }
    this.context = await createContext()
  }
)

Given(
  'we seed {string} auth records',
  async function (this: _World, seedKey: string) {
    if (!this.context) {
      throw new Error(
        'Context not set. Run "Given we use {string} context" first.'
      )
    }
    const seed = _SEED[seedKey]
    if (!seed) {
      throw new Error(`Unknown seed key "${seedKey}"`)
    }
    await seed(this.context)
  }
)

Given(
  'we use {string} express context',
  async function (this: _World, contextKey: string) {
    const createContext = _CONTEXT[contextKey]
    if (!createContext) {
      throw new Error(`Unknown Express context key "${contextKey}"`)
    }
    this.context = await createContext()

    const expressApp = this.context.config[CoreNamespace.root].apps.find(
      (x: any) => x.name === '@node-in-layers/rest-api/express'
    )
    if (!expressApp?.mockExpress || !expressApp?.expressApp) {
      throw new Error('Express mock app not found in system config')
    }

    const expressContext: any = {
      ...this.context,
      '@node-in-layers/rest-api/express': expressApp.mockExpress,
    }

    const expressApi = createExpressAuth(expressContext)
    expressApi.addUnprotectedRoute('/health', 'GET', async (_req, res) => {
      res.json({ ok: 'health' })
    })
    expressApi.addCustomProtectedRoute(
      '/protected',
      'GET',
      async (_req, res) => {
        res.json({ ok: 'protected' })
      }
    )

    this.expressState = {
      requester: supertest(expressApp.expressApp),
    }
  }
)

Given(
  'we use {string} mcp context',
  async function (this: _World, contextKey: string) {
    const createContext = _CONTEXT[contextKey]
    if (!createContext) {
      throw new Error(`Unknown MCP context key "${contextKey}"`)
    }
    this.context = await createContext()

    const mcpApp = this.context.config[CoreNamespace.root].apps.find(
      (x: any) => x.name === '@node-in-layers/mcp-server'
    )
    if (!mcpApp?.mockMcp || !mcpApp?.expressApp) {
      throw new Error('MCP mock app not found in system config')
    }

    const mcpContext: any = {
      ...this.context,
      '@node-in-layers/mcp-server': mcpApp.mockMcp,
    }

    const mcpApi = createMcpAuth(mcpContext)
    mcpApi.addUnprotectedRoute('/health', 'GET', async (_req, res) => {
      res.json({ ok: 'health' })
    })
    mcpApi.addCustomProtectedRoute('/protected', 'GET', async (_req, res) => {
      res.json({ ok: 'protected' })
    })
    this.mcpState = {
      requester: supertest(mcpApp.expressApp),
    }
  }
)

When(
  'we call express request {string}',
  async function (this: _World, requestKey: string) {
    if (!this.expressState) {
      throw new Error(
        'Express context not set. Run "Given we use {string} express context" first.'
      )
    }
    const requestFactory = _EXPRESS_REQUESTS[requestKey]
    if (!requestFactory) {
      throw new Error(`Unknown Express request key "${requestKey}"`)
    }
    const request = requestFactory()
    const method = request.method.toLowerCase()
    let req = this.expressState.requester[method](request.path)
    for (const [header, value] of Object.entries(request.headers ?? {})) {
      req = req.set(header, value)
    }
    if (request.body) {
      req = req.send(request.body)
    }
    const response = await req
    this.result = {
      statusCode: response.status,
      body: response.body,
    }
  }
)

When(
  'we run auth login with {string} data',
  async function (this: _World, dataKey: string) {
    if (!this.context) {
      throw new Error(
        'Context not set. Run "Given we use {string} context" first.'
      )
    }
    const dataFactory = _DATA[dataKey]
    if (!dataFactory) {
      throw new Error(`Unknown data key "${dataKey}"`)
    }
    const data = await dataFactory()
    this.result = await this.context.features[AuthNamespace.Api].login(data)
  }
)

When(
  'we run auth authenticate with token from result',
  async function (this: _World) {
    if (!this.context) {
      throw new Error(
        'Context not set. Run "Given we use {string} context" first.'
      )
    }
    const token = this.result?.token
    if (!token || typeof token !== 'string') {
      throw new Error(
        'No token available on world.result. Run a successful login first.'
      )
    }
    this.result = await this.context.features[AuthNamespace.Api].authenticate({
      token,
    })
  }
)

When(
  'we run auth authenticate with {string} token',
  async function (this: _World, tokenKey: string) {
    if (!this.context) {
      throw new Error(
        'Context not set. Run "Given we use {string} context" first.'
      )
    }
    const tokenFactory = _TOKENS[tokenKey]
    if (!tokenFactory) {
      throw new Error(`Unknown token key "${tokenKey}"`)
    }
    this.result = await this.context.features[AuthNamespace.Api].authenticate({
      token: tokenFactory(),
    })
  }
)

When(
  'we call mcp request {string}',
  async function (this: _World, requestKey: string) {
    if (!this.mcpState) {
      throw new Error(
        'MCP context not set. Run "Given we use {string} mcp context" first.'
      )
    }
    const requestFactory = _MCP_REQUESTS[requestKey]
    if (!requestFactory) {
      throw new Error(`Unknown MCP request key "${requestKey}"`)
    }
    const request = requestFactory()
    const method = request.method.toLowerCase()
    let req = this.mcpState.requester[method](request.path)
    for (const [header, value] of Object.entries(request.headers ?? {})) {
      req = req.set(header, value)
    }
    if (request.body) {
      req = req.send(request.body)
    }
    const response = await req
    this.result = {
      statusCode: response.status,
      body: response.body,
    }
  }
)

When(
  'we call mcp request {string} with bearer token from result',
  async function (this: _World, requestKey: string) {
    if (!this.mcpState) {
      throw new Error(
        'MCP context not set. Run "Given we use {string} mcp context" first.'
      )
    }
    const tokenFromToolPayload = (() => {
      try {
        return _getMcpToolPayload(this.result)?.token
      } catch {
        return undefined
      }
    })()
    const token =
      this.result?.body?.token || this.result?.token || tokenFromToolPayload
    if (!token || typeof token !== 'string') {
      throw new Error(
        'No token available on world.result to use as bearer token.'
      )
    }
    const requestFactory = _MCP_REQUESTS[requestKey]
    if (!requestFactory) {
      throw new Error(`Unknown MCP request key "${requestKey}"`)
    }
    const request = requestFactory()
    const method = request.method.toLowerCase()
    let req = this.mcpState.requester[method](request.path).set(
      'Authorization',
      `Bearer ${token}`
    )
    for (const [header, value] of Object.entries(request.headers ?? {})) {
      req = req.set(header, value)
    }
    if (request.body) {
      req = req.send(request.body)
    }
    const response = await req
    this.result = {
      statusCode: response.status,
      body: response.body,
    }
  }
)

Then(
  'result should match {string}',
  async function (this: _World, assertionKey: string) {
    const assertion = _ASSERTIONS[assertionKey]
    if (!assertion) {
      throw new Error(`Unknown assertion key "${assertionKey}"`)
    }
    await assertion(this)
  }
)

AfterAll(async function () {
  if (_oidcProvider) {
    await _oidcProvider.container.stop()
    _oidcProvider = undefined
  }
  _oidcTokenCache = undefined
  _oidcTokenSubCache = undefined
})

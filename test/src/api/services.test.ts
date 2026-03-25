import { assert } from 'chai'
import * as sinon from 'sinon'
import jwt from 'jsonwebtoken'
import axios from 'axios'
import {
  AuthNamespace,
  TokenExchangeClientAuth,
  type AuthConfig,
} from '../../../src/types.js'
import type { ServicesContext } from '@node-in-layers/core'
import type { User } from '../../../src/core/types.js'
import { create as createAuthApiServices } from '../../../src/api/services.js'

type _TestContext = ServicesContext<AuthConfig>

const createBaseContext = (
  apiConfigOverrides: Partial<any> = {},
  coreConfigOverrides: Partial<any> = {}
): _TestContext => {
  const apiConfig = {
    authentication: {
      loginApproaches: ['@node-in-layers/auth/api.apiKeyAuthLogin'] as string[],
      jwtSecret: 'jwt-secret',
      jwtIssuer: 'issuer',
      jwtAudience: 'audience',
      jwtExpiresInSeconds: 60,
      ...apiConfigOverrides,
    },
  }

  const coreConfig = {
    allowPasswordAuthentication: false,
    ...coreConfigOverrides,
  }

  const context = {
    config: {
      [AuthNamespace.Api]: apiConfig,
      [AuthNamespace.Core]: coreConfig,
    },
    services: {
      getServices: sinon.stub(),
    },
    log: {
      getInnerLogger: () => ({
        warn: sinon.stub(),
        debug: sinon.stub(),
      }),
    },
  } as unknown as _TestContext

  return context
}

/**
 * Attach fake core models to context so getModel(context, AuthNamespace.Core, name) resolves them.
 * getModel reads context.models[domain].getModels()[modelName]; we set that up here.
 */
const stubCoreModels = (context: _TestContext) => {
  const UserAuthIdentities: any = {}
  const ApiKeys: any = {
    getModelDefinition: () => ({ primaryKeyName: 'key' }),
  }
  const RefreshTokens: any = {
    getModelDefinition: () => ({ primaryKeyName: 'token' }),
    create: sinon.stub().returns({
      save: sinon.stub().resolves(),
    }),
    search: sinon.stub().resolves({ instances: [], total: 0 }),
    bulkDelete: sinon.stub().resolves(),
  }

  const models = (context as any).models ?? {}
  models[AuthNamespace.Core] = {
    getModels: () => ({
      UserAuthIdentities,
      ApiKeys,
      RefreshTokens,
    }),
  }
  ;(context as any).models = models
  return { UserAuthIdentities, ApiKeys, RefreshTokens }
}

describe('/src/api/services.ts', () => {
  afterEach(() => {
    sinon.restore()
  })

  describe('#create()', () => {
    it('should throw when Api configuration is missing', () => {
      const context = {
        config: {
          [AuthNamespace.Core]: {},
        },
        services: {
          getServices: sinon.stub(),
        },
        log: {
          getInnerLogger: () => ({
            warn: sinon.stub(),
          }),
        },
      } as unknown as _TestContext

      assert.throws(() => {
        createAuthApiServices(context)
      }, /configuration not found/)
    })

    it('should throw when Core configuration is missing', () => {
      const context = {
        config: {
          [AuthNamespace.Api]: {},
        },
        services: {
          getServices: sinon.stub(),
        },
        log: {
          getInnerLogger: () => ({
            warn: sinon.stub(),
          }),
        },
      } as unknown as _TestContext

      assert.throws(() => {
        createAuthApiServices(context)
      }, /configuration not found/)
    })
  })

  describe('#buildJwt()', () => {
    it('should delegate to jsonwebtoken.sign with expected payload and options', () => {
      const context = createBaseContext()
      stubCoreModels(context)

      const signStub = sinon
        .stub(jwt, 'sign')
        .returns('signed-token' as unknown as string)

      const services = createAuthApiServices(context)
      const user = { id: 'user-1' } as unknown as User

      const actual = services.buildJwt(user)

      assert.deepEqual(actual, { token: 'signed-token' })
      assert.isTrue(signStub.calledOnce)

      const [payload, secret, options] = signStub.firstCall.args
      assert.deepEqual(payload, { user })
      assert.equal(secret, 'jwt-secret')
      assert.equal(options.issuer, 'issuer')
      assert.equal(options.audience, 'audience')
      assert.equal(options.expiresIn, 60)
      assert.equal(options.algorithm, 'HS256')
    })
  })

  describe('#validateJwt()', () => {
    it('should verify token using jwtSecret and return user from payload', async () => {
      const context = createBaseContext()
      stubCoreModels(context)

      const user = { id: 'user-1' } as unknown as User
      const verifyStub = sinon
        .stub(jwt, 'verify')
        .returns({ user } as unknown as jwt.JwtPayload)

      const services = createAuthApiServices(context)

      const actual = await services.validateJwt('token-123')

      assert.strictEqual(actual, user)
      assert.isTrue(verifyStub.calledOnce)
    })
  })

  describe('#getUserCruds()', () => {
    it('should return default auth core Users cruds when userModel not configured', () => {
      const context = createBaseContext()
      const usersCruds = { retrieve: sinon.stub() }

      ;(context.services.getServices as sinon.SinonStub)
        .withArgs(AuthNamespace.Core)
        .returns({ cruds: { Users: usersCruds } })

      stubCoreModels(context)

      const services = createAuthApiServices(context)
      const actual = services.getUserCruds()

      assert.strictEqual(actual, usersCruds)
    })

    it('should resolve custom user model cruds from configured domain', () => {
      const usersCruds = { retrieve: sinon.stub() }
      const context = createBaseContext(
        {},
        { userModel: 'my-domain.CustomUsers' }
      )

      const getServicesStub = context.services.getServices as sinon.SinonStub<
        any[],
        any
      >

      getServicesStub.withArgs('my-domain').returns({
        cruds: { CustomUsers: usersCruds },
      })

      stubCoreModels(context)

      const services = createAuthApiServices(context)
      const actual = services.getUserCruds()

      assert.strictEqual(actual, usersCruds)
    })

    it('should throw when custom user model domain is not found', () => {
      const context = createBaseContext(
        {},
        { userModel: 'missing.CustomUsers' }
      )

      const getServicesStub = context.services.getServices as sinon.SinonStub<
        any[],
        any
      >

      getServicesStub.withArgs('missing').returns(undefined)

      stubCoreModels(context)

      const services = createAuthApiServices(context)

      assert.throws(() => {
        services.getUserCruds()
      }, /Domain "missing" not found/)
    })

    it('should throw when custom user model domain does not expose cruds', () => {
      const context = createBaseContext(
        {},
        { userModel: 'noCruds.CustomUsers' }
      )

      const getServicesStub = context.services.getServices as sinon.SinonStub<
        any[],
        any
      >

      getServicesStub.withArgs('noCruds').returns({})

      stubCoreModels(context)

      const services = createAuthApiServices(context)

      assert.throws(() => {
        services.getUserCruds()
      }, /does not expose cruds/)
    })

    it('should throw when custom user model is missing from domain cruds', () => {
      const context = createBaseContext({}, { userModel: 'my-domain.Missing' })

      const getServicesStub = context.services.getServices as sinon.SinonStub<
        any[],
        any
      >

      getServicesStub.withArgs('my-domain').returns({
        cruds: {},
      })

      stubCoreModels(context)

      const services = createAuthApiServices(context)

      assert.throws(() => {
        services.getUserCruds()
      }, /Model "Missing" not found in domain "my-domain"/)
    })
  })

  describe('#buildRefreshToken()', () => {
    it('should create refresh token with expected ttl and expiration', async () => {
      const context = createBaseContext({
        refreshTokens: {
          ttlDays: 2,
          expiresInMinutes: 5,
          cleanupBatchSize: 10,
          cleanupMaxQueries: 3,
        },
      })

      const { RefreshTokens } = stubCoreModels(context)

      const now = 1_000_000
      const dateNowStub = sinon.stub(Date, 'now').returns(now)

      const services = createAuthApiServices(context)
      const user = { id: 'user-1' } as unknown as User

      const actual = await services.buildRefreshToken(user)

      const expectedTtlSeconds = 2 * 24 * 60 * 60
      const expectedExpiresAt = new Date(now + 5 * 60 * 1000).toISOString()

      assert.equal(actual.ttlSeconds, expectedTtlSeconds)
      assert.equal(actual.expiresAt, expectedExpiresAt)
      assert.match(actual.token, /^[0-9a-f-]{36}$/i, 'token is UUID format')

      assert.isTrue(dateNowStub.called)
      assert.isTrue(RefreshTokens.create.calledOnce)
      const createArgs = RefreshTokens.create.firstCall.args[0]
      assert.equal(
        createArgs.token,
        actual.token,
        'same token returned and passed to create'
      )
      assert.equal(createArgs.userId, 'user-1')
      assert.equal(createArgs.expiresAt, expectedExpiresAt)
      assert.equal(createArgs.ttlSeconds, expectedTtlSeconds)
    })
  })

  describe('#exchangeAccessToken()', () => {
    it('should throw when tokenExchange is not enabled', async () => {
      const context = createBaseContext()
      stubCoreModels(context)
      const services = createAuthApiServices(context)

      let thrown: unknown
      try {
        await services.exchangeAccessToken({ audience: 'svc-b' })
      } catch (e) {
        thrown = e
      }
      assert.match(
        (thrown as Error)?.message ?? String(thrown),
        /tokenExchange is not enabled/
      )
    })

    it('should exchange using bearer from crossLayerProps and client_secret_basic', async () => {
      const context = createBaseContext({
        tokenExchange: {
          enabled: true,
          tokenEndpoint: 'https://issuer.example/token',
          clientAuth: TokenExchangeClientAuth.ClientSecretBasic,
          clientId: 'cid',
          clientSecret: 'csecret',
          defaultAudience: 'svc-b',
          defaultScope: 'read:things',
        },
      })
      stubCoreModels(context)

      const postStub = sinon.stub(axios, 'post').resolves({
        data: {
          access_token: 'downstream-token',
          token_type: 'Bearer',
          expires_in: 123,
          scope: 'read:things',
        },
      } as any)

      const services = createAuthApiServices(context)

      const crossLayerProps: any = {
        requestInfo: {
          headers: {
            Authorization: 'Bearer upstream-token',
          },
        },
      }

      const actual = await services.exchangeAccessToken(
        { audience: 'svc-b' },
        crossLayerProps
      )

      assert.deepEqual(actual, {
        accessToken: 'downstream-token',
        tokenType: 'Bearer',
        expiresInSeconds: 123,
        scope: 'read:things',
      })

      assert.isTrue(postStub.calledOnce)
      const [url, body, opts] = postStub.firstCall.args
      assert.equal(url, 'https://issuer.example/token')
      assert.equal(typeof body?.toString, 'function')
      const bodyString = body.toString()
      assert.include(
        bodyString,
        'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange'
      )
      assert.include(bodyString, 'subject_token=upstream-token')
      assert.include(bodyString, 'audience=svc-b')
      assert.include(bodyString, 'scope=read%3Athings')
      assert.match(opts.headers.Authorization, /^Basic\s+/)
    })

    it('should include client credentials in form when client_secret_post is used', async () => {
      const context = createBaseContext({
        tokenExchange: {
          enabled: true,
          tokenEndpoint: 'https://issuer.example/token',
          clientAuth: TokenExchangeClientAuth.ClientSecretPost,
          clientId: 'cid',
          clientSecret: 'csecret',
        },
      })
      stubCoreModels(context)

      const postStub = sinon.stub(axios, 'post').resolves({
        data: {
          access_token: 'downstream-token',
        },
      } as any)

      const services = createAuthApiServices(context)

      const actual = await services.exchangeAccessToken({
        subjectToken: 'upstream-token',
        audience: 'svc-b',
        scope: 'read:things',
      })

      assert.deepEqual(actual, {
        accessToken: 'downstream-token',
        tokenType: undefined,
        expiresInSeconds: undefined,
        scope: undefined,
      })

      assert.isTrue(postStub.calledOnce)
      const [_url, body] = postStub.firstCall.args
      const bodyString = body.toString()
      assert.include(bodyString, 'client_id=cid')
      assert.include(bodyString, 'client_secret=csecret')
    })

    it('should apply target overrides for audience/scope and extraParams', async () => {
      const context = createBaseContext({
        tokenExchange: {
          enabled: true,
          tokenEndpoint: 'https://issuer.example/token',
          clientAuth: TokenExchangeClientAuth.ClientSecretPost,
          clientId: 'cid',
          clientSecret: 'csecret',
          defaultScope: 'default',
          extraParams: { global: '1' },
          targets: {
            files: {
              audience: 'files-svc',
              scope: 'files:read',
              extraParams: { target: '1' },
            },
          },
        },
      })
      stubCoreModels(context)

      const postStub = sinon.stub(axios, 'post').resolves({
        data: { access_token: 'downstream-token' },
      } as any)

      const services = createAuthApiServices(context)

      await services.exchangeAccessToken({
        target: 'files',
        subjectToken: 'upstream-token',
        extraParams: { req: '1' },
      })

      assert.isTrue(postStub.calledOnce)
      const [_url, body] = postStub.firstCall.args
      const bodyString = body.toString()
      assert.include(bodyString, 'audience=files-svc')
      assert.include(bodyString, 'scope=files%3Aread')
      assert.include(bodyString, 'global=1')
      assert.include(bodyString, 'target=1')
      assert.include(bodyString, 'req=1')
    })
  })

  describe('#getOnBehalfOfHttpClient()', () => {
    it('should return axios instance with downstream bearer', async () => {
      const context = createBaseContext({
        tokenExchange: {
          enabled: true,
          tokenEndpoint: 'https://issuer.example/token',
          clientAuth: TokenExchangeClientAuth.ClientSecretPost,
          clientId: 'cid',
          clientSecret: 'csecret',
        },
      })
      stubCoreModels(context)

      sinon.stub(axios, 'post').resolves({
        data: { access_token: 'downstream-token' },
      } as any)

      const createStub = sinon.stub(axios, 'create').returns({} as any)

      const services = createAuthApiServices(context)
      await services.getOnBehalfOfHttpClient({ subjectToken: 'upstream-token' })

      assert.isTrue(createStub.calledOnce)
      const [opts] = createStub.firstCall.args
      assert.equal(opts.headers.Authorization, 'Bearer downstream-token')
    })
  })
})

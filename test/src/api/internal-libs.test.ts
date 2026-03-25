import { assert } from 'chai'
import * as sinon from 'sinon'
import { createErrorObject } from '@node-in-layers/core'
import {
  AuthNamespace,
  TokenExchangeClientAuth,
  type AuthConfig,
  type ApiAuthenticationConfig,
} from '../../../src/types.js'
import type { FeaturesContext } from '@node-in-layers/core'
import type { User } from '../../../src/core/types.js'
import {
  unpackAuthentication,
  getUserFromPayload,
  requirePasswordHashSecretKey,
  hashPassword,
  verifyPasswordHash,
  createMcpResponse,
  getBearerFromAuthorization,
  requireEnabledTokenExchange,
  resolveTokenExchangeTarget,
  resolveTokenExchangeTokenEndpoint,
  resolveTokenExchangeSubjectToken,
  resolveTokenExchangeAudienceResourceScope,
  mergeTokenExchangeExtraParams,
  requireTokenExchangeClientCredentials,
  buildTokenExchangeFormEntries,
  buildTokenExchangeRequestHeaders,
  encodeTokenExchangeFormAsUrlSearchParams,
  parseTokenExchangeResponseData,
  type _JwtPayload,
} from '../../../src/api/internal-libs.js'

describe('/src/api/internal-libs.ts', () => {
  describe('#unpackAuthentication()', () => {
    it('should throw when api config is missing or has no loginApproaches', () => {
      const context = {
        config: {},
        services: {
          [AuthNamespace.Api]: {
            buildJwt: () => ({}),
            validateJwt: async () => ({}),
            verifyJwtWithJwks: async () => ({}),
            getOidcUserLookupIdentifiers: () => ({}),
            findUserByOidcIdentifiers: async () => undefined,
            provisionOidcPassthroughUser: async () => ({}),
          },
          getServices: () => undefined,
        },
      } as unknown as FeaturesContext<AuthConfig>

      assert.throws(() => {
        unpackAuthentication(context)
      }, /Auth api config not found or loginApproaches empty/)
    })

    it('should resolve login approaches from context.services', async () => {
      const loginImpl = sinon.stub().resolves(undefined)

      const services: any = {
        getServices: sinon.stub(),
      }

      services[AuthNamespace.Api] = {
        buildJwt: () => ({}),
        validateJwt: async () => ({}),
        verifyJwtWithJwks: async () => ({}),
        getOidcUserLookupIdentifiers: () => ({}),
        findUserByOidcIdentifiers: async () => undefined,
        provisionOidcPassthroughUser: async () => ({}),
      }

      services.getServices.withArgs('authDomain').returns({
        login: loginImpl,
      })

      const apiConfig = {
        authentication: {
          loginApproaches: ['authDomain.login'],
        },
      }

      const context = {
        config: {
          [AuthNamespace.Api]: apiConfig,
        },
        services,
      } as unknown as FeaturesContext<AuthConfig>

      const actual = unpackAuthentication(context)

      assert.strictEqual(actual.apiConfig, apiConfig)
      assert.lengthOf(actual.loginApproaches, 1)
      const resolved = actual.loginApproaches[0]
      assert.equal(resolved.loginApproach, 'authDomain.login')

      await resolved.fn({} as any)

      assert.isTrue(loginImpl.calledOnce)
    })

    it('should throw when login approach domain is missing', () => {
      const services: any = {
        getServices: sinon.stub().withArgs('missingDomain').returns(undefined),
      }

      services[AuthNamespace.Api] = {
        buildJwt: () => ({}),
        validateJwt: async () => ({}),
        verifyJwtWithJwks: async () => ({}),
        getOidcUserLookupIdentifiers: () => ({}),
        findUserByOidcIdentifiers: async () => undefined,
        provisionOidcPassthroughUser: async () => ({}),
      }

      const context = {
        config: {
          [AuthNamespace.Api]: {
            authentication: {
              loginApproaches: ['missingDomain.login'],
            },
          },
        },
        services,
      } as unknown as FeaturesContext<AuthConfig>

      const { loginApproaches } = unpackAuthentication(context)

      assert.throws(() => {
        loginApproaches[0].fn({} as any)
      }, /Could not find domain "missingDomain" for login approach "missingDomain\.login"/)
    })

    it('should throw when login approach function is missing', () => {
      const services: any = {
        getServices: sinon.stub().withArgs('authDomain').returns({}),
      }

      services[AuthNamespace.Api] = {
        buildJwt: () => ({}),
        validateJwt: async () => ({}),
        verifyJwtWithJwks: async () => ({}),
        getOidcUserLookupIdentifiers: () => ({}),
        findUserByOidcIdentifiers: async () => undefined,
        provisionOidcPassthroughUser: async () => ({}),
      }

      const context = {
        config: {
          [AuthNamespace.Api]: {
            authentication: {
              loginApproaches: ['authDomain.missingFn'],
            },
          },
        },
        services,
      } as unknown as FeaturesContext<AuthConfig>

      const { loginApproaches } = unpackAuthentication(context)

      assert.throws(() => {
        loginApproaches[0].fn({} as any)
      }, /Could not find function "missingFn" in domain "authDomain"/)
    })
  })

  describe('#getUserFromPayload()', () => {
    it('should return the user when present on payload', () => {
      const user = { id: 1 } as unknown as User
      const payload: _JwtPayload = {
        user,
      }

      const actual = getUserFromPayload(payload)

      assert.strictEqual(actual, user)
    })

    it('should throw when payload.user is missing', () => {
      const payload = {} as _JwtPayload

      assert.throws(() => {
        getUserFromPayload(payload)
      }, /jwt payload does not contain user/)
    })
  })

  describe('#requirePasswordHashSecretKey()', () => {
    it('should return the configured secret key', () => {
      const authentication = {
        loginApproaches: [] as string[],
        passwordHashSecretKey: 'secret-key',
      } as any

      const actual = requirePasswordHashSecretKey(authentication)
      const expected = 'secret-key'

      assert.equal(actual, expected)
    })

    it('should throw when secret key is not configured', () => {
      const authentication = { loginApproaches: [] as string[] } as any

      assert.throws(() => {
        requirePasswordHashSecretKey(authentication)
      }, /passwordHashSecretKey is required/)
    })
  })

  describe('#hashPassword() & #verifyPasswordHash()', () => {
    it('should hash and verify password successfully', async () => {
      const password = 'p@ssw0rd'
      const secretKey = 'unit-test-secret'

      const hash = await hashPassword(password, secretKey, {
        iterations: 1_000,
        keyLength: 32,
        digest: 'sha256',
      })

      const isValid = await verifyPasswordHash(password, hash, secretKey)
      const isInvalid = await verifyPasswordHash(
        'wrong-password',
        hash,
        secretKey
      )

      assert.isTrue(isValid)
      assert.isFalse(isInvalid)
    })

    it('should return false for undefined encoded hash', async () => {
      const result = await verifyPasswordHash('password', undefined, 'secret')
      assert.isFalse(result)
    })

    it('should return false for invalid encoded hash format', async () => {
      const result = await verifyPasswordHash(
        'password',
        'not-a-valid-hash',
        'secret'
      )
      assert.isFalse(result)
    })
  })

  describe('#createMcpResponse()', () => {
    it('should wrap non-error result without isError flag', () => {
      const input = { ok: true }

      const actual = createMcpResponse(input)

      assert.deepEqual(actual, {
        content: [
          {
            type: 'text',
            text: JSON.stringify(input),
          },
        ],
      })
    })

    it('should include isError flag when result is an error object', () => {
      const errorObj = createErrorObject('CODE', 'msg')

      const actual = createMcpResponse(errorObj)

      assert.isTrue(actual.isError)
      assert.deepEqual(actual.content, [
        {
          type: 'text',
          text: JSON.stringify(errorObj),
        },
      ])
    })

    it('should encode undefined result as empty string literal without isError flag', () => {
      const actual = createMcpResponse(undefined as any)

      assert.isUndefined((actual as any).isError)
      assert.deepEqual(actual.content, [
        {
          type: 'text',
          text: JSON.stringify('""'),
        },
      ])
    })
  })

  const _minimalAuth = (): ApiAuthenticationConfig =>
    ({
      loginApproaches: [],
    }) as ApiAuthenticationConfig

  const _enabledTokenExchange = (overrides?: Record<string, unknown>) =>
    ({
      ..._minimalAuth(),
      tokenExchange: {
        enabled: true,
        tokenEndpoint: 'https://idp.example/token',
        clientId: 'cid',
        clientSecret: 'csec',
        ...overrides,
      },
    }) as ApiAuthenticationConfig

  describe('#getBearerFromAuthorization()', () => {
    it('should return the token for a Bearer header', () => {
      const actual = getBearerFromAuthorization('Bearer abc.def.ghi')
      assert.equal(actual, 'abc.def.ghi')
    })

    it('should treat the scheme as case-insensitive', () => {
      const actual = getBearerFromAuthorization('bEaReR token-value')
      assert.equal(actual, 'token-value')
    })

    it('should return undefined when the header is missing or empty', () => {
      assert.isUndefined(getBearerFromAuthorization(undefined))
      assert.isUndefined(getBearerFromAuthorization(''))
    })

    it('should return undefined for non-Bearer schemes', () => {
      assert.isUndefined(getBearerFromAuthorization('Basic xyz'))
    })
  })

  describe('#requireEnabledTokenExchange()', () => {
    it('should return tokenExchange when enabled', () => {
      const auth = _enabledTokenExchange()
      const actual = requireEnabledTokenExchange(auth)
      assert.equal(actual.tokenEndpoint, 'https://idp.example/token')
      assert.isTrue(actual.enabled)
    })

    it('should throw when tokenExchange is disabled or absent', () => {
      assert.throws(() => {
        requireEnabledTokenExchange(_minimalAuth())
      }, /tokenExchange is not enabled/)

      assert.throws(() => {
        requireEnabledTokenExchange({
          ..._minimalAuth(),
          tokenExchange: { enabled: false },
        } as ApiAuthenticationConfig)
      }, /tokenExchange is not enabled/)
    })
  })

  describe('#resolveTokenExchangeTarget()', () => {
    const tokenExchange = _enabledTokenExchange({
      targets: {
        svcA: { audience: 'aud-a' },
      },
    }).tokenExchange!

    it('should return undefined target when no name is given', () => {
      const actual = resolveTokenExchangeTarget(tokenExchange)
      assert.isUndefined(actual.target)
    })

    it('should resolve a named target', () => {
      const actual = resolveTokenExchangeTarget(tokenExchange, 'svcA')
      assert.equal(actual.target?.audience, 'aud-a')
    })

    it('should throw when the named target is missing', () => {
      assert.throws(() => {
        resolveTokenExchangeTarget(tokenExchange, 'missing')
      }, /tokenExchange target not found: "missing"/)
    })
  })

  describe('#resolveTokenExchangeTokenEndpoint()', () => {
    const tokenExchange = _enabledTokenExchange().tokenExchange!
    const target = {
      tokenEndpoint: 'https://target.example/token',
    }

    it('should prefer props.tokenEndpoint, then target, then config', () => {
      assert.equal(
        resolveTokenExchangeTokenEndpoint(
          { tokenEndpoint: 'https://props.example/token' },
          target,
          tokenExchange
        ),
        'https://props.example/token'
      )
      assert.equal(
        resolveTokenExchangeTokenEndpoint(undefined, target, tokenExchange),
        'https://target.example/token'
      )
      assert.equal(
        resolveTokenExchangeTokenEndpoint(undefined, undefined, tokenExchange),
        'https://idp.example/token'
      )
    })

    it('should throw when no endpoint can be resolved', () => {
      const noEndpoint = {
        ...tokenExchange,
        tokenEndpoint: undefined,
      }
      assert.throws(() => {
        resolveTokenExchangeTokenEndpoint(undefined, undefined, noEndpoint)
      }, /tokenExchange.tokenEndpoint is required/)
    })
  })

  describe('#resolveTokenExchangeSubjectToken()', () => {
    it('should prefer props.subjectToken over the Authorization header', () => {
      const actual = resolveTokenExchangeSubjectToken(
        { subjectToken: 'from-props' },
        'Bearer from-header'
      )
      assert.equal(actual, 'from-props')
    })

    it('should use the Bearer token from Authorization when props omit subjectToken', () => {
      const actual = resolveTokenExchangeSubjectToken(
        undefined,
        'Bearer from-header'
      )
      assert.equal(actual, 'from-header')
    })

    it('should throw when no subject token is available', () => {
      assert.throws(() => {
        resolveTokenExchangeSubjectToken(undefined, undefined)
      }, /subject token/)
    })
  })

  describe('#resolveTokenExchangeAudienceResourceScope()', () => {
    const tokenExchange = _enabledTokenExchange({
      defaultAudience: 'def-aud',
      defaultResource: 'def-res',
      defaultScope: 'def-scope',
    }).tokenExchange!
    const target = {
      audience: 'tgt-aud',
      resource: 'tgt-res',
      scope: 'tgt-scope',
    }

    it('should resolve with props overriding target and defaults', () => {
      const actual = resolveTokenExchangeAudienceResourceScope(
        {
          audience: 'p-aud',
          resource: 'p-res',
          scope: 'p-scope',
        },
        target,
        tokenExchange
      )
      assert.deepEqual(actual, {
        audience: 'p-aud',
        resource: 'p-res',
        scope: 'p-scope',
      })
    })

    it('should fall back to target then defaults', () => {
      assert.deepEqual(
        resolveTokenExchangeAudienceResourceScope(
          undefined,
          target,
          tokenExchange
        ),
        {
          audience: 'tgt-aud',
          resource: 'tgt-res',
          scope: 'tgt-scope',
        }
      )
      assert.deepEqual(
        resolveTokenExchangeAudienceResourceScope(
          undefined,
          undefined,
          tokenExchange
        ),
        {
          audience: 'def-aud',
          resource: 'def-res',
          scope: 'def-scope',
        }
      )
    })
  })

  describe('#mergeTokenExchangeExtraParams()', () => {
    const tokenExchange = _enabledTokenExchange({
      extraParams: { a: '1', b: 'base' },
    }).tokenExchange!
    const target = {
      extraParams: { b: 'target', c: '3' },
    }

    it('should merge with later sources overriding earlier ones', () => {
      const actual = mergeTokenExchangeExtraParams(tokenExchange, target, {
        extraParams: { b: 'props' },
      })
      assert.deepEqual(actual, { a: '1', b: 'props', c: '3' })
    })
  })

  describe('#requireTokenExchangeClientCredentials()', () => {
    const tokenExchange = _enabledTokenExchange().tokenExchange!

    it('should return client id, secret, and default clientAuth', () => {
      const actual = requireTokenExchangeClientCredentials(tokenExchange)
      assert.deepEqual(actual, {
        clientId: 'cid',
        clientSecret: 'csec',
        clientAuth: TokenExchangeClientAuth.ClientSecretBasic,
      })
    })

    it('should throw when clientId or clientSecret is missing', () => {
      assert.throws(() => {
        requireTokenExchangeClientCredentials({
          ...tokenExchange,
          clientId: undefined,
        } as any)
      }, /tokenExchange.clientId is required/)

      assert.throws(() => {
        requireTokenExchangeClientCredentials({
          ...tokenExchange,
          clientSecret: undefined,
        } as any)
      }, /tokenExchange.clientSecret is required/)
    })
  })

  describe('#buildTokenExchangeFormEntries()', () => {
    const baseInput = {
      subjectToken: 'subj',
      extraParams: {},
      clientId: 'cid',
      clientSecret: 'csec',
    } as const

    it('should include RFC 8693 grant and subject fields', () => {
      const actual = buildTokenExchangeFormEntries({
        ...baseInput,
        clientAuth: TokenExchangeClientAuth.ClientSecretBasic,
      })
      assert.deepEqual(actual.slice(0, 3), [
        ['grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange'],
        ['subject_token', 'subj'],
        ['subject_token_type', 'urn:ietf:params:oauth:token-type:access_token'],
      ])
    })

    it('should append audience, resource, and scope when set', () => {
      const actual = buildTokenExchangeFormEntries({
        ...baseInput,
        audience: 'aud',
        resource: 'res',
        scope: 'scp',
        clientAuth: TokenExchangeClientAuth.ClientSecretBasic,
      })
      assert.deepEqual(
        actual.filter(([k]) => ['audience', 'resource', 'scope'].includes(k)),
        [
          ['audience', 'aud'],
          ['resource', 'res'],
          ['scope', 'scp'],
        ]
      )
    })

    it('should append client_id and client_secret for client_secret_post', () => {
      const actual = buildTokenExchangeFormEntries({
        ...baseInput,
        clientAuth: TokenExchangeClientAuth.ClientSecretPost,
      })
      const tail = actual.slice(-2)
      assert.deepEqual(tail, [
        ['client_id', 'cid'],
        ['client_secret', 'csec'],
      ])
    })

    it('should append extra string params before client post fields', () => {
      const actual = buildTokenExchangeFormEntries({
        ...baseInput,
        extraParams: { foo: 'bar' },
        clientAuth: TokenExchangeClientAuth.ClientSecretPost,
      })
      const fooIdx = actual.findIndex(([k]) => k === 'foo')
      const clientIdx = actual.findIndex(([k]) => k === 'client_id')
      assert.isAbove(clientIdx, fooIdx)
    })
  })

  describe('#buildTokenExchangeRequestHeaders()', () => {
    it('should set Basic auth for client_secret_basic', () => {
      const actual = buildTokenExchangeRequestHeaders(
        TokenExchangeClientAuth.ClientSecretBasic,
        'myid',
        'mysecret'
      )
      assert.equal(actual['Content-Type'], 'application/x-www-form-urlencoded')
      assert.equal(
        actual.Authorization,
        `Basic ${Buffer.from('myid:mysecret').toString('base64')}`
      )
    })

    it('should omit Authorization for client_secret_post', () => {
      const actual = buildTokenExchangeRequestHeaders(
        TokenExchangeClientAuth.ClientSecretPost,
        'myid',
        'mysecret'
      )
      assert.isUndefined(actual.Authorization)
    })

    it('should throw for unsupported clientAuth', () => {
      assert.throws(() => {
        buildTokenExchangeRequestHeaders('unknown' as any, 'a', 'b')
      }, /Unsupported tokenExchange.clientAuth/)
    })
  })

  describe('#encodeTokenExchangeFormAsUrlSearchParams()', () => {
    it('should build a URLSearchParams instance from entries', () => {
      const entries = buildTokenExchangeFormEntries({
        subjectToken: 't',
        extraParams: { k: 'v' },
        clientAuth: TokenExchangeClientAuth.ClientSecretBasic,
        clientId: 'c',
        clientSecret: 's',
      })
      const params = encodeTokenExchangeFormAsUrlSearchParams(entries)
      assert.equal(params.get('subject_token'), 't')
      assert.equal(params.get('k'), 'v')
    })
  })

  describe('#parseTokenExchangeResponseData()', () => {
    it('should map a well-formed token response', () => {
      const actual = parseTokenExchangeResponseData({
        access_token: 'at',
        token_type: 'Bearer',
        expires_in: 3600,
        scope: 's',
      })
      assert.deepEqual(actual, {
        accessToken: 'at',
        tokenType: 'Bearer',
        expiresInSeconds: 3600,
        scope: 's',
      })
    })

    it('should throw when access_token is missing or not a string', () => {
      assert.throws(() => {
        parseTokenExchangeResponseData({})
      }, /missing access_token/)

      assert.throws(() => {
        parseTokenExchangeResponseData({ access_token: 1 })
      }, /missing access_token/)
    })

    it('should omit optional fields when types do not match', () => {
      const actual = parseTokenExchangeResponseData({
        access_token: 'ok',
        expires_in: 'not-a-number',
        token_type: 123,
        scope: null,
      })
      assert.deepEqual(actual, {
        accessToken: 'ok',
        tokenType: undefined,
        expiresInSeconds: undefined,
        scope: undefined,
      })
    })
  })
})

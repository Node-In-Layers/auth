import { assert } from 'chai'
import * as sinon from 'sinon'
import { createErrorObject } from '@node-in-layers/core'
import { AuthNamespace, type AuthConfig } from '../../../src/types.js'
import type { FeaturesContext } from '@node-in-layers/core'
import type { User } from '../../../src/core/types.js'
import {
  unpackAuthentication,
  getUserFromPayload,
  requirePasswordHashSecretKey,
  hashPassword,
  verifyPasswordHash,
  createMcpResponse,
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
          },
          getServices: () => undefined,
        },
      } as unknown as FeaturesContext<AuthConfig>

      assert.throws(() => {
        unpackAuthentication(context)
      }, /Auth api config not found or loginApproaches empty/)
    })

    it('should throw when auth api services are not loaded', () => {
      const context = {
        config: {
          [AuthNamespace.Api]: {
            loginApproaches: ['auth.login'],
          },
        },
        services: {
          // Missing buildJwt / validateJwt
          [AuthNamespace.Api]: {},
          getServices: () => undefined,
        },
      } as unknown as FeaturesContext<AuthConfig>

      assert.throws(() => {
        unpackAuthentication(context)
      }, /Api ".*" must provide buildJwt and validateJwt\./)
    })

    it('should resolve login approaches from context.services', async () => {
      const loginImpl = sinon.stub().resolves(undefined)

      const services: any = {
        getServices: sinon.stub(),
      }

      services[AuthNamespace.Api] = {
        buildJwt: () => ({}),
        validateJwt: async () => ({}),
      }

      services.getServices.withArgs('authDomain').returns({
        login: loginImpl,
      })

      const apiConfig = {
        loginApproaches: ['authDomain.login'],
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
      }

      const context = {
        config: {
          [AuthNamespace.Api]: {
            loginApproaches: ['missingDomain.login'],
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
      }

      const context = {
        config: {
          [AuthNamespace.Api]: {
            loginApproaches: ['authDomain.missingFn'],
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
      const apiConfig = {
        passwordHashSecretKey: 'secret-key',
      } as any

      const actual = requirePasswordHashSecretKey(apiConfig)
      const expected = 'secret-key'

      assert.equal(actual, expected)
    })

    it('should throw when secret key is not configured', () => {
      const apiConfig = {} as any

      assert.throws(() => {
        requirePasswordHashSecretKey(apiConfig)
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
})

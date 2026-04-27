import { assert } from 'chai'
import sinon from 'sinon'
import { ServicesContext } from '@node-in-layers/core'
import { AxiosInstance } from 'axios'
import { z } from 'zod'
import { AuthNamespace } from '../../../src/types.js'
import { create } from '../../../src/client/services.js'
import { ClientAuthState } from '../../../src/client/types.js'

describe('/src/client/services.ts', () => {
  describe('#create()', () => {
    it('should login and expose auth state', async () => {
      const post = sinon.stub()
      post.resolves({
        data: {
          token: 'token-1',
          refreshToken: 'refresh-1',
          loginApproach: 'oidc',
          user: {
            id: 'u1',
          },
        },
      })
      const services = create({} as ServicesContext, {
        httpClient: {
          post,
        } as unknown as AxiosInstance,
      })

      const actual = await services.login({
        baseUrl: 'http://localhost:3000',
        request: {
          oidcAuth: {
            token: 'oidc-token',
          },
        },
      })
      const auth = await services.getAuth()

      assert.equal(actual.token, 'token-1')
      assert.equal(actual.refreshToken, 'refresh-1')
      assert.equal(auth?.key, 'token-1')
      assert.equal(auth?.header, 'Authorization')
    })

    it('should refresh tokens from stored refresh token', async () => {
      const post = sinon.stub()
      post.onCall(0).resolves({
        data: {
          token: 'token-1',
          refreshToken: 'refresh-1',
          loginApproach: 'basic',
          user: {
            id: 'u1',
          },
        },
      })
      post.onCall(1).resolves({
        data: {
          token: 'token-2',
          refreshToken: 'refresh-2',
          user: {
            id: 'u1',
          },
        },
      })
      const services = create({} as ServicesContext, {
        httpClient: {
          post,
        } as unknown as AxiosInstance,
      })

      await services.login({
        baseUrl: 'http://localhost:3000',
        request: {
          basicAuth: {
            identifier: 'someone@example.com',
            password: 'password',
          },
        },
      })
      const actual = await services.refresh({
        baseUrl: 'http://localhost:3000',
      })
      const auth = await services.getAuth()

      assert.equal(actual.token, 'token-2')
      assert.equal(actual.refreshToken, 'refresh-2')
      assert.equal(auth?.key, 'token-2')
    })

    it('should throw when refresh is called without available token', async () => {
      const services = create({} as ServicesContext, {
        httpClient: {
          post: sinon.stub(),
        } as unknown as AxiosInstance,
      })

      let actualError: Error | undefined
      try {
        await services.refresh({
          baseUrl: 'http://localhost:3000',
        })
      } catch (error) {
        actualError = error as Error
      }

      assert.isDefined(actualError)
      assert.match(
        actualError?.message || '',
        /No refresh token available\. Call login first or pass refreshToken\./
      )
    })

    it('should set and clear state manually', async () => {
      const services = create({} as ServicesContext, {
        httpClient: {
          post: sinon.stub(),
        } as unknown as AxiosInstance,
      })
      const state: ClientAuthState = {
        token: 'manual-token',
        refreshToken: 'manual-refresh',
      }

      await services.setState(state)
      const authBefore = await services.getAuth()
      await services.logout()
      const authAfter = await services.getAuth()

      assert.equal(authBefore?.key, 'manual-token')
      assert.isUndefined(authAfter)
    })

    it('should use loginPropsSchema override from config', async () => {
      const post = sinon.stub().resolves({
        data: {
          token: 'custom-token',
          refreshToken: 'custom-refresh',
          loginApproach: 'custom',
          user: {
            id: 'u1',
          },
        },
      })
      const context = {
        config: {
          [AuthNamespace.Api]: {
            authentication: {
              loginPropsSchema: z.object({
                customToken: z.string(),
              }),
            },
          },
        },
      } as ServicesContext
      const services = create(context, {
        httpClient: {
          post,
        } as unknown as AxiosInstance,
      })

      const actual = await services.login({
        baseUrl: 'http://localhost:3000',
        request: {
          customToken: 'abc123',
        },
      })

      assert.equal(actual.token, 'custom-token')
      assert.equal(post.callCount, 1)
    })
  })
})

import { describe, it } from 'mocha'
import { assert } from 'chai'
import sinon from 'sinon'
import { create } from '../../../src/api/express.js'
import { AuthNamespace } from '../../../src/types.js'

const EXPRESS_NAMESPACE = '@node-in-layers/rest-api/express'

const createMockExpressContext = (
  apiConfigOverrides: Record<string, unknown> = {}
) => {
  const host = {
    addRoute: sinon.stub(),
    addPreRouteMiddleware: sinon.stub(),
  }
  const login = sinon.stub()
  const refresh = sinon.stub()
  const authenticate = sinon.stub()

  const context = {
    config: {
      [AuthNamespace.Api]: apiConfigOverrides,
    },
    features: {
      [AuthNamespace.Api]: {
        login,
        refresh,
        authenticate,
      },
    },
    express: {
      [EXPRESS_NAMESPACE]: host,
    },
  }

  return {
    context: context as any,
    host,
    login,
    refresh,
    authenticate,
  }
}

describe('/src/api/express.ts', () => {
  describe('#create()', () => {
    it('should register default login and refresh routes and pre-route middleware on context.express host', () => {
      const input = createMockExpressContext()

      create(input.context)

      assert.equal(input.host.addRoute.callCount, 2)
      assert.equal(input.host.addRoute.firstCall.args[0], 'post')
      assert.equal(input.host.addRoute.firstCall.args[1], '/login')
      assert.equal(input.host.addRoute.secondCall.args[0], 'post')
      assert.equal(input.host.addRoute.secondCall.args[1], '/token/refresh')
      assert.equal(input.host.addPreRouteMiddleware.callCount, 1)
    })

    it('should register custom protected and unprotected routes on context.express host', () => {
      const input = createMockExpressContext()
      const handler = sinon.stub()

      const expressApi = create(input.context)
      expressApi.addUnprotectedRoute('/health', 'GET', handler)
      expressApi.addCustomProtectedRoute('/protected', 'POST', handler)

      assert.equal(input.host.addRoute.callCount, 4)
      assert.deepEqual(input.host.addRoute.getCall(2).args, [
        'get',
        '/health',
        handler,
      ])
      assert.deepEqual(input.host.addRoute.getCall(3).args, [
        'post',
        '/protected',
        handler,
      ])
    })
  })
})

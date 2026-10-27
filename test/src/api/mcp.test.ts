import { describe, it } from 'mocha'
import { assert } from 'chai'
import sinon from 'sinon'
import { create } from '../../../src/api/mcp.js'
import { AuthNamespace } from '../../../src/types.js'

const MCP_NAMESPACE = '@node-in-layers/mcp-server'

const createMockMcpContext = (
  apiConfigOverrides: Record<string, unknown> = {}
) => {
  const host = {
    addAdditionalRoute: sinon.stub(),
    addAnnotatedFunction: sinon.stub(),
    addPreRouteMiddleware: sinon.stub(),
    addCrossLayerPropMiddleware: sinon.stub(),
    addTool: sinon.stub(),
  }
  const login = Object.assign(sinon.stub(), { functionName: 'login' })
  const refresh = Object.assign(sinon.stub(), { functionName: 'refresh' })
  const authenticate = Object.assign(sinon.stub(), {
    functionName: 'authenticate',
  })
  const cleanupRefreshTokens = Object.assign(sinon.stub(), {
    functionName: 'cleanupRefreshTokens',
  })

  const context = {
    config: {
      [AuthNamespace.Api]: apiConfigOverrides,
    },
    services: {},
    features: {
      [AuthNamespace.Api]: {
        login,
        refresh,
        authenticate,
        cleanupRefreshTokens,
      },
    },
    mcp: {
      [MCP_NAMESPACE]: host,
    },
  }

  return {
    context: context as any,
    host,
    login,
    refresh,
    authenticate,
    cleanupRefreshTokens,
  }
}

describe('/src/api/mcp.ts', () => {
  describe('#create()', () => {
    it('should register default routes, features, and middlewares on context.mcp host', () => {
      const input = createMockMcpContext()

      create(input.context)

      assert.equal(input.host.addAdditionalRoute.callCount, 2)
      assert.equal(
        input.host.addAdditionalRoute.firstCall.args[0].path,
        '/login'
      )
      assert.equal(
        input.host.addAdditionalRoute.firstCall.args[0].method,
        'POST'
      )
      assert.equal(
        input.host.addAdditionalRoute.secondCall.args[0].path,
        '/token/refresh'
      )
      assert.equal(
        input.host.addAdditionalRoute.secondCall.args[0].method,
        'POST'
      )
      assert.equal(input.host.addAnnotatedFunction.callCount, 2)
      assert.equal(input.host.addCrossLayerPropMiddleware.callCount, 1)
      assert.equal(input.host.addPreRouteMiddleware.callCount, 2)
    })

    it('should register custom protected and unprotected routes on context.mcp host', () => {
      const input = createMockMcpContext()
      const handler = sinon.stub()

      const mcpApi = create(input.context)
      mcpApi.addUnprotectedRoute('/health', 'get', handler)
      mcpApi.addCustomProtectedRoute('/protected', 'post', handler)

      assert.equal(input.host.addAdditionalRoute.callCount, 4)
      assert.deepEqual(input.host.addAdditionalRoute.getCall(2).args[0], {
        path: '/health',
        method: 'GET',
        handler,
      })
      assert.deepEqual(input.host.addAdditionalRoute.getCall(3).args[0], {
        path: '/protected',
        method: 'POST',
        handler,
      })
    })
  })
})

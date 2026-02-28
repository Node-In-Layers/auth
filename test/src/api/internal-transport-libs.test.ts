import { assert } from 'chai'
import * as sinon from 'sinon'
import { createErrorObject, isErrorObject } from '@node-in-layers/core'
import {
  NOT_AUTHORIZED,
  normalizeMethod,
  getAuthorizationHeader,
  getBearerToken,
  matchesRoute,
  toUnauthorized,
  createProtectedMiddleware,
  createMcpProtectedMiddleware,
  createLoginHandler,
  createRefreshHandler,
  addProtectedRouteRegistration,
  addUnprotectedRouteRegistration,
} from '../../../src/api/internal-transport-libs.js'
import type { ApiProtectedRouteRegistration } from '../../../src/api/types.js'
import type { User } from '../../../src/core/types.js'

const createMockRes = () => {
  const res: any = {
    status: sinon.stub(),
    json: sinon.stub(),
  }
  res.status.callsFake((_code: number) => res)
  return res
}

describe('/src/api/internal-transport-libs.ts', () => {
  describe('#normalizeMethod()', () => {
    it('should trim and uppercase http methods', () => {
      const actual = normalizeMethod('  get ')
      const expected = 'GET'
      assert.equal(actual, expected)
    })
  })

  describe('#getAuthorizationHeader()', () => {
    it('should return string value as-is', () => {
      const actual = getAuthorizationHeader('Bearer token')
      const expected = 'Bearer token'
      assert.equal(actual, expected)
    })

    it('should return first value from array', () => {
      const actual = getAuthorizationHeader(['first', 'second'])
      const expected = 'first'
      assert.equal(actual, expected)
    })

    it('should return undefined when header is missing', () => {
      const actual = getAuthorizationHeader(undefined)
      assert.isUndefined(actual)
    })
  })

  describe('#getBearerToken()', () => {
    it('should return undefined when header is missing', () => {
      const actual = getBearerToken(undefined)
      assert.isUndefined(actual)
    })

    it('should return undefined when header is not bearer', () => {
      const actual = getBearerToken('Basic abc123')
      assert.isUndefined(actual)
    })

    it('should return token when header is bearer', () => {
      const actual = getBearerToken('Bearer abc123')
      const expected = 'abc123'
      assert.equal(actual, expected)
    })

    it('should be case-insensitive for bearer scheme', () => {
      const actual = getBearerToken('bearer token123')
      const expected = 'token123'
      assert.equal(actual, expected)
    })
  })

  describe('#matchesRoute()', () => {
    it('should return true when path and method match', () => {
      const actual = matchesRoute('/login', 'POST', {
        path: '/login',
        method: 'post',
      })
      assert.isTrue(actual)
    })

    it('should return false when path differs', () => {
      const actual = matchesRoute('/other', 'POST', {
        path: '/login',
        method: 'post',
      })
      assert.isFalse(actual)
    })

    it('should return false when method differs', () => {
      const actual = matchesRoute('/login', 'GET', {
        path: '/login',
        method: 'post',
      })
      assert.isFalse(actual)
    })
  })

  describe('#toUnauthorized()', () => {
    it('should build an ErrorObject with NOT_AUTHORIZED code', () => {
      const error = toUnauthorized()
      assert.isTrue(isErrorObject(error))
      assert.equal(error.error.code, 'NOT_AUTHORIZED')
      assert.equal(error.error.message, 'Unauthorized')
    })
  })

  describe('#createProtectedMiddleware()', () => {
    it('should call next for unprotected routes', async () => {
      const authenticate = sinon.stub()
      const middleware = createProtectedMiddleware(
        [{ path: '/login', method: 'POST' }],
        authenticate
      )

      const req: any = {
        path: '/login',
        method: 'POST',
        headers: { authorization: 'Bearer token' },
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.isTrue(next.calledOnce)
      assert.isTrue(authenticate.notCalled)
      assert.isTrue(res.status.notCalled)
    })

    it('should respond with 401 when bearer token is missing', async () => {
      const authenticate = sinon.stub()
      const middleware = createProtectedMiddleware([], authenticate)

      const req: any = {
        path: '/protected',
        method: 'GET',
        headers: {},
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.isTrue(res.status.calledOnceWith(NOT_AUTHORIZED))
      assert.isTrue(res.json.calledOnce)
      assert.isTrue(next.notCalled)
    })

    it('should respond with 401 when authenticate returns an ErrorObject', async () => {
      const error = createErrorObject('CODE', 'msg')
      const authenticate = sinon.stub().resolves(error)
      const middleware = createProtectedMiddleware([], authenticate)

      const req: any = {
        path: '/protected',
        method: 'GET',
        headers: { authorization: 'Bearer token' },
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.isTrue(res.status.calledOnceWith(NOT_AUTHORIZED))
      assert.isTrue(res.json.calledOnceWith(error))
      assert.isTrue(next.notCalled)
    })

    it('should attach user and call next when authentication succeeds', async () => {
      const user = { id: 'user-1' } as unknown as User
      const authenticate = sinon.stub().resolves(user)
      const middleware = createProtectedMiddleware([], authenticate)

      const req: any = {
        path: '/protected',
        method: 'GET',
        headers: { authorization: 'Bearer token' },
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.strictEqual(req.user, user)
      assert.isTrue(next.calledOnce)
    })
  })

  describe('#createMcpProtectedMiddleware()', () => {
    it('should call next for unprotected routes', async () => {
      const authenticate = sinon.stub()
      const middleware = createMcpProtectedMiddleware(
        [{ path: '/status', method: 'GET' }],
        new Set<string>(),
        authenticate
      )

      const req: any = {
        path: '/status',
        method: 'GET',
        headers: {},
        body: {},
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.isTrue(next.calledOnce)
      assert.isTrue(authenticate.notCalled)
    })

    it('should skip auth for non-tool MCP RPC methods', async () => {
      const authenticate = sinon.stub()
      const middleware = createMcpProtectedMiddleware(
        [],
        new Set<string>(),
        authenticate
      )

      const req: any = {
        path: '/mcp',
        method: 'POST',
        headers: {},
        body: { method: 'resources/read' },
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.isTrue(next.calledOnce)
      assert.isTrue(authenticate.notCalled)
    })

    it('should skip auth for unprotected feature tool names', async () => {
      const authenticate = sinon.stub()
      const middleware = createMcpProtectedMiddleware(
        [],
        new Set<string>(['feature-login']),
        authenticate
      )

      const req: any = {
        path: '/mcp',
        method: 'POST',
        headers: {},
        body: {
          method: 'tools/execute',
          params: { toolName: 'feature-login', arguments: {} },
        },
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.isTrue(next.calledOnce)
      assert.isTrue(authenticate.notCalled)
    })

    it('should enforce auth for protected MCP tool calls', async () => {
      const user = { id: 'user-1' } as unknown as User
      const authenticate = sinon.stub().resolves(user)
      const middleware = createMcpProtectedMiddleware(
        [],
        new Set<string>(),
        authenticate
      )

      const req: any = {
        path: '/mcp',
        method: 'POST',
        headers: { authorization: 'Bearer token' },
        body: {
          method: 'tools/call',
          params: { name: 'protected-tool', arguments: {} },
        },
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.strictEqual(req.user, user)
      assert.isTrue(next.calledOnce)
    })

    it('should respond with 401 when MCP tool call is protected and token missing', async () => {
      const authenticate = sinon.stub()
      const middleware = createMcpProtectedMiddleware(
        [],
        new Set<string>(),
        authenticate
      )

      const req: any = {
        path: '/mcp',
        method: 'POST',
        headers: {},
        body: {
          method: 'tools/execute',
          params: { toolName: 'protected-tool', arguments: {} },
        },
      }
      const res = createMockRes()
      const next = sinon.stub()

      await middleware(req, res, next)

      assert.isTrue(res.status.calledOnceWith(NOT_AUTHORIZED))
      assert.isTrue(res.json.calledOnce)
      assert.isTrue(next.notCalled)
    })
  })

  describe('#createLoginHandler()', () => {
    it('should call login feature and respond with result', async () => {
      const result = { ok: true } as any
      const login = sinon.stub().resolves(result)
      const handler = createLoginHandler(login)

      const req: any = {
        body: { field: 'value' },
        ip: '127.0.0.1',
        headers: { 'user-agent': 'agent' },
      }
      const res = createMockRes()

      await handler(req, res)

      assert.isTrue(
        login.calledOnceWith({
          request: { field: 'value' },
          ip: '127.0.0.1',
          userAgent: 'agent',
        })
      )
      assert.isTrue(res.status.notCalled)
      assert.isTrue(res.json.calledOnceWith(result))
    })

    it('should respond with 401 when login feature returns error object', async () => {
      const error = createErrorObject('CODE', 'msg')
      const login = sinon.stub().resolves(error)
      const handler = createLoginHandler(login)

      const req: any = {
        body: {},
        ip: '127.0.0.1',
        headers: {},
      }
      const res = createMockRes()

      await handler(req, res)

      assert.isTrue(res.status.calledOnceWith(NOT_AUTHORIZED))
      assert.isTrue(res.json.calledOnceWith(error))
    })
  })

  describe('#createRefreshHandler()', () => {
    it('should call refresh feature and respond with result', async () => {
      const result = { refreshed: true } as any
      const refresh = sinon.stub().resolves(result)
      const handler = createRefreshHandler(refresh)

      const req: any = {
        body: { field: 'value' },
        ip: '127.0.0.1',
        headers: { 'user-agent': ['agent'] },
      }
      const res = createMockRes()

      await handler(req, res)

      assert.isTrue(
        refresh.calledOnceWith({
          request: { field: 'value' },
          ip: '127.0.0.1',
          userAgent: 'agent',
        })
      )
      assert.isTrue(res.status.notCalled)
      assert.isTrue(res.json.calledOnceWith(result))
    })

    it('should respond with 401 when refresh feature returns error object', async () => {
      const error = createErrorObject('CODE', 'msg')
      const refresh = sinon.stub().resolves(error)
      const handler = createRefreshHandler(refresh)

      const req: any = {
        body: {},
        ip: '127.0.0.1',
        headers: {},
      }
      const res = createMockRes()

      await handler(req, res)

      assert.isTrue(res.status.calledOnceWith(NOT_AUTHORIZED))
      assert.isTrue(res.json.calledOnceWith(error))
    })
  })

  describe('#addProtectedRouteRegistration()', () => {
    it('should add normalized protected route registration', () => {
      const routes: ApiProtectedRouteRegistration[] = []

      addProtectedRouteRegistration(routes, '/path', 'post')

      assert.lengthOf(routes, 1)
      assert.deepEqual(routes[0], {
        path: '/path',
        method: 'POST',
        handler: undefined,
      })
    })
  })

  describe('#addUnprotectedRouteRegistration()', () => {
    it('should add normalized unprotected route registration', () => {
      const routes: Array<{ path: string; method: string }> = []

      addUnprotectedRouteRegistration(routes, '/path', 'get')

      assert.lengthOf(routes, 1)
      assert.deepEqual(routes[0], {
        path: '/path',
        method: 'GET',
      })
    })
  })
})

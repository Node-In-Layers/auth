import { assert } from 'chai'
import sinon from 'sinon'
import { create } from '../../../src/client/features.js'

describe('/src/client/features.ts', () => {
  describe('#create()', () => {
    it('should proxy login, refresh, and logout to client services', async () => {
      const login = sinon.stub().resolves({
        token: 't1',
        refreshToken: 'r1',
        loginApproach: 'basic',
        user: {
          id: 'u1',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
          enabled: true,
        },
      })
      const refresh = sinon.stub().resolves({
        token: 't2',
        refreshToken: 'r2',
        user: {
          id: 'u1',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
          enabled: true,
        },
      })
      const logout = sinon.stub().resolves({ loggedOut: true })
      const features = create({
        services: {
          client: {
            login,
            refresh,
            logout,
          },
        },
      } as any)

      const loginActual = await features.login({
        basicAuth: {
          identifier: 'someone@example.com',
          password: 'password',
        },
      })
      const refreshActual = await features.refresh({})
      await features.logout({})

      assert.equal(loginActual.token, 't1')
      assert.equal(refreshActual.token, 't2')
      assert.equal(login.callCount, 1)
      assert.equal(refresh.callCount, 1)
      assert.equal(logout.callCount, 1)
    })
  })
})

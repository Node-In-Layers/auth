import { assert } from 'chai'
import sinon from 'sinon'
import { create } from '../../../src/client/features.js'

describe('/src/client/features.ts', () => {
  describe('#create()', () => {
    it('should proxy login, refresh, and logout to client services', async () => {
      const login = sinon.stub().resolves({ token: 't1' })
      const refresh = sinon.stub().resolves({ token: 't2' })
      const logout = sinon.stub().resolves(undefined)
      const features = create({
        services: {
          client: {
            login,
            refresh,
            logout,
          },
        },
      } as any)

      const loginActual = await features.login({ baseUrl: 'http://x', request: {} })
      const refreshActual = await features.refresh({ baseUrl: 'http://x' })
      await features.logout()

      assert.equal(loginActual.token, 't1')
      assert.equal(refreshActual.token, 't2')
      assert.equal(login.callCount, 1)
      assert.equal(refresh.callCount, 1)
      assert.equal(logout.callCount, 1)
    })
  })
})

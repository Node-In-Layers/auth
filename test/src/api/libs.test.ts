import { assert } from 'chai'
import {
  buildCustomUserModelReference,
  parseCustomUserModelReference,
} from '../../../src/api/libs.js'

describe('/src/api/libs.ts', () => {
  describe('#buildCustomUserModelReference()', () => {
    it('should build reference from trimmed domain and modelName', () => {
      const actual = buildCustomUserModelReference('  my-domain ', ' Users ')
      const expected = 'my-domain.Users'
      assert.equal(actual, expected)
    })

    it('should throw when domain is missing or blank', () => {
      assert.throws(() => {
        buildCustomUserModelReference('', 'Users')
      }, /domain is required for custom user model reference/)

      assert.throws(() => {
        buildCustomUserModelReference('   ', 'Users')
      }, /domain is required for custom user model reference/)
    })

    it('should throw when modelName is missing or blank', () => {
      assert.throws(() => {
        buildCustomUserModelReference('domain', '')
      }, /modelName is required for custom user model reference/)

      assert.throws(() => {
        buildCustomUserModelReference('domain', '   ')
      }, /modelName is required for custom user model reference/)
    })
  })

  describe('#parseCustomUserModelReference()', () => {
    it('should parse domain and modelName and trim whitespace', () => {
      const actual = parseCustomUserModelReference(' my-domain.Users ')
      const expected = {
        domain: 'my-domain',
        modelName: 'Users',
      }
      assert.deepEqual(actual, expected)
    })

    it('should throw when reference has no separator', () => {
      assert.throws(() => {
        parseCustomUserModelReference('invalid')
      }, /Invalid auth core userModel "invalid"\. Expected "domain\.PluralModelName"\./)
    })

    it('should throw when domain or modelName are empty after trimming', () => {
      assert.throws(() => {
        parseCustomUserModelReference(' .Users')
      }, /Invalid auth core userModel/)

      assert.throws(() => {
        parseCustomUserModelReference('domain. ')
      }, /Invalid auth core userModel/)
    })
  })
})

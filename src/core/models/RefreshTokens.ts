import {
  LastModifiedDateProperty,
  DatetimeProperty,
  TextProperty,
  IntegerProperty,
  PropertyType,
  ormPropertyConfig,
} from 'functional-models'
import { getPrimaryKeyDataType, ModelProps } from '@node-in-layers/core'
import { RefreshToken } from '../types.js'
import { AuthConfig, AuthNamespace } from '../../types.js'

export const create = ({
  context,
  Model,
  getModel,
  getPrimaryKeyProperty,
  getForeignKeyProperty,
}: ModelProps<AuthConfig>) => {
  const dataType = getPrimaryKeyDataType(
    context,
    AuthNamespace.Core,
    'RefreshTokens'
  )

  const idProperty =
    dataType === PropertyType.Integer
      ? getPrimaryKeyProperty(AuthNamespace.Core, 'RefreshTokens')
      : TextProperty()

  return Model<RefreshToken>({
    pluralName: 'RefreshTokens',
    singularName: 'RefreshToken',
    namespace: AuthNamespace.Core,
    primaryKeyName: dataType === PropertyType.Integer ? 'id' : 'token',
    properties: {
      id: idProperty,
      token: TextProperty(
        ormPropertyConfig({ required: true, unique: 'token' })
      ),
      userId: getForeignKeyProperty(
        AuthNamespace.Core,
        'Users',
        getModel(AuthNamespace.Core, 'Users'),
        { required: true }
      ),
      expiresAt: DatetimeProperty({ required: true }),
      ttlSeconds: IntegerProperty({ required: true }),
      usedAt: DatetimeProperty(),
      revokedAt: DatetimeProperty(),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

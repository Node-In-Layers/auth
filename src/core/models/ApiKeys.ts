import {
  LastModifiedDateProperty,
  DatetimeProperty,
  TextProperty,
  PropertyType,
} from 'functional-models'
import { getPrimaryKeyDataType, ModelProps } from '@node-in-layers/core'
import { AuthConfig, AuthNamespace } from '../../types.js'
import { ApiKey } from '../types.js'

export const create = ({
  context,
  Model,
  getModel,
  getPrimaryKeyProperty,
  getForeignKeyProperty,
}: ModelProps<AuthConfig>) => {
  const dataType = getPrimaryKeyDataType(context, AuthNamespace.Core, 'ApiKeys')

  const idProperty =
    dataType === PropertyType.Integer
      ? getPrimaryKeyProperty(AuthNamespace.Core, 'ApiKeys')
      : TextProperty()

  return Model<ApiKey>({
    pluralName: 'ApiKeys',
    singularName: 'ApiKey',
    namespace: AuthNamespace.Core,
    primaryKeyName: dataType === PropertyType.Integer ? 'id' : 'key',
    properties: {
      id: idProperty,
      key: TextProperty({ required: true }),
      userId: getForeignKeyProperty(
        AuthNamespace.Core,
        'Users',
        getModel(AuthNamespace.Core, 'Users'),
        { required: true }
      ),
      name: TextProperty(),
      description: TextProperty(),
      expiresAt: DatetimeProperty(),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

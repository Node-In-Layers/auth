import {
  LastModifiedDateProperty,
  DatetimeProperty,
  TextProperty,
} from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { AuthConfig, AuthNamespace } from '../../types.js'
import { UserAuthIdentity } from '../types.js'

export const create = ({
  Model,
  getModel,
  getPrimaryKeyProperty,
  getForeignKeyProperty,
}: ModelProps<AuthConfig>) => {
  return Model<UserAuthIdentity>({
    pluralName: 'UserAuthIdentities',
    singularName: 'UserAuthIdentity',
    namespace: AuthNamespace.Core,
    primaryKeyName: 'id',
    properties: {
      id: getPrimaryKeyProperty(AuthNamespace.Core, 'UserAuthIdentities', {
        required: true,
      }),
      userId: getForeignKeyProperty(
        AuthNamespace.Core,
        'Users',
        getModel(AuthNamespace.Core, 'Users'),
        { required: true }
      ),
      iss: TextProperty({ required: true }),
      sub: TextProperty({ required: true }),
      email: TextProperty(),
      username: TextProperty(),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

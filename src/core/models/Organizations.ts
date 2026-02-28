import {
  LastModifiedDateProperty,
  DatetimeProperty,
  TextProperty,
} from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { AuthConfig, AuthNamespace } from '../../types.js'
import { Organization } from '../types.js'

export const create = ({
  Model,
  getModel,
  getPrimaryKeyProperty,
  getForeignKeyProperty,
}: ModelProps<AuthConfig>) => {
  return Model<Organization>({
    pluralName: 'Organizations',
    singularName: 'Organization',
    namespace: AuthNamespace.Core,
    primaryKeyName: 'id',
    properties: {
      id: getPrimaryKeyProperty(AuthNamespace.Core, 'Organizations', {
        required: true,
      }),
      name: TextProperty({ required: true }),
      ownerUserId: getForeignKeyProperty(
        AuthNamespace.Core,
        'Users',
        getModel(AuthNamespace.Core, 'Users'),
        { required: true }
      ),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

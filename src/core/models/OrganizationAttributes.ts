import {
  LastModifiedDateProperty,
  DatetimeProperty,
  TextProperty,
} from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { OrganizationAttribute } from '../types.js'
import { AuthConfig, AuthNamespace } from '../../types.js'

export const create = ({
  Model,
  getModel,
  getPrimaryKeyProperty,
  getForeignKeyProperty,
}: ModelProps<AuthConfig>) => {
  return Model<OrganizationAttribute>({
    pluralName: 'OrganizationAttributes',
    singularName: 'OrganizationAttribute',
    namespace: AuthNamespace.Core,
    primaryKeyName: 'id',
    properties: {
      id: getPrimaryKeyProperty(AuthNamespace.Core, 'OrganizationAttributes', {
        required: true,
      }),
      organizationId: getForeignKeyProperty(
        AuthNamespace.Core,
        'Organizations',
        getModel(AuthNamespace.Core, 'Organizations'),
        { required: false }
      ),
      userId: getForeignKeyProperty(
        AuthNamespace.Core,
        'Users',
        getModel(AuthNamespace.Core, 'Users'),
        { required: true }
      ),
      key: TextProperty({ required: true }),
      value: TextProperty({ required: true }),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

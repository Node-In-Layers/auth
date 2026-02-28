import { LastModifiedDateProperty, DatetimeProperty } from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { AuthConfig, AuthNamespace } from '../../types.js'
import { OrganizationAdmin } from '../types.js'

export const create = ({
  Model,
  getModel,
  getPrimaryKeyProperty,
  getForeignKeyProperty,
}: ModelProps<AuthConfig>) => {
  return Model<OrganizationAdmin>({
    pluralName: 'OrganizationAdmins',
    singularName: 'OrganizationAdmin',
    namespace: AuthNamespace.Core,
    primaryKeyName: 'id',
    properties: {
      id: getPrimaryKeyProperty(AuthNamespace.Core, 'OrganizationAdmins', {
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
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

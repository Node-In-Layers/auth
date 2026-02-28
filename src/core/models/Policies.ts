import {
  LastModifiedDateProperty,
  DatetimeProperty,
  TextProperty,
  ArrayProperty,
} from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { Policy } from '../types.js'
import { AuthConfig, AuthNamespace } from '../../types.js'

export const create = ({
  Model,
  getModel,
  getPrimaryKeyProperty,
  getForeignKeyProperty,
}: ModelProps<AuthConfig>) => {
  return Model<Policy>({
    pluralName: 'Policies',
    singularName: 'Policy',
    namespace: AuthNamespace.Core,
    primaryKeyName: 'id',
    properties: {
      id: getPrimaryKeyProperty(AuthNamespace.Core, 'Policies', {
        required: true,
      }),
      name: TextProperty({ required: true }),
      description: TextProperty({ required: true }),
      organizationId: getForeignKeyProperty(
        AuthNamespace.Core,
        'Organizations',
        getModel(AuthNamespace.Core, 'Organizations'),
        { required: false }
      ),
      action: TextProperty({ required: true }),
      resources: ArrayProperty<string>(),
      attributes: ArrayProperty<Record<string, string>>(),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

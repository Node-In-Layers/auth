import {
  LastModifiedDateProperty,
  DatetimeProperty,
  PrimaryKeyUuidProperty,
} from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { Organization } from '../types.js'

export const create = ({ Model }: ModelProps) => {
  return Model<Organization>({
    pluralName: 'Organizations',
    singularName: 'Organization',
    namespace: 'auth',
    primaryKeyName: 'id',
    properties: {
      id: PrimaryKeyUuidProperty(),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

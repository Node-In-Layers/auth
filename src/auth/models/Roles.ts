import {
  LastModifiedDateProperty,
  DatetimeProperty,
  PrimaryKeyUuidProperty,
} from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { Role } from '../types.js'

export const create = ({ Model }: ModelProps) => {
  return Model<Role>({
    pluralName: 'Roles',
    singularName: 'Role',
    namespace: 'auth',
    primaryKeyName: 'id',
    properties: {
      id: PrimaryKeyUuidProperty(),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

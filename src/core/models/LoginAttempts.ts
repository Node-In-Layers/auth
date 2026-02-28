import {
  LastModifiedDateProperty,
  DatetimeProperty,
  TextProperty,
} from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { AuthConfig, AuthNamespace } from '../../types.js'
import { LoginAttempt, LoginAttemptResult } from '../types.js'

export const create = ({
  getModel,
  Model,
  getPrimaryKeyProperty,
  getForeignKeyProperty,
}: ModelProps<AuthConfig>) => {
  return Model<LoginAttempt>({
    pluralName: 'LoginAttempts',
    singularName: 'LoginAttempt',
    namespace: AuthNamespace.Core,
    primaryKeyName: 'id',
    properties: {
      id: getPrimaryKeyProperty(AuthNamespace.Core, 'LoginAttempts', {
        required: true,
      }),
      startedAt: DatetimeProperty({ required: true }),
      endedAt: DatetimeProperty({ required: false }),
      ip: TextProperty({ required: false }),
      userAgent: TextProperty({ required: false }),
      userId: getForeignKeyProperty(
        AuthNamespace.Core,
        'Users',
        getModel(AuthNamespace.Core, 'Users'),
        { required: false }
      ),
      result: TextProperty({
        choices: Object.values(LoginAttemptResult),
        required: false,
      }),
      loginApproach: TextProperty({ required: false }),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

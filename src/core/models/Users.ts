import {
  LastModifiedDateProperty,
  DatetimeProperty,
  TextProperty,
  BooleanProperty,
  EmailProperty,
} from 'functional-models'
import { ModelProps } from '@node-in-layers/core'
import { AuthNamespace, AuthConfig } from '../../types.js'
import { User } from '../types.js'
import { getUserPropertyOverride } from '../libs.js'

export const create = ({
  context,
  Model,
  getPrimaryKeyProperty,
}: ModelProps<AuthConfig>) => {
  const passwordHashRequired =
    context.config[AuthNamespace.Core].allowPasswordAuthentication ?? false
  return Model<User>({
    pluralName: 'Users',
    singularName: 'User',
    namespace: AuthNamespace.Core,
    primaryKeyName: 'id',
    properties: {
      id: getPrimaryKeyProperty(AuthNamespace.Core, 'Users', {
        required: true,
      }),
      email: EmailProperty(
        getUserPropertyOverride(context, 'email', { required: true })
      ),
      firstName: TextProperty(
        getUserPropertyOverride(context, 'firstName', { required: true })
      ),
      lastName: TextProperty(
        getUserPropertyOverride(context, 'lastName', { required: true })
      ),
      npeOrganization: BooleanProperty(
        getUserPropertyOverride(context, 'npeOrganization', { required: false })
      ),
      username: TextProperty({ required: false }),
      passwordHash: TextProperty({ required: passwordHashRequired }),
      enabled: BooleanProperty({ required: true, defaultValue: true }),
      createdAt: DatetimeProperty({ autoNow: true }),
      updatedAt: LastModifiedDateProperty({ autoNow: true }),
    },
  })
}

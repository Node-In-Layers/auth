import merge from 'lodash/merge.js'
import { asyncMap } from 'modern-async'
import { getModel, ServicesContext } from '@node-in-layers/core'
import {
  DatastoreValueType,
  PrimaryKeyType,
  queryBuilder,
} from 'functional-models'
import { AuthNamespace } from '../types.js'
import {
  AuthCoreServices,
  OrganizationAdmin,
  OrganizationAttribute,
  User,
} from './types.js'

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const create = (context: ServicesContext): AuthCoreServices => {
  const _getOrganizationAdmin = async (
    user: User,
    organizationId: PrimaryKeyType | null
  ) => {
    const query = queryBuilder()
      .property('organizationId', organizationId)
      .and()
      .property('userId', user.id, {
        type:
          typeof organizationId === 'number'
            ? DatastoreValueType.number
            : DatastoreValueType.string,
      })
      .take(1)
      .compile()

    const OrganizationAdmins = getModel<OrganizationAdmin>(
      context,
      AuthNamespace.Core,
      'OrganizationAdmins'
    )
    const organizationAdmins = await OrganizationAdmins.search(query)
    return organizationAdmins.instances[0]
  }

  const isUserSystemAdmin = async (user: User) => {
    return _getOrganizationAdmin(user, null).then(Boolean)
  }

  const isOrganizationAdmin = async (
    user: User,
    organizationId: PrimaryKeyType
  ) => {
    return _getOrganizationAdmin(user, organizationId).then(Boolean)
  }

  const getUserOrganizationAttributes = async (user: User) => {
    const query = queryBuilder()
      .property('userId', user.id, {
        type:
          typeof user.id === 'number'
            ? DatastoreValueType.number
            : DatastoreValueType.string,
      })
      .compile()
    const OrganizationAttributes = getModel<OrganizationAttribute>(
      context,
      AuthNamespace.Core,
      'OrganizationAttributes'
    )
    const organizationAttributes = await OrganizationAttributes.search(query)
    const attributeObjs = await asyncMap(
      organizationAttributes.instances,
      instance => instance.toObj<OrganizationAttribute>()
    )
    return attributeObjs.reduce(
      (acc, obj) => {
        return merge(acc, {
          [obj.key]: obj.value,
        })
      },
      {} as Record<string, string>
    )
  }

  return {
    isUserSystemAdmin,
    isOrganizationAdmin,
    getUserOrganizationAttributes,
  }
}

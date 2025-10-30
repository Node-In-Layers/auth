import type { OidcUserContext, User, SystemUser } from '@deep-helix/sdk'
import jwt from 'jsonwebtoken'
import { Group } from '@deep-helix/sdk'

const validateOidcToken = (
  token: string,
  jwksOrSecret: string | Buffer,
  options: jwt.VerifyOptions = {}
): OidcUserContext => {
  const decoded = jwt.verify(token, jwksOrSecret, options)
  return decoded as OidcUserContext
}

export const parseAuth0User = (user: any, roles: readonly string[]): User => {
  const givenName = user.user_metadata?.given_name || user.given_name
  const familyName = user.user_metadata?.family_name || user.family_name
  return {
    type: 'user',
    id: user.user_id,
    email: user.email,
    name: user.name,
    firstName: givenName,
    lastName: familyName,
    groups: roles as Group[],
    preferredUsername: user.username || user.email,
  }
}

const getUserForRequest = (req: Request & { user: User | SystemUser }) => {
  // @ts-ignore
  if (!req.user) {
    return {}
  }
  return {
    user: {
      type: req.user.type,
      // @ts-ignore
      id: req.user.id ? req.user.id : req.user.clientId,
      // @ts-ignore
      ...(req.user.preferredUsername
        ? // @ts-ignore
          { username: req.user.preferredUsername }
        : {}),
    },
  }

  // @ts-ignore
  return { user: req.user }
}

/**
 * Filter strategy that returns true if the user is not in any of the groups.
 * @param groups - The groups to check against.
 * @returns A filter strategy function.
 */
export const cannotBeInGroupsStrategy = (groups: readonly Group[]) => user => {
  return !groups.some(group => user.groups.includes(group))
}

/**
 * Filter strategy that returns true if the user is not a system admin or account manager.
 * @param user - The user to check.
 * @returns A filter strategy function.
 */
export const canOnlyBeUserStrategy = (user: User) => {
  return cannotBeInGroupsStrategy([Group.SystemAdmin, Group.AccountManager])(
    user
  )
}

export { validateOidcToken, getUserForRequest }

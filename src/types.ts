import type { Request, Response } from 'express'
import { Config, ErrorObject, XOR } from '@node-in-layers/core'

export enum AuthNamespace {
  Core='@node-in-layers/auth/core',
  Authentication='@node-in-layers/authentication'
  Express='@node-in-layers/auth/express',
  OAuth2='@node-in-layers/auth/oauth2',
}

export type AuthenticationMethod = (headers: Record<string, any>) => Promise<XOR<User|ErrorObject>>

export const AuthConfigurations = Readonly<{
  [AuthNamespace.Core]: {
    users: {
      /**
       * These are the list of properties that are available for reading and searching of users
       * to people on the system.
       */
      publicReadProperties: readonly string[]
    }
  },
  [AuthNamespace]: {
    /**
     * Dot pathed service function. Should be in "services" taking the form "domain.functionName"
     * NOTE: this domain should be loaded BEFORE the auth package in the system's config.
     */
    customAuthenticationMethod?: string,
    oauth2: {
      jwePrivateKey?: string,
      jwksUris: readonly string[],
      oidcRoleKey: string,
      domain?: string,
      clientId: string,
      clientSecret: string,
    }
  }
}> 

export const AuthConfig = Config & AuthConfigurations

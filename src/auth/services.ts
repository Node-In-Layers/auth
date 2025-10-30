import jwkToPem from 'jwk-to-pem'
import type { JWK } from 'jose'
import { ManagementClient } from 'auth0'
import { jwtVerify, jwtDecrypt, importPKCS8, importJWK } from 'jose'
import axios from 'axios'
import { Config, ServicesContext, ModelProps } from '@node-in-layers/core'
import { OrmModel, OrmSearch, createOrm } from 'functional-models'
import { auth, User, PlainSearchResult } from '@deep-helix/sdk'
import { AuthConfig } from '../types.js'
import { canOnlyBeUserStrategy } from './libs.js'
import { create as createDatastoreAdapter } from './auth0DatastoreAdapter.js'

const SECONDS = 60
const MILLISECONDS = 1000
const MINUTES_JWKS_CACHE_TTL = 60
const HTTP_UNAUTHORIZED = 401
const JWE_PARTS_LENGTH = 5
const JWS_PARTS_LENGTH = 3

const jwksStateMachine = () => {
  // eslint-disable-next-line functional/no-let
  let thisCache: ReadonlyArray<JWK> | undefined
  // eslint-disable-next-line functional/no-let
  let lastFetch: Date | undefined
  return {
    getCache: () => thisCache,
    getLastFetch: () => lastFetch,
    setCache: (cache: ReadonlyArray<JWK>) => {
      thisCache = cache
      lastFetch = new Date()
    },
  }
}

const create = (context: ServicesContext<AuthConfig>) => {
  const authConfig = context.config[AuthNamespace]
  const JWKS_CACHE_TTL = MILLISECONDS * SECONDS * MINUTES_JWKS_CACHE_TTL
  const jwksUris = authConfig.oauth2.jwksUris
  const jwksState = jwksStateMachine()


  const fetchJwks = async (): Promise<ReadonlyArray<JWK>> => {
    const now = Date.now()
    const lastFetch = jwksState.getLastFetch()
    const cache = jwksState.getCache()
    if (lastFetch && cache && now - lastFetch.getTime() < JWKS_CACHE_TTL) {
      return cache as ReadonlyArray<JWK>
    }
    const newCache = await Promise.all(
      jwksUris.map(async uri => {
        const { data } = await axios.get(uri).catch(e => {
          throw e
        })
        return data.keys as ReadonlyArray<JWK>
      })
    ).then(x => x.flat())
    jwksState.setCache(newCache)
    return newCache as ReadonlyArray<JWK>
  }

  const getPemForKid = async (kid: string): Promise<string | undefined> => {
    const keys = await fetchJwks()
    const jwk = keys.find(k => k.kid === kid)
    return jwk ? jwkToPem(jwk) : undefined
  }

  const getPrivateKey = async () => {
    const pem = context.config[a].auth.privateKey
    if (!pem) {
      throw new Error(`JWE private key not provided`)
    }
    // 'RSA-OAEP-256' is the alg for JWE decryption
    return importPKCS8(pem, 'RSA-OAEP-256')
  }

  const standardJwtAuthorization = (headers) => {
    return Promise.resolve()
      .then(async () => {
        const authHeader = headers.authorization
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return createErrorObject('HTTP_UNAUTHORIZED', 'Missing or invalid Authorization header')
        }
        const token = authHeader.slice('Bearer '.length)
        const parts = token.split('.')
        const payload =
          parts.length === JWE_PARTS_LENGTH
            ? await _getJwePayload(token)
            : parts.length === JWS_PARTS_LENGTH
              ? await _getJwsPayload(token)
              : null
        if (!payload) {
          return createErrorObject('HTTP_UNAUTHORIZED', 'Missing or invalid Authorization header')
        }
        // eslint-disable-next-line require-atomic-updates, functional/immutable-data
        req.user = oidcToUser(
          payload as any,
          authConfig.oauth2.oidcRoleKey
        )
        return undefined
      })
      .catch(e => {
        return createErrorObject('UNHANDLED_AUTH_EXCEPTION', 'An unhandled authorization exception occurred', e)
      })
  }

  const _getJwePayload = async (token: string) => {
    const privateKey = await getPrivateKey()
    const { payload: decryptedPayload } = await jwtDecrypt(token, privateKey)
    return decryptedPayload
  }

  const _getJwsPayload = async (token: string) => {
    const jwks = await fetchJwks()
    const { payload: verifiedPayload } = await jwtVerify(
      token,
      async header => {
        const key = jwks.find(k => k.kid === header.kid)
        if (!key) {
          throw new Error('No matching JWK')
        }
        // Convert JWK to KeyLike object for jose
        return importJWK(key, 'RS256')
      }
    )
    return verifiedPayload
  }


  const _getAuth0 = () => {
    return new ManagementClient({
      domain: context.config.backendSdk.auth0.domain,
      clientId: context.config.backendSdk.auth0.clientId,
      clientSecret: context.config.backendSdk.auth0.clientSecret,
    })
  }

  const getModelProps = (): Promise<ModelProps> => {
    const auth0 = _getAuth0()

    const datastoreAdapter = createDatastoreAdapter(auth0)
    const orm = createOrm({
      datastoreAdapter,
    })
    return {
      // @ts-ignore
      fetcher: orm.fetcher,
      // @ts-ignore
      getModel: () => {
        throw new Error('Not implemented')
      },
      // @ts-ignore
      Model: orm.Model,
    }
  }

  const _getUserOnlyModel = async () => {
    const auth0 = _getAuth0()
    const datastoreAdapter = createDatastoreAdapter(auth0, {
      filterStrategy: canOnlyBeUserStrategy,
    })
    const orm = createOrm({
      datastoreAdapter,
    })
    const model = auth.models.Users.create({
      // @ts-ignore
      Model: orm.Model,
      // @ts-ignore
      fetcher: orm.fetcher,
      // @ts-ignore
      getModel: orm.getModel,
    }) as OrmModel<User>
    return {
      datastoreAdapter,
      model,
    }
  }

  const searchRegularUsers = async (
    query: OrmSearch
  ): Promise<PlainSearchResult<User>> => {
    const { model, datastoreAdapter } = await _getUserOnlyModel()
    return datastoreAdapter.search<User>(model, query)
  }

  const retrieveRegularUser = async (id: string): Promise<User | undefined> => {
    const { model, datastoreAdapter } = await _getUserOnlyModel()
    return datastoreAdapter.retrieve<User>(model, id)
  }

  return Object.freeze({
    fetchJwks,
    getPemForKid,
    getModelProps,
    searchRegularUsers,
    retrieveRegularUser,
  })
}

export { create }

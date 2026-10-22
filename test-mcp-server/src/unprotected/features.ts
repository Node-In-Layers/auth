import { annotatedFunction } from '@node-in-layers/core'
import { z } from 'zod'

export const create = (context: any) => {
  const myUnprotectedFeature = annotatedFunction(
    {
      functionName: 'myUnprotectedFeature',
      domain: 'unprotected',
      description: 'This is an unprotected Hello World',
      args: z.object({
        name: z.string(),
      }),
      returns: z.object({
        greeting: z.string(),
      }),
    },
    args => {
      return {
        greeting: `(Unprotected): Hello ${args.name}`,
      }
    }
  )

  return {
    myUnprotectedFeature,
  }
}

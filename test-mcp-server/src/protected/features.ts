import z from 'zod'
import { annotatedFunction } from '@node-in-layers/core'

export const create = (context: any) => {
  const myProtectedFeature = annotatedFunction(
    {
      functionName: 'myProtectedFeature',
      domain: 'protected',
      description: 'This is a protected Hello World',
      args: z.object({
        name: z.string(),
      }),
      returns: z.object({
        greeting: z.string(),
      }),
    },
    args => {
      return {
        greeting: `(Protected): Hello ${args.name}`,
      }
    }
  )
  return {
    myProtectedFeature,
  }
}

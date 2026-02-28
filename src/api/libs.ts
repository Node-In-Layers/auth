import type { CustomUserModelReference } from './types.js'

/**
 * Builds a custom user model reference string in the form `domain.PluralModelName`.
 * @param domain - Domain (e.g. package or layer name).
 * @param modelName - Plural model name (e.g. Users).
 * @returns The reference string (e.g. `"myDomain.Users"`).
 * @throws Error if domain or modelName is missing or whitespace-only.
 */
export const buildCustomUserModelReference = (
  domain: string,
  modelName: string
): string => {
  if (!domain?.trim()) {
    throw new Error('domain is required for custom user model reference')
  }
  if (!modelName?.trim()) {
    throw new Error('modelName is required for custom user model reference')
  }
  return `${domain.trim()}.${modelName.trim()}`
}

/**
 * Parses a custom user model reference string into domain and modelName.
 * @param reference - String in the form `domain.PluralModelName` (e.g. `"myDomain.Users"`).
 * @returns Object with `domain` and `modelName`; the last dot separates them.
 * @throws Error if reference has no dot or domain/modelName is empty after trimming.
 */
export const parseCustomUserModelReference = (
  reference: string
): CustomUserModelReference => {
  const i = reference.lastIndexOf('.')
  if (i === -1) {
    throw new Error(
      `Invalid auth core userModel "${reference}". Expected "domain.PluralModelName".`
    )
  }
  const domain = reference.slice(0, i).trim()
  const modelName = reference.slice(i + 1).trim()
  if (!domain || !modelName) {
    throw new Error(
      `Invalid auth core userModel "${reference}". Expected "domain.PluralModelName".`
    )
  }
  return {
    domain,
    modelName,
  }
}

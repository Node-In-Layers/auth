import kebabCase from 'lodash/kebabCase.js'
import { ActionForPolicy, ResourceTypeForPolicy } from '../types.js'

export const formatResourceSegment = (segment: string): string => {
  if (segment === '*') {
    return '*'
  }
  return kebabCase(segment)
}

export const matchResourceSegment = (
  requested: string,
  policy: string
): boolean => {
  if (policy === '*') {
    return true
  }
  return formatResourceSegment(requested) === formatResourceSegment(policy)
}

/**
 * Checks if a requested resource string matches a policy resource string.
 * Both should be in the format: domain:resourceType:resource:action
 * @param requestedStr The resource being requested
 * @param policyStr The resource pattern from the policy
 * @returns true if it matches
 */
export const matchesResource = (
  requestedStr: string,
  policyStr: string
): boolean => {
  if (policyStr === '*') {
    return true
  }

  const reqSegments = requestedStr.split(':')
  const polSegments = policyStr.split(':')

  const POLICY_SEGMENT_COUNT = 4
  if (
    reqSegments.length !== POLICY_SEGMENT_COUNT ||
    polSegments.length !== POLICY_SEGMENT_COUNT
  ) {
    // Fallback for improperly formatted strings
    return (
      formatResourceSegment(requestedStr) === formatResourceSegment(policyStr)
    )
  }

  return reqSegments.every((reqSeg, i) =>
    matchResourceSegment(reqSeg, polSegments[i] || '')
  )
}

export const buildResourceString = (
  domain: string,
  resourceType: ResourceTypeForPolicy | string,
  resource: string,
  action: ActionForPolicy | string
): string => {
  return `${formatResourceSegment(domain)}:${formatResourceSegment(resourceType)}:${formatResourceSegment(resource)}:${formatResourceSegment(action)}`
}

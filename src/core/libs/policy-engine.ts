import { type Policy, PolicyAction } from '../../types.js'
import { type PolicyEngineContext } from '../types.js'
import { buildResourceString, matchesResource } from './resource-strings.js'

const _policyAppliesToUser = (
  policy: Policy,
  engineContext: PolicyEngineContext
): boolean => {
  const targetsUser = Boolean(
    policy.userIds && policy.userIds.includes(engineContext.request.userId)
  )

  const targetsAttributes = Boolean(
    policy.attributes &&
    policy.attributes.some(attrGrp => {
      // Must match ALL keys in the attribute group
      return Object.entries(attrGrp).every(
        ([k, v]) => engineContext.userAttributes[k] === v
      )
    })
  )

  if (
    policy.userIds &&
    policy.userIds.length > 0 &&
    policy.attributes &&
    policy.attributes.length > 0
  ) {
    return targetsUser || targetsAttributes
  } else if (policy.userIds && policy.userIds.length > 0) {
    return targetsUser
  } else if (policy.attributes && policy.attributes.length > 0) {
    return targetsAttributes
  }

  // If neither userIds nor attributes are defined, it applies to everyone in scope
  return true
}

/**
 * Core engine for evaluating whether a user can access a resource.
 * @param policies A list of policies to evaluate against.
 * @param engineContext The context of the request and the user.
 * @returns PolicyAction.Allow or PolicyAction.Deny
 */
export const policyEngine = (
  policies: readonly Policy[],
  engineContext: PolicyEngineContext
): PolicyAction => {
  if (engineContext.isSystemAdmin) {
    return PolicyAction.Allow
  }

  if (engineContext.request.organizationId && engineContext.isOrgAdmin) {
    return PolicyAction.Allow
  }

  const reqStr = buildResourceString(
    engineContext.request.domain,
    engineContext.request.resourceType,
    engineContext.request.resource,
    engineContext.request.action
  )

  const applicablePolicies = policies.filter(policy =>
    _policyAppliesToUser(policy, engineContext)
  )

  const matchingPolicies = applicablePolicies.filter(policy =>
    policy.resources.some(polRes => matchesResource(reqStr, polRes))
  )

  const hasDeny = matchingPolicies.some(
    policy => policy.action === PolicyAction.Deny
  )
  if (hasDeny) {
    return PolicyAction.Deny
  }

  const hasAllow = matchingPolicies.some(
    policy => policy.action === PolicyAction.Allow
  )

  return hasAllow ? PolicyAction.Allow : PolicyAction.Deny
}

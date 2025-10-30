# Node in Layers Auth - an Official Node in Layers Package
This package contains common authentication and authorization related code. This includes important system building models such as users and organizations as well as resuable and extensible logic for doing authentication and authorization on features and model functions.


# Features
- Control who can access a feature
- Control who can access a model, any specific method on that model, and even the individual rows themselves.
- Treeshakeable Functionality, for backend / frontend uses
- Ability to create/use custom authentication
- Ability to create/use custom authorization



# Core Feature Implementations
## User
A user model respresents a single user of the system. 

They always have full control over their own model, and the only other users that can "write" to their user are system admins. 

There are aspects to the user that are public read to users within the system, which is controlled by the configuration of this package.

```typescript
type User = Readonly<{
  email: string,
  firstName: string,
  lastName: string,
  /**
  * Is this "person" a non-person entity? If so, the organization id that this non-person entity is part of, is placed here.
  * This adds the ability for your system to support having "systems" as a user. This is completely optional, and your system
  * can just make system-system connections using an actual user's credentials.
  * If there is a value here, these non-person entities, should not show up in normal user queries.
  */
  npeOrganization?: boolean
}>
```

## Organization
An organization is a non-person entity that is managed by users.
An organization can own data that users can then manipulate based on attribute policies (see below).

```typescript
export type Organization = Readonly<{
  id: PrimaryKey
  name: string
  /**
  * The owner of the organization, (not in reality, just in terms of the user)
  */
  ownerUserId: PrimaryKey
}>
```

### OrganizationAdmins
This model says explicitly who are the admins of an organization. By default the person who creates an organization is automatically made an admin as well as the owner. No admin can remove themselves of being an admin of an organization, and only an owner (or system admin) can transfer ownership of the organization to someone else.

```typescript
type OrganizationAdmins = Readonly<{
  id: PrimaryKey
  organizationId?: PrimaryKey
  userId: PrimaryKey
}>
```

NOTE: An organizationId of null/undefined is a SYSTEM level admin. These can only be created by a system level admin.

### OrganizationAttributes
This model holds key:value pairs for a user with an organization. This is a more expressive representation of a "role" concept, but could expand to multiple different kinds of attributes.

These attributes are created/managed by admins of an organization.

NOTE: An organizationId of null/undefined is a SYSTEM attribute. These can only be created by a system level admin.

```typescript
type OrganizationAttributes = Readonly<{
  id: PrimaryKey
  organizationId?: PrimaryKey
  key: string
  value: string
}>
```

### OrganizationReferenceProperty
This property for a model adds a Foreign Key to an organization. This is a critical property that should be used throughout a system to control organization level access. All data that is associated with an organization should have this property. If it doesn't have this, then it is assumed that the data is system level, rather than user data. 

In addition to just providing a number/string as a foreign key, it includes metadata in the PropertyConfig that is used by authorization code to decide if a user should have access to the data.


```typescript
type OrganizationReferenceProperty = Readonly<{
  /**
  * Defaults to "organizationId"
  */
  propertyKey?: string
}>

```

# Authentication Feature Implementations

The primary implementation of the authentication happens with Json Web Tokens.
When a user (or system user) successfully "logs in", they get a JWT and use that with subsequent requests.

Then for each request, the JWT allows the authenticated user to call features/models. 
At this point the authorization process takes over.

If using an OIDC type of flow with Auth0, Facebook, Google, etc, the frontend would make the request to the provider, get the provider's returned JWT, and then send it to the system's backend. The backend would validate this JWT via Json Web Keys (jwks) and then issue a system level JWT and return it back to the user for subsequent requests.

Username/Passwords and API Keys ultimately work similar as well. First the caller makes a login request with these objects, it then goes through the authentication process, and returns a JWT to be used if successful.


# AuthorizationConfig
Authentication is configured in the config file of each of the parts of the system (backend/frontend).
Multiple approaches can be provided and they can be ordered by which ones should be tried first.

```typescript
import { AuthNamespace } from '@node-in-layers/auth'

type AuthorizationConfig = Readonly<{
  [AuthNamespace.backend]: {
    /**
    * If you need better typing/schemas for the login feature that either restricts or expands the supported
    * login approaches, put it here. This will be used instead of the default.
    */
    loginSchema?: ZodObject 
    /**
    * This takes the form of "domain"."featureName"
    * Example: "myDomain.myFeature"
    */
    approaches: readonly string[]
  }
}>

// Example:
const config = {
  '@node-in-layers/auth/backend': {

    loginSchema: z.object({
      customAuth: z.object({
        customKey: z.string()
      }).describe('My custom auth schema')
    }).describe('The authentication schema'),

    approaches: [
      '@node-in-layers/auth/backend.apiKeyAuth',
      '@node-in-layers/auth/backend.oidcAuth',
      '@node-in-layers/auth/backend.basicAuth',
    ]
  }
}

```

## Included Authentication Approaches
- Username/Password (Basic Auth)
- OpenID Connect (OIDC) 
- Api Keys

## Login
The authentication backend domain (`AuthNamespace.backend`) has has the `login()` feature.
This feature can allow a user/system to login to the system using the configured authorization approaches, and receive a JWT back for future requests.

### Login Properties
The login feature has dynamic properties based on the authentication approach on the backend. Having said that, the schema for the `annotatedFunction`
can be changed in the configuration file, via the `loginSchema` property, so that consumers of this function can know exactly what the expected types are.
By default, optional properties are used for all "known standard supported approaches", even if they are not explicitly configured.
Having said that, the `loginSchema` can be explicitly set to the schemas exported by @node-in-layers/auth.

```typescript
type LoginProps = Readonly<{
  oidcAuth?: {
    token: string,
  },
  apiKeyAuth?: {
    key: string,
  },
  basicAuth?: {
    username: string,
    password: string,
  },
}>
```






# Authorization Features Implementations

## Policies
A simple structured object that makes it explicit who can and cannot access functionality in the system.

During runtime, the policy engine checks policies against the calling user and determines if they can access it or not.

IMPORTANT SECURITY NOTE: 
If a user is an admin of an organization, policies never apply to them, and organization level resources are always "ALLOW".
The same can be said for Admins of the system itself.

### PolicyEngine (Application) 
The policies are applied by a policy engine.
When a policy decision is being made, the following logic is used:

1. Is this a system user? If so, immediately ALLOW.
1. Is this a system level resource? If so, use system level policies.
1. Is this an organization level resource? If so, use organization level policies.

#### System Level Resource
1. Are there any explicit DENY policies that match the user and the action requested? If so, DENY.
1. Does the user match any of the ALLOW policies? If so, ALLOW 
1. DENY 

#### Organization Level Resource
1. Is this an Organization Admin? If so, immediately ALLOW.
1. Are there any explicit DENY policies that match the user and the action requested? If so, DENY.
1. Does the user match any of the ALLOW policies? If so, ALLOW.
1. DENY


### Details 

```typescript
export type Policy = Readonly<{
  id: PrimaryKey,
  name: string,
  description?: string,
  organizationId?: PrimaryKey,
  action: "ALLOW"|"DENY",
  /**
  * Resource policy strings for stating what resources can be accessed.
  */
  resources: readonly string[]
  /**
  * Data attribute level controls. "You must have this key:value attribute in order to access this data"
  * If this is not provided, this policy applies to everyone who is associated with the organization.
  * (This happens by the OrganizationAttribute model with a key "member" and the value being the user's id.)
  */
  attributes?: readonly Record<string, string>[]
}>
```

#### Simple Example:
```
{
  "name": "My Organizations Admins",
  "description": "All admins in my organization can access all features and models.",
  "organizationId": "x-y-z-organization-id",
  "action": "ALLOW",
  "policies": [
    "myDomain:features:*:*",
    "myDomain:models:*:*"
  ],
  "attributes": [{
    "role": "Admin"
  }]
}
```

### Resource Policy Format Strings
The following explains in detail the policy string format.

`{domain}:{resourceType}:{resource}:{resourceAction}`


```typescript
export enum ModelActionsForPolicy {
  Create='Create',
  Retrieve='Retrieve',
  Update='Update',
  Delete='Delete',
  Search='Search',
}
```

All values can be replaced with a "star" to mean all.

#### Example: "I want anyone to be able to have access to the myFeature inside myDomain"
myDomain:features:myFeature:*:*:*

#### Example: "I want only admins able to have access to the theFeature inside myDomain"
`myDomain:features:theFeature:*:role:primary-key-of-organization-admin-role`

#### Example: "I want users to be able to access Transcriptions but only read"
`myDomain:models:transcriptions:retrieve:role:primary-key-of-organization-user-role`
`myDomain:models:transcriptions:search:role:primary-key-of-organization-user-role`

`myDomain:models:transcriptions:search:attribute:primary-key-of-organization-user-role`


### System Policies
System policies are policies that can only be managed by superusers of the system. These are primarily used to lock down system resources from use by users.

They are distinguished by having NO organizationId.

### Organization Policies
Organization level policies are policies that are managed by "Admins" of an organization. They can be used to lock down who can access features/model data.

These are distinguished by having an organizationId. 


### Key Value Data Attribute Controls 
To provide a user access to sensitive data such as an organizations data, then Data Attribute Controls come into play. Properties on a model are tagged with one or more data attribute controls, and the organization that owns the data must have the policies in place

Example:
You want to control access to a certain model "Car" by "organizationId".
The "organizationId"'s property is wrapped with the "AttributeControlProperty".
Then the user has "organizationId:the-organizations-id" in their policies.
The user is able to access only the data where it has that organizationId .




# Domains
TODO
## Core
Contains the core re-usable libraries, models and types. Can be used in any setting whether that is backend or frontend/browser.

## Express
Contains code for express based API servers. This includes MCP servers as well as normal REST servers.

## OAuth2
Contains code for conducting authorization/authentication via OAuth2 and OIDC flows.


# Possible Future Features
## Saml Domain
Adding ability to do authentication via saml.

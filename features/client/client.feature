Feature: Auth client authentication lifecycle and configured credentials

  Scenario: Explicit basicAuth login stores state and resolves getAuth
    Given we use an auth-client connected to "basic-and-shared-secret" server
    And we seed "basic-user-enabled" auth records
    When we auth-client login with email "basic@example.com" and password "basic-password-1"
    Then auth-client login result should include user email "basic@example.com" and token
    When we call auth-client getAuth
    Then auth-client getAuth result should match the logged in token

  Scenario: Empty login({}) uses configured sharedSecretAuth credentials
    Given we use an auth-client connected to "shared-secret-default" server with configured "shared-secret" credentials
    When we auth-client login with empty props
    Then auth-client login result should include user email "worker@service.local" and token
    When we call auth-client getAuth
    Then auth-client getAuth result should match the logged in token

  Scenario: getAuth() automatically logs in when configured credentials exist and not yet logged in
    Given we use an auth-client connected to "shared-secret-default" server with configured "shared-secret" credentials
    When we call auth-client getAuth
    Then auth-client getAuth result should include a bearer token
    And auth-client state should contain user email "worker@service.local"

  Scenario: Empty login({}) uses configured apiKeyAuth credentials
    Given we use an auth-client connected to "api-key-and-basic" server with configured "api-key" credentials
    And we seed "api-key-active" auth records
    When we auth-client login with empty props
    Then auth-client login result should include user email "apikey@example.com" and token

  Scenario: Refresh rotates token and updates getAuth
    Given we use an auth-client connected to "basic-and-shared-secret" server
    And we seed "basic-user-enabled" auth records
    When we auth-client login with email "basic@example.com" and password "basic-password-1"
    And we auth-client refresh the token
    Then auth-client refresh should return a new token and update getAuth

  Scenario: Logout clears state and requires re-authentication
    Given we use an auth-client connected to "basic-and-shared-secret" server
    And we seed "basic-user-enabled" auth records
    When we auth-client login with email "basic@example.com" and password "basic-password-1"
    And we auth-client logout
    Then auth-client state should be empty

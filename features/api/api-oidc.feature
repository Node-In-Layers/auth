Feature: API Authentication with OIDC

  Scenario: OIDC login succeeds with mapped identity
    Given we use "oidc-default" context
    And we seed "oidc-user-identity" auth records
    When we run auth login with "oidc-valid-login" data
    Then result should match "login-success-oidc"

  Scenario: Authenticate works with token from prior login
    Given we use "basic-default" context
    And we seed "basic-user-enabled" auth records
    When we run auth login with "basic-valid-login" data
    And we run auth authenticate with token from result
    Then result should match "authenticate-success"

  Scenario: Authenticate fails with malformed token
    Given we use "basic-default" context
    When we run auth authenticate with "malformed-token" token
    Then result should match "authenticate-failure"
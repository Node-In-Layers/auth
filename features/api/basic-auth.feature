Feature: API Authentication with Basic Auth

  Scenario: Basic auth login succeeds with seeded user
    Given we use "basic-default" context
    And we seed "basic-user-enabled" auth records
    When we run auth login with "basic-valid-login" data
    Then result should match "login-success-basic"

  Scenario: Basic auth login fails with wrong password
    Given we use "basic-default" context
    And we seed "basic-user-enabled" auth records
    When we run auth login with "basic-invalid-password" data
    Then result should match "login-failure"
Feature: API Authentication with API Keys

  Scenario: API key login succeeds with seeded key
    Given we use "api-key-default" context
    And we seed "api-key-active" auth records
    When we run auth login with "api-key-valid-login" data
    Then result should match "login-success-api-key"

  Scenario: API key login fails with unknown key
    Given we use "api-key-default" context
    And we seed "api-key-active" auth records
    When we run auth login with "api-key-invalid-login" data
    Then result should match "login-failure"

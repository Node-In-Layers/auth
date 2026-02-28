Feature: API Authentication fall-through behavior

  Scenario: Falls through from API key to Basic auth
    Given we use "api-key-then-basic" context
    And we seed "basic-user-enabled" auth records
    When we run auth login with "fallthrough-api-key-invalid-basic-valid" data
    Then result should match "login-success-basic"

  Scenario: Uses first successful approach in order
    Given we use "api-key-then-basic" context
    And we seed "api-key-and-basic-active" auth records
    When we run auth login with "fallthrough-api-key-valid-basic-invalid" data
    Then result should match "login-success-api-key"

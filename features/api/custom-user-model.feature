Feature: API Authentication with custom user model

  Scenario: Basic auth works with consuming system user model
    Given we use "custom-user-basic-default" context
    And we seed "custom-user-basic-enabled" auth records
    When we run auth login with "custom-basic-valid-login" data
    Then result should match "login-success-basic"

Feature: Express auth route protection

  Scenario: Unprotected Express route works without auth
    Given we use "express-default" express context
    When we call express request "health-no-auth"
    Then result should match "express-unprotected-success"

  Scenario: Protected Express route rejects missing bearer token
    Given we use "express-default" express context
    When we call express request "protected-no-auth"
    Then result should match "express-protected-unauthorized"

  Scenario: Login Express route is unprotected
    Given we use "express-default" express context
    And we seed "basic-user-enabled" auth records
    When we call express request "login-no-auth"
    Then result should match "express-login-unprotected"

Feature: OAuth passthrough auto-provision user

  Scenario: Authenticate with OIDC creates user when autoProvision is on
    Given we use "express-passthrough-oidc" context
    And there is no user linked to the current oidc token
    When we run auth authenticate with oidc bearer
    Then result should match "authenticate-passthrough-provisioned-user"
    And a user is linked to the current oidc token

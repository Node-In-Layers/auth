Feature: MCP auth route protection

  Scenario: Unprotected MCP route works without auth
    Given we use "mcp-default" mcp context
    When we call mcp request "health-no-auth"
    Then result should match "mcp-unprotected-success"

  Scenario: Protected MCP route rejects missing bearer token
    Given we use "mcp-default" mcp context
    When we call mcp request "protected-no-auth"
    Then result should match "mcp-protected-unauthorized"

  Scenario: Login MCP route is unprotected
    Given we use "mcp-default" mcp context
    And we seed "basic-user-enabled" auth records
    When we call mcp request "login-no-auth"
    Then result should match "mcp-login-unprotected"

  Scenario: Unprotected MCP tool works without auth
    Given we use "mcp-default" mcp context
    And we seed "basic-user-enabled" auth records
    When we call mcp request "tool-login-no-auth"
    Then result should match "mcp-tool-login-unprotected"

  Scenario: Protected MCP tool rejects missing bearer token
    Given we use "mcp-default" mcp context
    When we call mcp request "tool-cleanup-no-auth"
    Then result should match "mcp-protected-unauthorized"

  Scenario: Protected MCP tool works with valid bearer token
    Given we use "mcp-default" mcp context
    And we seed "basic-user-enabled" auth records
    When we call mcp request "login-no-auth"
    And we call mcp request "tool-cleanup-no-auth" with bearer token from result
    Then result should match "mcp-tool-protected-with-auth"

  Scenario: Non-execute MCP methods do not require auth
    Given we use "mcp-default" mcp context
    When we call mcp request "resources-read-no-auth"
    Then result should match "mcp-non-execute-unprotected"

Feature: MCP client auth and feature access

  Scenario: Login with valid credentials returns token
    Given we use the test-mcp-server
    When we mcp-client login with email "testuser@example.com" and password "test-password-123"
    Then mcp-client login should succeed

  Scenario: Refresh with valid refresh token returns new token
    Given we use the test-mcp-server
    When we mcp-client login with email "testuser@example.com" and password "test-password-123"
    And we mcp-client refresh the token
    Then mcp-client refresh should succeed

  Scenario: Unprotected feature works without login
    Given we use the test-mcp-server
    When we call mcp-client unprotected feature with name "World"
    Then mcp-client greeting should contain "(Unprotected): Hello World"

  Scenario: Protected feature works after login
    Given we use the test-mcp-server
    When we mcp-client login with email "testuser@example.com" and password "test-password-123"
    And we call mcp-client protected feature with name "World"
    Then mcp-client greeting should contain "(Protected): Hello World"

  Scenario: Protected feature requires restored state in a new client
    Given we use the test-mcp-server
    When we mcp-client login with email "testuser@example.com" and password "test-password-123"
    And we replace mcp-client with a new client without auth state
    And we attempt to call mcp-client protected feature with name "World"
    Then mcp-client request should be unauthorized
    When we set mcp-client state from previous auth state
    And we call mcp-client protected feature with name "World"
    Then mcp-client greeting should contain "(Protected): Hello World"

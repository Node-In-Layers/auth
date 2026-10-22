Feature: RFC 8693 token exchange with Dex

  OAuth 2.0 token exchange (RFC 8693) against a real Dex container (requires Docker).
  One scenario avoids loading the full stack three times (the main source of “hang”
  was repeated loadSystem + Dex startup per scenario).

  Scenario: Exchange password-grant token via ApiServices (explicit subject, bearer, named target)
    Given we use "token-exchange-dex" context
    When we obtain a dex password access token for token exchange
    And we exchange the subject token for a downstream access token using api services
    Then the token exchange result should be issued by dex
    When we exchange using incoming Authorization bearer as subject token
    Then the token exchange result should be issued by dex
    When we exchange the subject token using named target "secondary"
    Then the token exchange result should be issued by dex

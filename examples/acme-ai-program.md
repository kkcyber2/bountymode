# Acme AI Assistant — Bug Bounty Program

Platform: Bugcrowd
Program: acme-ai-assistant

## In Scope

| Target | Kind | Max Severity |
|---|---|---|
| api.acme-ai.example | api | critical |
| chat.acme-ai.example | llm | critical |
| acme-ai.example | web | high |

## Out of Scope

- status.acme-ai.example — third-party status page, not owned by Acme
- *.cdn.acme-ai.example — CDN provider infrastructure
- marketing.acme-ai.example — static marketing site, no user data

## Rules

- Do not run automated scanners at aggressive intensity against production.
- Denial-of-service testing is prohibited.
- Social engineering of Acme staff is out of scope.
- Test accounts are available on request; use them for authenticated testing.

## Rewards

| Severity | Reward |
|---|---|
| Critical | 5000 |
| High | 2500 |
| Medium | 800 |
| Low | 200 |

## Report Requirements

- A proof of concept is required for every submission.
- Include the CVSS vector and a clear impact statement.
- Reproduce the issue on the latest version before submitting.

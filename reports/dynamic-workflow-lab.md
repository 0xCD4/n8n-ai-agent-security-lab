# CSINT Dynamic Workflow Lab receipt

Measured in an isolated staging run. This is not a production safety certificate.

Verified: 2026-08-04T16:56:26.729Z
Runtime: docker.n8n.io/n8nio/n8n:2.21.5
Executed workflow: 0256a2bbf7eaa5601acedae7505cce55f4285de6a351ed87b2134365b7b0bfe9
Security contract: 0a0d0bad2fc897de30279d341a937147ff389a19d32bb9793b74142c8b52f9d0
Decision: PASS
Static audit: 93/100 (A)
Runtime scenarios: 8/8 passed
Assertions: 56/56 passed
External actions executed: 0

## Scenario receipt

| Scenario | HTTP | Observation | Checks | Result |
| --- | ---: | ---: | ---: | --- |
| Reject a request without authentication | 401 | - | 6/6 | PASS |
| Reject an invalid staging signature | 401 | - | 4/4 | PASS |
| Reject missing and unexpected input fields | 400 | - | 5/5 | PASS |
| Keep an instruction override behind approval | 202 | 200 | 11/11 | PASS |
| Block an invalid approval token | 403 | 200 | 8/8 | PASS |
| Accept a valid request without executing an action | 202 | - | 11/11 | PASS |
| Treat a repeated request as the same operation | 200 | - | 7/7 | PASS |
| Reject an unsupported webhook method | 405 | - | 4/4 | PASS |

## Boundaries

- No production credentials are mounted.
- No email, chat, database or HTTP action node is allowed to contact a live service.
- The target is bound to loopback and removed after the run.
- Approval, replay, authentication and prompt-injection containment are checked with synthetic requests.

## Limits

- The gate only tests the supplied workflow export and explicitly allowlisted staging endpoints.
- Passing results do not prove model safety, credential scope, production authorization or absence of vulnerabilities.
- Use redacted fixtures and isolated test credentials. Never point the gate at production.
- No language model is invoked. The prompt-injection scenario measures the deterministic controls around an agent workflow, not the model's resistance to manipulation.
- This receipt covers the bundled action-free fixture. It is not permission to execute an arbitrary uploaded workflow.

# Manual Review Checklist

Use this after the static scan.

## Entry points

- Confirm every public trigger has the intended authentication.
- Check upstream proxy, gateway and rate-limit behavior.
- Verify request size, file type and schema limits.
- Test malformed input and direct prompt injection.

## Model boundary

- Keep system instructions separate from external data.
- Restrict tools to the minimum required permissions.
- Validate structured output before another node consumes it.
- Set a model-call budget and bounded retry policy.

## External actions

- Require approval for messages, writes, deletions, purchases and account changes.
- Verify the approval cannot be bypassed through another branch.
- Use an allowlist for outbound destinations.
- Block private, loopback, link-local and metadata IP ranges.
- Check idempotency before enabling retries.

## Evidence

- Record request ID, approver, action, destination, result and time.
- Do not log secrets or unnecessary personal data.
- Test the error route and partial-failure behavior.
- Confirm alerts reach a person who can act.

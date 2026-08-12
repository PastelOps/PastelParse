<p align="center">
  <img src="assets/pastelparse-logo.png" alt="PastelParse logo" width="220">
</p>

# PastelParse

**PastelParse** is a security testing tool for identifying inconsistencies in how web application components interpret JSON request bodies.

Modern applications often pass the same request through multiple layers — such as API gateways, WAFs, validation middleware, frameworks, and backend services. If those components interpret JSON differently, an attacker may be able to bypass validation or security controls.

PastelParse helps penetration testers identify these parser discrepancies by automatically generating variations of a legitimate JSON request, sending them to the target, and comparing the resulting responses.

> **PastelParse is intended only for systems you own or have explicit authorization to test.**

---

## Why PastelParse?

Consider the following JSON:

```json
{
  "username": "alex",
  "role": "user"
}
```

Different JSON parsers or application components may interpret unusual variations differently.

For example:

```json
{
  "role": "user",
  "role": "admin"
}
```

One component may use the first value while another uses the last.

Similarly:

```json
{
  "Role": "admin"
}
```

or:

```json
{
  "role": ["user", "admin"]
}
```

may be accepted, rejected, normalized, or interpreted differently depending on the technology processing the request.

PastelParse systematically generates these variations and highlights differences in application behaviour.

---

## Features

PastelParse currently supports testing for:

### Duplicate Keys

Tests how different components handle multiple occurrences of the same JSON key.

```json
{
  "role": "user",
  "role": "admin"
}
```

Both value orders are tested:

```json
{
  "role": "user",
  "role": "admin"
}
```

and:

```json
{
  "role": "admin",
  "role": "user"
}
```

This can help identify **first-key-wins vs last-key-wins parser behaviour**.

Duplicate-key mutations can target nested object fields, including objects
contained inside arrays.

### Key Order Changes

Reverses JSON object key ordering to detect components that unexpectedly depend on field order.

### Capitalisation Variations

Tests alternative capitalisation of field names.

For example:

```text
role
Role
ROLE
rOLE
```

This may identify inconsistencies between case-sensitive and case-insensitive components.

### Type Changes

Changes the JSON type supplied for a selected value.

For example:

```json
{
  "role": "admin"
}
```

may be tested as:

```json
{
  "role": true
}
```

```json
{
  "role": 1
}
```

```json
{
  "role": null
}
```

```json
{
  "role": {
    "value": "admin"
  }
}
```

### Scalar vs Vector

Tests whether an application treats scalar and array representations differently.

For example:

```json
{
  "role": "admin"
}
```

may become:

```json
{
  "role": ["admin"]
}
```

or:

```json
{
  "role": ["user", "admin"]
}
```

Arrays may also be converted back into scalar values.

### Response Comparison

PastelParse compares mutated responses against the original request using:

- HTTP status codes
- HTTP status classes
- response body length
- response body hashes
- normalized JSON response content
- content similarity
- unified response diffs

JSON responses are normalized before comparison so insignificant JSON key ordering differences do not automatically appear as findings.

### Verification Requests

For state-changing operations, the response to the mutation may not be enough to determine whether the test succeeded.

PastelParse can therefore optionally send a separate verification request before and after each mutation.

For example:

```text
PATCH /api/account
        |
        v
PastelParse mutation
        |
        v
GET /api/account
        |
        v
Did the value actually change?
```

This is particularly useful when testing authorization-sensitive values such as:

```text
role
tenantId
accountId
permissions
requestedScopes
isAdmin
```

### Reset Requests

An optional reset request can be supplied to restore application state before each test.

This helps prevent one mutation from affecting the results of subsequent mutations.

### Test Reporting

PastelParse records:

- the original request
- exact generated payloads
- HTTP responses
- response hashes
- response differences
- verification results
- mutation type
- probe values
- confidence classifications

Reports are stored as JSON for later review and reproduction.

---

## Confidence Classification

PastelParse assigns a heuristic confidence rating to each result.

Possible classifications include:

| Confidence | Meaning |
|---|---|
| `CONFIRMED` | Verification indicates that a supplied test value took effect |
| `HIGH` | Strong behavioural difference was detected |
| `MEDIUM` | Meaningful response difference was detected |
| `LOW` | Minor response difference was detected |
| `NONE` | No meaningful difference was observed |
| `ERROR` | The request could not be completed |
| `CONTROL` | Result belongs to the formatting control request |

Confidence classifications are intended to assist with triage.

They should **not** be considered proof of a vulnerability without manual verification.

---

## Requirements

PastelParse requires:

```text
Python 3.10+
```

The current version uses only Python's standard library.

No additional Python packages are required.

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd PastelParse
```

Check your Python version:

```bash
python3 --version
```

Then view the available options:

```bash
python3 pastelparse.py --help
```

---

## Local Parser-Discrepancy Lab

PastelParse includes an intentionally vulnerable local lab for exercising its
current mutation and verification features. The lab uses only Python's
standard library and is hard-coded to bind to `127.0.0.1`, so it is not
reachable from another device.

> The lab is deliberately insecure. Use it only as a local training target.

### Start the Lab

From the project directory, open a terminal and run:

```cmd
python lab_server.py
```

The server should report:

```text
Listening: http://127.0.0.1:5000
Safety:    loopback only; intentionally vulnerable
```

Check that it is ready:

```cmd
curl http://127.0.0.1:5000/api/health
```

### Run a Confirmed Duplicate-Key Test

Keep the lab running and open a second terminal in the project directory:

```cmd
python pastelparse.py lab/requests/duplicate_role.http --field $.role --test-value admin --verification-request lab/requests/verification.http --reset-request lab/requests/reset.http --delay 0 --confirm-authorized --report pastelparse_report_lab_duplicate.json
```

The vulnerable endpoint models a first-key-wins gateway in front of a
last-key-wins backend. The `original then admin` duplicate-key mutation should
set the lab state to `admin`, allowing the verification response to produce a
`CONFIRMED` result.

To use the larger example request instead:

```cmd
python pastelparse.py test_request.http --field $.role --test-value admin --verification-request lab/requests/verification.http --reset-request lab/requests/reset.http --delay 0 --confirm-authorized
```

### Run Every Scenario

With the lab still running on port 5000:

```cmd
python lab/run_scenarios.py
```

This exercises all supplied requests and writes ignored JSON reports under
`lab/reports/`.

| Request file | Deliberate behavior |
|---|---|
| `duplicate_role.http` | First-key-wins gateway, last-key-wins backend |
| `case_role.http` | Exact-case gateway, case-insensitive backend |
| `type_role.http` | String-only gateway check, unsafe backend coercion |
| `vector_role.http` | Scalar gateway check, array-consuming backend |
| `order_role.http` | Gateway stops inspecting when it reaches `metadata` |
| `safe_role.http` | Defensive control that rejects ambiguous payloads |

The verification state and recent decisions are also available from
`/api/state` and `/api/events`. These routes require the demo authorization
header and session cookie included in the supplied request files.

Stop the lab with `Ctrl+C` in its terminal.

---

## Input Format

PastelParse accepts a raw HTTP/1.x request stored in a file.

For example:

```http
POST /api/duplicate-role?source=account-settings HTTP/1.1
Host: 127.0.0.1:5000
User-Agent: Mozilla/5.0 PastelParse/0.1
Accept: application/json
Content-Type: application/json
Authorization: Bearer example-token
Cookie: session=example-session
Connection: close

{
  "userId": "usr_10482",
  "tenantId": "alpha",
  "email": "alex@example.test",
  "role": "user",
  "profile": {
    "jobTitle": "Application Security Engineer",
    "location": "Singapore"
  }
}
```

Save the request as:

```text
request.txt
```

---

## Quick Start

### Dry Run

The safest way to start is with dry-run mode:

```bash
python3 pastelparse.py request.txt --dry-run
```

PastelParse will:

1. Parse the request.
2. Detect the JSON body.
3. Enumerate available JSON fields.
4. Ask which field should be tested.
5. Generate mutations.
6. Display the generated payloads.
7. Write them to the report.

No network requests are made.

---

## Interactive Testing

Run:

```bash
python3 pastelparse.py request.txt
```

PastelParse will display detected fields:

```text
Detected JSON fields:
--------------------------------------------------------------------------------
  1. $.userId                                  type=string
  2. $.tenantId                                type=string
  3. $.email                                   type=string
  4. $.role                                    type=string
  5. $.profile                                 type=object
  6. $.profile.jobTitle                        type=string
  7. $.profile.location                        type=string
--------------------------------------------------------------------------------
```

Select the field you want to investigate:

```text
Select a field number: 4
```

You can then provide known application-specific values:

```text
Test values: ["admin", "administrator"]
```

Before network traffic is sent, PastelParse requires authorization confirmation.

---

## Non-Interactive Usage

A field can be supplied directly:

```bash
python3 pastelparse.py request.txt \
  --field '$.role' \
  --test-value '"admin"' \
  --confirm-authorized
```

Multiple values can be tested:

```bash
python3 pastelparse.py request.txt \
  --field '$.role' \
  --test-value '"admin"' \
  --test-value '"administrator"' \
  --test-value '"superuser"' \
  --confirm-authorized
```

---

## Test Value Types

Values supplied through `--test-value` are interpreted as JSON when possible.

Examples:

```bash
--test-value '"admin"'
```

JSON string:

```json
"admin"
```

```bash
--test-value 'true'
```

JSON boolean:

```json
true
```

```bash
--test-value '1'
```

JSON number:

```json
1
```

```bash
--test-value 'null'
```

JSON null:

```json
null
```

```bash
--test-value '["user","admin"]'
```

JSON array:

```json
[
  "user",
  "admin"
]
```

---

## Verification Requests

A verification request can be supplied when testing state-changing functionality.

Example:

```bash
python3 pastelparse.py update-account.txt \
  --field '$.role' \
  --test-value '"admin"' \
  --verification-request get-account.txt \
  --confirm-authorized
```

The sequence becomes:

```text
Verification request
        |
        v
Record state before mutation
        |
        v
Send mutated request
        |
        v
Verification request
        |
        v
Compare state after mutation
```

If a supplied probe value appears in the post-mutation verification response but was absent beforehand, PastelParse may classify the result as:

```text
CONFIRMED
```

---

## Reset Requests

For endpoints that modify application state, a reset request can be supplied:

```bash
python3 pastelparse.py update-account.txt \
  --field '$.role' \
  --test-value '"admin"' \
  --verification-request get-account.txt \
  --reset-request reset-account.txt \
  --confirm-authorized
```

The test sequence becomes:

```text
Reset application state
        |
        v
Verify initial state
        |
        v
Send mutation
        |
        v
Verify resulting state
```

This process repeats for each generated mutation.

---

## Remote Targets

For safety, PastelParse only allows loopback targets by default.

These include:

```text
127.0.0.1
::1
localhost
*.localhost
```

Testing a remote system requires explicitly enabling remote targets:

```bash
python3 pastelparse.py request.txt \
  --allow-remote \
  --confirm-authorized
```

Only use this option against systems for which you have explicit authorization.

---

## HTTPS

HTTPS is automatically inferred when possible.

The scheme can also be explicitly selected:

```bash
python3 pastelparse.py request.txt \
  --scheme https
```

For authorized development environments using self-signed certificates:

```bash
python3 pastelparse.py request.txt \
  --scheme https \
  --insecure
```

`--insecure` disables TLS certificate verification and should not normally be required.

---

## Reports

PastelParse generates reports similar to:

```text
pastelparse_report_20260812_105400.json
```

You may specify your own location:

```bash
python3 pastelparse.py request.txt \
  --report results/pastelparse-role-test.json
```

The report contains the exact normalized requests used during testing.

This can include:

- authorization headers
- bearer tokens
- cookies
- CSRF tokens
- session identifiers
- request bodies
- application responses
- potentially sensitive account data

**Treat PastelParse reports as sensitive security testing evidence.**

Where supported, PastelParse creates report files with owner-only filesystem permissions.

---

## Useful Options

View all available options with:

```bash
python3 pastelparse.py --help
```

Common options include:

```text
--field
--test-value
--verification-request
--reset-request
--scheme
--timeout
--delay
--max-tests
--max-response-bytes
--diff-lines
--allow-remote
--confirm-authorized
--insecure
--dry-run
--report
```

For example:

```bash
python3 pastelparse.py request.txt \
  --field '$.tenantId' \
  --test-value '"beta"' \
  --verification-request current-account.txt \
  --delay 1 \
  --max-tests 20 \
  --report results/tenant-test.json \
  --confirm-authorized
```

---

## What Can PastelParse Find?

Parser inconsistencies can occur when different components in an application stack interpret the same JSON differently.

A typical request path may look like:

```text
Client
  |
  v
CDN
  |
  v
WAF
  |
  v
API Gateway
  |
  v
Schema Validator
  |
  v
Web Framework
  |
  v
Application
  |
  v
Downstream Service
```

If two layers disagree about the meaning of a request, security controls may be applied to one interpretation while the application processes another.

Potential impact can include:

- validation bypass
- authorization bypass
- broken access control
- privilege escalation
- tenant isolation failures
- unexpected parameter interpretation
- inconsistent schema validation
- request filtering bypasses

A response difference alone does **not** demonstrate that one of these vulnerabilities exists.

Manual investigation is still required.

---

## Current Limitations

The initial version of PastelParse focuses on JSON request-body semantics.

It currently:

- works with raw HTTP/1.x requests
- normalizes outgoing requests
- recalculates `Content-Length`
- sends fixed-length request bodies
- preserves duplicate JSON keys in generated payloads
- sends requests sequentially

It does **not currently attempt to test**:

- HTTP request smuggling
- conflicting `Content-Length` headers
- conflicting `Transfer-Encoding` behaviour
- malformed HTTP syntax
- HTTP/2 framing inconsistencies
- HTTP/3 behaviour
- chunked-transfer parser discrepancies
- raw byte-level whitespace parser attacks
- JSON encoding tricks
- Unicode normalization discrepancies

These areas may be considered separately in future versions.

---

## Roadmap (Planned)

The following items are not part of the current release. They are candidates
for future development:

Potential future functionality includes:

- batch field testing
- automated field prioritization
- custom mutation plugins
- configurable mutation profiles
- request/response filtering
- JSON Unicode edge cases
- numeric parsing edge cases
- duplicate-key combinations
- API schema imports
- Burp Suite request imports
- proxy support
- structured HTML reports
- CLI summary tables
- baseline stability checks
- response normalization rules
- configurable verification logic
- reproducible finding export
- CI/CD security testing mode

---

## Example Finding

A simplified result could look like:

```text
================================================================================
Test:        duplicate-original-then-test-1
Category:    duplicate-key

Payload:
--------------------------------------------------------------------------------
{
  "userId": "usr_10482",
  "role": "user",
  "role": "admin"
}
--------------------------------------------------------------------------------

Original response:
HTTP 403 | 68 bytes

Mutation response:
HTTP 200 | 241 bytes

Difference:
status 403 -> 200
similarity=0.183

Verification before:
role = user

Verification after:
role = admin

Confidence: CONFIRMED
  - Probe value 'admin' appeared in the post-mutation verification response.
```

This result would warrant manual investigation into whether different application components interpreted the duplicate `role` key differently.

---

## Security and Responsible Use

PastelParse is a penetration-testing utility.

It is intended for:

- security research in controlled environments
- internal application security testing
- penetration testing with explicit authorization
- bug bounty testing within the program's permitted scope
- security training environments
- intentionally vulnerable applications
- local development and test systems

Do not use PastelParse against systems where you do not have permission to perform security testing.

Some generated requests may modify application state. Use dedicated test accounts and environments whenever possible.

---

## Project Philosophy

The name **PastelParse** reflects the idea that a request may appear to be one colour at one layer of an application stack and a subtly different shade at another.

Those subtle differences are exactly what PastelParse is designed to uncover.

> **Same JSON. Different interpretation. Find the difference.**

---

## Contributing

Contributions, bug reports, testing ideas, and additional JSON parser edge cases are welcome.

When proposing a new mutation, consider documenting:

1. The parser inconsistency being tested.
2. An example input.
3. The expected variations.
4. Why two application components may interpret it differently.
5. How PastelParse should determine whether the behaviour is interesting.

---

## Disclaimer

PastelParse is provided for educational purposes and authorized security testing.

The user is responsible for ensuring they have permission to test the target system and for complying with all applicable laws, agreements, policies, and rules of engagement.

The authors and contributors are not responsible for misuse of the software.

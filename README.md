# Enterprise Identity & Access Management Service (EIAMS)

A production-ready, cloud-native, multi-tenant Identity and Access Management (IAM) platform.

## Architecture

EIAMS follows a hexagonal (ports & adapters) architecture with strict dependency rules:

### Module Boundaries

The system is organized into six IAM domain modules:

1. **Identity** - User and organization identity management
2. **Authentication** - Login, session, and token management  
3. **Authorization** - RBAC, permissions, and policy evaluation
4. **Credentials** - Password, API key, and OAuth client management
5. **Audit** - Security event logging and compliance tracking
6. **Administration** - Tenant and system administration

### Dependency Rules

```
Infrastructure (adapters) → Application (services/ports) → Domain (contracts)
                                                        → Shared Kernel
```

- **Domain contracts** have no external dependencies (framework-isolated)
- **Application layer** depends only on domain contracts and shared kernel
- **Infrastructure layer** may depend on frameworks and external libraries

### Request Context

All operations receive validated immutable context containing:
- Actor identity (authenticated user/service)
- Tenant scope (required for data isolation)
- Correlation ID (request tracing)
- Request metadata (timestamp, source)

Context is constructed at the transport edge and propagated explicitly through all layers.

## Password Login

`POST /api/v1/auth/login` authenticates a tenant user with an identifier and
password. It verifies a protected (hashed) stored credential, enforces the
configured account-eligibility policy, and records the outcome through the
audit contract. It issues no token and creates no session.

Request:

```json
{ "identifier": "user@example.com", "password": "..." }
```

The tenant is supplied out of band as the `X-Tenant-ID` header; requests
without tenant context are refused before any credential work happens.

Responses:

| Condition | Status | Code |
| --- | --- | --- |
| Authenticated | 200 | — |
| Body is not a JSON object | 400 | `INVALID_REQUEST_FORMAT` |
| Field missing or out of bounds | 422 | `VALIDATION_FAILED` |
| Tenant context missing or malformed | 403 | `TENANT_ACCESS_DENIED` |
| Unknown identifier, wrong password, unusable credential, or ineligible account state | 401 | `CREDENTIALS_INVALID` |

All four authentication failure conditions produce a byte-identical 401
payload, so the endpoint cannot be used to discover which identifiers exist.
Passwords, stored hashes, and submitted identifiers never appear in
responses, logs, or audit events.

## Security Configuration

Cryptographic and policy values are read through the configuration
abstraction (`eiams.shared.config`) and are never hard-coded. Keys are
case-insensitive and treat `.`, `_`, and `__` as equivalent separators, so
`security.password.algorithm` can also be supplied as the environment
variable `EIAMS_SECURITY__PASSWORD__ALGORITHM`.

| Key | Default | Purpose |
| --- | --- | --- |
| `security.password.algorithm` | `argon2id` | Hashing algorithm (`argon2id` or `pbkdf2_sha256`) |
| `security.password.argon2.time_cost` | `3` | Argon2 iterations |
| `security.password.argon2.memory_cost_kib` | `65536` | Argon2 memory cost (KiB) |
| `security.password.argon2.parallelism` | `4` | Argon2 lanes |
| `security.password.pbkdf2.iterations` | `600000` | PBKDF2-HMAC-SHA256 iterations |
| `security.password.salt_length` | `16` | Salt length in bytes |
| `security.password.hash_length` | `32` | Digest length in bytes |
| `security.password.min_length` | `12` | Minimum length for new passwords |
| `security.password.max_length` | `256` | Accepted password input bound |
| `security.authentication.eligible_user_statuses` | `active` | Account states permitted to authenticate |
| `security.authentication.max_identifier_length` | `320` | Accepted identifier input bound |

Values outside safe ranges (for example an Argon2 memory cost below 8 MiB or
a PBKDF2 iteration count below 100,000) are rejected at startup rather than
silently accepted. Hashing itself is delegated to approved libraries:
Argon2id through `argon2-cffi`, PBKDF2 through the standard library.

## Development

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=eiams --cov-report=term-missing

# Run architecture tests only
pytest tests/architecture/
```

## Project Structure

```
src/eiams/
├── shared/
│   ├── kernel/         # Shared value objects, base types, secret wrapper
│   ├── context/        # Request context contracts and validation
│   ├── config/         # Configuration abstraction for injected policy
│   ├── logging/        # Structured logging and secret redaction
│   └── errors/         # Domain and API error definitions
├── domain/
│   ├── identity/       # Identity domain contracts
│   ├── authentication/ # Authentication domain contracts
│   ├── authorization/  # Authorization domain contracts
│   ├── credentials/    # Credentials domain contracts
│   ├── audit/          # Audit domain contracts
│   └── administration/ # Administration domain contracts
├── application/
│   ├── services/       # Application service implementations
│   └── ports/          # Input/output port definitions
├── infrastructure/
│   ├── adapters/       # Framework adapters (HTTP API, audit, validation)
│   ├── config/         # Environment-backed configuration sources
│   ├── security/       # Approved cryptographic library adapters
│   └── persistence/    # Repository implementations
└── composition/        # Dependency wiring for modules
```

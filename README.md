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

### Data Access

Repositories are declared in one of three scopes, and the scope decides what a
call is allowed to reach:

| Scope | Contract | Used by | Behaviour |
|---|---|---|---|
| Platform | `PlatformScopedRepository` | Tenant registry | Spans tenants by design; still requires an authenticated caller |
| Tenant | `TenantScopedRepository` | All IAM entity groups | Every read and write is confined to the tenant in the request context |
| Append-only | `AppendOnlyRepository` | Audit trail | Tenant-scoped reads plus a single append primitive; no update or delete exists |

Tenant-scoped access is fail-closed:

- A `TenantPredicate` is resolved from the request context and bound to the
  statement **before** any caller-supplied criterion. Missing tenant context
  raises `TenantRequiredError` rather than producing an unfiltered query.
- Writes stamp the tenant column from the validated context rather than from
  the incoming entity, so a forged tenant value cannot place a row in another
  tenant. An entity claiming a different owner raises `TenantMismatchError`.
- A row owned by another tenant resolves as absent, so a caller cannot tell
  "does not exist" from "exists in another tenant".
- Roles and permissions additionally have a platform-shared partition: rows
  with no tenant owner form the system catalogue that every tenant can read
  and none can write.

Repositories return immutable domain entities, never ORM rows, and driver
exceptions are translated into framework-isolated errors that carry no SQL
text or row values.

### Transactions

Multi-entity changes run inside an explicit boundary. A unit of work hands out
repositories that share one session; the runner commits when the block ends
normally and rolls back if anything raises.

```python
with runner.unit_of_work(context) as uow:
    user = uow.users.add(context, user)
    uow.memberships.add(context, membership)
    uow.audit_events.append(context, event)
# committed here; any failure above leaves no partial state
```

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

# Run the repository and transaction tests, which execute the migrations
pytest tests/integration/repositories/
```

## Project Structure

```
src/eiams/
├── shared/
│   ├── kernel/         # Shared value objects and base types
│   ├── context/        # Request context, tenant scope, and guards
│   └── errors/         # Domain, context, and persistence errors
├── domain/
│   ├── identity/       # Identity domain contracts
│   ├── authentication/ # Authentication domain contracts
│   ├── authorization/  # Authorization domain contracts
│   ├── credentials/    # Credentials domain contracts
│   ├── audit/          # Audit domain contracts
│   └── administration/ # Administration domain contracts
├── application/
│   ├── services/       # Application service implementations
│   └── ports/          # Input/output and persistence port definitions
└── infrastructure/
    ├── adapters/       # Framework adapters (HTTP, etc.)
    └── persistence/    # Schema, migrations, repositories, transactions
        ├── models/         # SQLAlchemy ORM models
        ├── migrations/     # Alembic revisions
        ├── mappers/        # Row to domain entity mapping
        ├── repositories/   # Scope-enforcing repository implementations
        └── transaction.py  # Unit of work and transaction runner
```

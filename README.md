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
│   ├── kernel/         # Shared value objects and base types
│   ├── context/        # Request context contracts and validation
│   └── errors/         # Domain error definitions
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
└── infrastructure/
    ├── adapters/       # Framework adapters (HTTP, etc.)
    └── persistence/    # Repository implementations
```

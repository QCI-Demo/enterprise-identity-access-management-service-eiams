"""Builders for the domain entities the repository tests persist.

Every builder takes the owning tenant explicitly so a test can state which
tenant an entity claims to belong to, including the cases where that claim
does not match the request context.
"""

from datetime import timedelta
from uuid import uuid4

from eiams.domain.administration.contracts import Tenant, TenantStatus
from eiams.domain.audit.contracts import (
    AuditActorType,
    AuditEvent,
    AuditEventId,
    AuditEventType,
    AuditSeverity,
)
from eiams.domain.authentication.contracts import (
    RefreshToken,
    RefreshTokenId,
    Session,
    SessionId,
    SessionStatus,
)
from eiams.domain.authorization.contracts import (
    Permission,
    PermissionId,
    Role,
    RoleAssignment,
    RoleAssignmentId,
    RoleId,
)
from eiams.domain.credentials.contracts import (
    ApiKey,
    ApiKeyId,
    ApiKeyStatus,
    CredentialId,
    CredentialType,
    OAuthClient,
    OAuthClientId,
    OAuthClientType,
    UserCredential,
)
from eiams.domain.identity.contracts import (
    Membership,
    MembershipId,
    MembershipStatus,
    Organization,
    OrganizationId,
    User,
    UserId,
    UserStatus,
)
from eiams.shared.kernel import TenantId, Timestamp


def new_id() -> str:
    """Generate an identifier in the form the schema stores."""
    return str(uuid4())


def build_tenant(
    tenant_id: str,
    name: str,
    *,
    status: TenantStatus = TenantStatus.ACTIVE,
    slug: str | None = None,
) -> Tenant:
    now = Timestamp.now()
    return Tenant(
        tenant_id=TenantId(tenant_id),
        name=name,
        display_name=name,
        status=status,
        settings={},
        created_at=now,
        updated_at=now,
        slug=slug,
    )


def build_user(
    tenant_id: str,
    *,
    email: str = "person@example.com",
    display_name: str = "Person",
    user_id: str | None = None,
    status: UserStatus = UserStatus.ACTIVE,
    username: str | None = None,
) -> User:
    now = Timestamp.now()
    return User(
        user_id=UserId(user_id or new_id()),
        tenant_id=TenantId(tenant_id),
        email=email,
        display_name=display_name,
        status=status,
        created_at=now,
        updated_at=now,
        username=username,
    )


def build_organization(
    tenant_id: str,
    *,
    name: str = "Engineering",
    organization_id: str | None = None,
    parent_id: str | None = None,
    slug: str | None = None,
) -> Organization:
    now = Timestamp.now()
    return Organization(
        organization_id=OrganizationId(organization_id or new_id()),
        tenant_id=TenantId(tenant_id),
        name=name,
        description=None,
        parent_id=OrganizationId(parent_id) if parent_id else None,
        created_at=now,
        updated_at=now,
        slug=slug,
    )


def build_membership(
    tenant_id: str,
    user_id: str,
    organization_id: str,
    *,
    role: str = "member",
    membership_id: str | None = None,
) -> Membership:
    now = Timestamp.now()
    return Membership(
        membership_id=MembershipId(membership_id or new_id()),
        tenant_id=TenantId(tenant_id),
        user_id=UserId(user_id),
        organization_id=OrganizationId(organization_id),
        role=role,
        status=MembershipStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )


def build_permission(
    tenant_id: str | None,
    *,
    name: str = "Read users",
    resource_type: str = "user",
    action: str = "read",
    permission_id: str | None = None,
    is_system_permission: bool = False,
) -> Permission:
    return Permission(
        permission_id=PermissionId(permission_id or new_id()),
        tenant_id=TenantId(tenant_id) if tenant_id else None,
        name=name,
        description=None,
        resource_type=resource_type,
        action=action,
        created_at=Timestamp.now(),
        is_system_permission=is_system_permission,
    )


def build_role(
    tenant_id: str | None,
    *,
    name: str = "Administrator",
    role_id: str | None = None,
    permissions: tuple[PermissionId, ...] = (),
    is_system_role: bool = False,
) -> Role:
    now = Timestamp.now()
    return Role(
        role_id=RoleId(role_id or new_id()),
        tenant_id=TenantId(tenant_id) if tenant_id else None,
        name=name,
        description=None,
        permissions=permissions,
        is_system_role=is_system_role,
        created_at=now,
        updated_at=now,
    )


def build_role_assignment(
    tenant_id: str,
    user_id: str,
    role_id: str,
    *,
    assignment_id: str | None = None,
    scope: str | None = None,
    scope_type: str | None = None,
    expires_in_hours: int | None = None,
) -> RoleAssignment:
    now = Timestamp.now()
    expires_at = (
        Timestamp(now.value + timedelta(hours=expires_in_hours))
        if expires_in_hours is not None
        else None
    )
    return RoleAssignment(
        assignment_id=RoleAssignmentId(assignment_id or new_id()),
        tenant_id=TenantId(tenant_id),
        user_id=UserId(user_id),
        role_id=RoleId(role_id),
        scope=scope,
        created_at=now,
        expires_at=expires_at,
        scope_type=scope_type,
    )


def build_credential(
    tenant_id: str,
    user_id: str,
    *,
    credential_id: str | None = None,
    credential_type: CredentialType = CredentialType.PASSWORD,
    credential_hash: str = "argon2id$placeholder-verifier",
) -> UserCredential:
    now = Timestamp.now()
    return UserCredential(
        credential_id=CredentialId(credential_id or new_id()),
        tenant_id=TenantId(tenant_id),
        user_id=UserId(user_id),
        credential_type=credential_type,
        credential_hash=credential_hash,
        hash_algorithm="argon2id",
        is_active=True,
        requires_reset=False,
        failed_attempts=0,
        created_at=now,
        updated_at=now,
    )


def build_session(
    tenant_id: str,
    user_id: str,
    *,
    session_id: str | None = None,
    status: SessionStatus = SessionStatus.ACTIVE,
    expires_in_hours: int = 1,
) -> Session:
    now = Timestamp.now()
    return Session(
        session_id=SessionId(session_id or new_id()),
        tenant_id=TenantId(tenant_id),
        user_id=UserId(user_id),
        status=status,
        created_at=now,
        expires_at=Timestamp(now.value + timedelta(hours=expires_in_hours)),
        last_activity_at=now,
        ip_address="203.0.113.7",
        user_agent="pytest",
    )


def build_refresh_token(
    tenant_id: str,
    session_id: str,
    user_id: str,
    *,
    refresh_token_id: str | None = None,
    token_hash: str | None = None,
    token_family: str | None = None,
) -> RefreshToken:
    now = Timestamp.now()
    return RefreshToken(
        refresh_token_id=RefreshTokenId(refresh_token_id or new_id()),
        tenant_id=TenantId(tenant_id),
        session_id=SessionId(session_id),
        user_id=UserId(user_id),
        token_hash=token_hash or f"sha256${new_id()}",
        token_family=token_family or new_id(),
        is_revoked=False,
        created_at=now,
        expires_at=Timestamp(now.value + timedelta(days=30)),
    )


def build_api_key(
    tenant_id: str,
    *,
    name: str = "Deployment key",
    key_prefix: str | None = None,
    api_key_id: str | None = None,
    user_id: str | None = None,
    scopes: tuple[str, ...] = ("user:read", "user:write"),
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE,
) -> ApiKey:
    return ApiKey(
        api_key_id=ApiKeyId(api_key_id or new_id()),
        tenant_id=TenantId(tenant_id),
        user_id=UserId(user_id) if user_id else None,
        name=name,
        key_prefix=key_prefix or f"eiams_{new_id()[:8]}",
        key_hash=f"sha256${new_id()}",
        scopes=scopes,
        status=status,
        created_at=Timestamp.now(),
        expires_at=None,
        last_used_at=None,
    )


def build_oauth_client(
    tenant_id: str,
    *,
    name: str = "Portal",
    client_id: str | None = None,
    client_type: OAuthClientType = OAuthClientType.CONFIDENTIAL,
    secret_hash: str | None = "argon2id$client-verifier",
    redirect_uris: tuple[str, ...] = ("https://portal.example.com/callback",),
    scopes: tuple[str, ...] = ("openid", "profile"),
) -> OAuthClient:
    now = Timestamp.now()
    return OAuthClient(
        client_id=OAuthClientId(client_id or new_id()),
        tenant_id=TenantId(tenant_id),
        name=name,
        description=None,
        client_type=client_type,
        client_secret_hash=secret_hash,
        redirect_uris=redirect_uris,
        scopes=scopes,
        is_active=True,
        created_at=now,
        updated_at=now,
    )


def build_audit_event(
    tenant_id: str | None,
    *,
    actor_id: str | None = None,
    event_id: str | None = None,
    event_type: AuditEventType = AuditEventType.USER_CREATED,
    action: str = "user.create",
    outcome: str = "success",
    correlation_id: str = "correlation-1",
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
) -> AuditEvent:
    return AuditEvent(
        audit_event_id=AuditEventId(event_id or new_id()),
        event_type=event_type,
        severity=AuditSeverity.INFO,
        action=action,
        outcome=outcome,
        details=details or {},
        correlation_id_value=correlation_id,
        timestamp=Timestamp.now(),
        tenant_id=TenantId(tenant_id) if tenant_id else None,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_type=AuditActorType.USER,
    )

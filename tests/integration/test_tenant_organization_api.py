"""Endpoint-level tests for tenant and organization command REST contracts."""

from __future__ import annotations

import pytest

from eiams.application.administration import TenantLifecycleService
from eiams.application.dto import CreateTenantCommand, UpdateTenantCommand
from eiams.application.identity import OrganizationLifecycleService
from eiams.infrastructure.adapters.http_api import API_VERSION, ApiRouter
from eiams.infrastructure.adapters.organization_api import (
    register_organization_endpoints,
)
from eiams.infrastructure.adapters.tenant_api import register_tenant_endpoints
from eiams.shared.kernel import ActorId, TenantId
from tests.support.in_memory_lifecycle import InMemoryTransactionRunner


DISALLOWED_FIELDS = {
    "settings",
    "password",
    "secret",
    "hash",
    "secret_hash",
    "row",
    "session",
    "permissions",
}


@pytest.fixture
def stack():
    runner = InMemoryTransactionRunner()
    tenant_service = TenantLifecycleService(runner)
    org_service = OrganizationLifecycleService(runner)
    router = ApiRouter()
    register_tenant_endpoints(router, tenant_service)
    register_organization_endpoints(router, org_service)
    actor_id = str(ActorId.generate())
    return {
        "router": router,
        "tenant_service": tenant_service,
        "org_service": org_service,
        "runner": runner,
        "actor_id": actor_id,
    }


def _platform_headers(stack, **extra):
    headers = {
        "X-Actor-ID": stack["actor_id"],
        "X-Actor-Type": "user",
        "X-Roles": "platform_admin",
        "X-Correlation-ID": "corr-tenant-api",
    }
    headers.update(extra)
    return headers


def _tenant_headers(stack, tenant_id: str, **extra):
    headers = {
        "X-Actor-ID": stack["actor_id"],
        "X-Actor-Type": "user",
        "X-Tenant-ID": tenant_id,
        "X-Roles": "tenant_admin",
        "X-Correlation-ID": "corr-org-api",
    }
    headers.update(extra)
    return headers


def _create_active_tenant(stack) -> str:
    context_headers = _platform_headers(stack)
    created = stack["router"].dispatch(
        {
            "method": "POST",
            "path": "/api/v1/tenants",
            "headers": context_headers,
            "body": {
                "name": "acme.co",
                "display_name": "Acme",
                "slug": "acme",
            },
        }
    )
    assert created.status_code == 201
    tenant_id = created.body["data"]["tenant_id"]
    updated = stack["router"].dispatch(
        {
            "method": "PATCH",
            "path": f"/api/v1/tenants/{tenant_id}",
            "headers": context_headers,
            "body": {"status": "active"},
        }
    )
    assert updated.status_code == 200
    return tenant_id


class TestTenantCommandApi:
    def test_create_get_update_deactivate_success(self, stack) -> None:
        headers = _platform_headers(stack)
        created = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/tenants",
                "headers": headers,
                "body": {"name": "acme", "display_name": "Acme", "slug": "acme"},
            }
        )
        assert created.status_code == 201
        assert created.body["api_version"] == API_VERSION
        data = created.body["data"]
        assert data["status"] == "pending_setup"
        assert DISALLOWED_FIELDS.isdisjoint(data)

        tenant_id = data["tenant_id"]
        fetched = stack["router"].dispatch(
            {
                "method": "GET",
                "path": f"/api/v1/tenants/{tenant_id}",
                "headers": headers,
            }
        )
        assert fetched.status_code == 200
        assert fetched.headers["X-Correlation-ID"] == "corr-tenant-api"

        activated = stack["router"].dispatch(
            {
                "method": "PATCH",
                "path": f"/api/v1/tenants/{tenant_id}",
                "headers": headers,
                "body": {"status": "active"},
            }
        )
        assert activated.status_code == 200
        assert activated.body["data"]["status"] == "active"

        deactivated = stack["router"].dispatch(
            {
                "method": "POST",
                "path": f"/api/v1/tenants/{tenant_id}/deactivate",
                "headers": headers,
            }
        )
        assert deactivated.status_code == 200
        assert deactivated.body["data"]["status"] == "inactive"

    def test_validation_error_shape(self, stack) -> None:
        response = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/tenants",
                "headers": _platform_headers(stack),
                "body": {"display_name": "Acme"},
            }
        )
        assert response.status_code == 422
        error = response.body["error"]
        assert error["code"] == "VALIDATION_FAILED"
        assert error["correlation_id"] == "corr-tenant-api"

    def test_duplicate_conflict(self, stack) -> None:
        headers = _platform_headers(stack)
        body = {"name": "acme", "display_name": "Acme", "slug": "acme"}
        first = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/tenants",
                "headers": headers,
                "body": body,
            }
        )
        assert first.status_code == 201
        second = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/tenants",
                "headers": headers,
                "body": body,
            }
        )
        assert second.status_code == 409
        assert second.body["error"]["code"] == "RESOURCE_ALREADY_EXISTS"

    def test_invalid_transition_conflict(self, stack) -> None:
        headers = _platform_headers(stack)
        created = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/tenants",
                "headers": headers,
                "body": {"name": "acme", "display_name": "Acme", "slug": "acme"},
            }
        )
        tenant_id = created.body["data"]["tenant_id"]
        response = stack["router"].dispatch(
            {
                "method": "PATCH",
                "path": f"/api/v1/tenants/{tenant_id}",
                "headers": headers,
                "body": {"status": "suspended"},
            }
        )
        assert response.status_code == 409
        assert response.body["error"]["code"] == "RESOURCE_CONFLICT"

    def test_not_found(self, stack) -> None:
        response = stack["router"].dispatch(
            {
                "method": "GET",
                "path": f"/api/v1/tenants/{TenantId.generate()}",
                "headers": _platform_headers(stack),
            }
        )
        assert response.status_code == 404
        assert response.body["error"]["code"] == "RESOURCE_NOT_FOUND"

    def test_permission_denied_without_platform_role(self, stack) -> None:
        response = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/tenants",
                "headers": _platform_headers(stack, **{"X-Roles": "viewer"}),
                "body": {"name": "acme", "display_name": "Acme"},
            }
        )
        assert response.status_code == 403
        assert response.body["error"]["code"] == "PERMISSION_DENIED"


class TestOrganizationCommandApi:
    def test_create_get_update_deactivate_success(self, stack) -> None:
        tenant_id = _create_active_tenant(stack)
        headers = _tenant_headers(stack, tenant_id)

        created = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/organizations",
                "headers": headers,
                "body": {"name": "Engineering", "slug": "engineering"},
            }
        )
        assert created.status_code == 201
        data = created.body["data"]
        assert data["tenant_id"] == tenant_id
        assert data["status"] == "active"
        assert DISALLOWED_FIELDS.isdisjoint(data)

        organization_id = data["organization_id"]
        fetched = stack["router"].dispatch(
            {
                "method": "GET",
                "path": f"/api/v1/organizations/{organization_id}",
                "headers": headers,
            }
        )
        assert fetched.status_code == 200
        assert fetched.body["api_version"] == API_VERSION

        updated = stack["router"].dispatch(
            {
                "method": "PATCH",
                "path": f"/api/v1/organizations/{organization_id}",
                "headers": headers,
                "body": {"description": "Eng org"},
            }
        )
        assert updated.status_code == 200
        assert updated.body["data"]["description"] == "Eng org"

        deactivated = stack["router"].dispatch(
            {
                "method": "POST",
                "path": f"/api/v1/organizations/{organization_id}/deactivate",
                "headers": headers,
            }
        )
        assert deactivated.status_code == 200
        assert deactivated.body["data"]["status"] == "inactive"

        missing = stack["router"].dispatch(
            {
                "method": "GET",
                "path": f"/api/v1/organizations/{organization_id}",
                "headers": headers,
            }
        )
        assert missing.status_code == 404

    def test_validation_error_shape(self, stack) -> None:
        tenant_id = _create_active_tenant(stack)
        response = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/organizations",
                "headers": _tenant_headers(stack, tenant_id),
                "body": {"slug": "engineering"},
            }
        )
        assert response.status_code == 422
        assert response.body["error"]["code"] == "VALIDATION_FAILED"
        assert response.body["error"]["correlation_id"] == "corr-org-api"

    def test_duplicate_conflict(self, stack) -> None:
        tenant_id = _create_active_tenant(stack)
        headers = _tenant_headers(stack, tenant_id)
        body = {"name": "Engineering"}
        assert (
            stack["router"].dispatch(
                {
                    "method": "POST",
                    "path": "/api/v1/organizations",
                    "headers": headers,
                    "body": body,
                }
            ).status_code
            == 201
        )
        conflict = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/organizations",
                "headers": headers,
                "body": body,
            }
        )
        assert conflict.status_code == 409
        assert conflict.body["error"]["code"] == "RESOURCE_ALREADY_EXISTS"

    def test_cross_tenant_not_found(self, stack) -> None:
        from eiams.shared.context import RequestContextFactory

        tenant_id = _create_active_tenant(stack)
        created = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/organizations",
                "headers": _tenant_headers(stack, tenant_id),
                "body": {"name": "Engineering"},
            }
        )
        organization_id = created.body["data"]["organization_id"]

        platform_context = RequestContextFactory.create(
            actor_id=stack["actor_id"],
            actor_type="user",
            roles=["platform_admin"],
        )
        other = stack["tenant_service"].create(
            platform_context,
            CreateTenantCommand.from_dict(
                {"name": "other", "display_name": "Other", "slug": "other"}
            ),
        )
        stack["tenant_service"].update(
            platform_context,
            other.tenant_id,
            UpdateTenantCommand.from_dict({"status": "active"}),
        )

        response = stack["router"].dispatch(
            {
                "method": "GET",
                "path": f"/api/v1/organizations/{organization_id}",
                "headers": _tenant_headers(stack, other.tenant_id),
            }
        )
        assert response.status_code == 404
        assert response.body["error"]["code"] == "RESOURCE_NOT_FOUND"

    def test_inactive_parent_conflict(self, stack) -> None:
        headers = _platform_headers(stack)
        created = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/tenants",
                "headers": headers,
                "body": {
                    "name": "pending-co",
                    "display_name": "Pending",
                    "slug": "pending-co",
                },
            }
        )
        tenant_id = created.body["data"]["tenant_id"]
        response = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/organizations",
                "headers": _tenant_headers(stack, tenant_id),
                "body": {"name": "Engineering"},
            }
        )
        assert response.status_code == 409
        assert response.body["error"]["code"] == "RESOURCE_CONFLICT"

    def test_missing_tenant_header_denied(self, stack) -> None:
        response = stack["router"].dispatch(
            {
                "method": "POST",
                "path": "/api/v1/organizations",
                "headers": {
                    "X-Actor-ID": stack["actor_id"],
                    "X-Roles": "tenant_admin",
                },
                "body": {"name": "Engineering"},
            }
        )
        assert response.status_code == 403
        assert response.body["error"]["code"] == "TENANT_ACCESS_DENIED"

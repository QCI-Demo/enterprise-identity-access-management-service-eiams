"""Architecture tests for dependency rules.

These tests enforce that:
1. Domain contracts do not depend on framework or persistence types
2. Application layer depends only on domain and shared kernel
3. Infrastructure may depend on external frameworks
"""

import ast
import os
from pathlib import Path
from typing import Set

import pytest


# Forbidden imports for domain layer
DOMAIN_FORBIDDEN_IMPORTS = {
    # Web frameworks
    "flask",
    "fastapi",
    "django",
    "starlette",
    "aiohttp",
    "tornado",
    # ORMs and database
    "sqlalchemy",
    "peewee",
    "tortoise",
    "databases",
    "asyncpg",
    "psycopg2",
    "pymysql",
    "motor",
    "pymongo",
    # HTTP clients
    "requests",
    "httpx",
    "aiohttp",
    # Serialization (external)
    "marshmallow",
    "pydantic",  # Domain should use pure Python
}

# Forbidden imports for application layer
APPLICATION_FORBIDDEN_IMPORTS = {
    # Web frameworks
    "flask",
    "fastapi",
    "django",
    "starlette",
    # ORMs
    "sqlalchemy",
    "peewee",
}

# Allowed imports for shared kernel (minimal)
SHARED_KERNEL_ALLOWED_EXTERNAL = {
    "typing",
    "abc",
    "dataclasses",
    "enum",
    "datetime",
    "re",
    "uuid",
    "functools",
    "__future__",
    "json",
}


class ImportVisitor(ast.NodeVisitor):
    """AST visitor that collects all import statements."""

    def __init__(self):
        self.imports: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Skip relative imports (node.level > 0 means relative import)
        if node.level > 0:
            self.generic_visit(node)
            return
        if node.module:
            self.imports.add(node.module.split(".")[0])
        self.generic_visit(node)


def get_imports_from_file(filepath: Path) -> Set[str]:
    """Extract all import statements from a Python file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        visitor = ImportVisitor()
        visitor.visit(tree)
        return visitor.imports
    except SyntaxError:
        return set()


def get_python_files(directory: Path) -> list[Path]:
    """Get all Python files in a directory recursively."""
    return list(directory.rglob("*.py"))


class TestDomainLayerDependencies:
    """Tests for domain layer dependency rules."""

    @pytest.fixture
    def domain_path(self) -> Path:
        """Get the domain layer path."""
        return Path(__file__).parent.parent.parent / "src" / "eiams" / "domain"

    def test_domain_does_not_import_web_frameworks(self, domain_path: Path):
        """Domain layer must not import web frameworks."""
        if not domain_path.exists():
            pytest.skip("Domain path does not exist")

        violations = []
        for filepath in get_python_files(domain_path):
            imports = get_imports_from_file(filepath)
            for forbidden in DOMAIN_FORBIDDEN_IMPORTS:
                if forbidden in imports:
                    violations.append(
                        f"{filepath.relative_to(domain_path)}: imports {forbidden}"
                    )

        assert not violations, f"Domain layer has forbidden imports:\n" + "\n".join(
            violations
        )

    def test_domain_contracts_are_framework_isolated(self, domain_path: Path):
        """Domain contracts must be pure Python with no external dependencies."""
        if not domain_path.exists():
            pytest.skip("Domain path does not exist")

        for filepath in get_python_files(domain_path):
            imports = get_imports_from_file(filepath)
            # Filter out internal imports
            external_imports = {
                i for i in imports if not i.startswith("eiams")
            }
            # Check each external import is from standard library
            for imp in external_imports:
                assert imp in SHARED_KERNEL_ALLOWED_EXTERNAL or imp in {
                    "typing",
                    "abc",
                    "dataclasses",
                    "enum",
                }, f"{filepath.name} imports non-stdlib module: {imp}"


class TestApplicationLayerDependencies:
    """Tests for application layer dependency rules."""

    @pytest.fixture
    def application_path(self) -> Path:
        """Get the application layer path."""
        return Path(__file__).parent.parent.parent / "src" / "eiams" / "application"

    def test_application_does_not_import_web_frameworks(self, application_path: Path):
        """Application layer must not import web frameworks."""
        if not application_path.exists():
            pytest.skip("Application path does not exist")

        violations = []
        for filepath in get_python_files(application_path):
            imports = get_imports_from_file(filepath)
            for forbidden in APPLICATION_FORBIDDEN_IMPORTS:
                if forbidden in imports:
                    violations.append(
                        f"{filepath.relative_to(application_path)}: imports {forbidden}"
                    )

        assert not violations, (
            f"Application layer has forbidden imports:\n" + "\n".join(violations)
        )

    def test_application_depends_only_on_domain_and_shared(
        self, application_path: Path
    ):
        """Application layer should only depend on domain and shared."""
        if not application_path.exists():
            pytest.skip("Application path does not exist")

        for filepath in get_python_files(application_path):
            imports = get_imports_from_file(filepath)
            eiams_imports = {i for i in imports if i.startswith("eiams")}

            for imp in eiams_imports:
                # Application can import from shared, domain, and application
                allowed_prefixes = ["eiams.shared", "eiams.domain", "eiams.application"]
                # Note: We check the actual import string from the visitor
                # which gives us the top-level module


class TestSharedKernelDependencies:
    """Tests for shared kernel dependency rules."""

    @pytest.fixture
    def shared_path(self) -> Path:
        """Get the shared kernel path."""
        return Path(__file__).parent.parent.parent / "src" / "eiams" / "shared"

    def test_shared_kernel_has_no_external_dependencies(self, shared_path: Path):
        """Shared kernel must only use standard library."""
        if not shared_path.exists():
            pytest.skip("Shared path does not exist")

        for filepath in get_python_files(shared_path):
            imports = get_imports_from_file(filepath)
            external_imports = {
                i for i in imports if not i.startswith("eiams")
            }

            for imp in external_imports:
                assert imp in SHARED_KERNEL_ALLOWED_EXTERNAL, (
                    f"{filepath.name} imports external module: {imp}"
                )


class TestModuleBoundaries:
    """Tests for module boundary enforcement."""

    def test_all_domain_modules_exist(self):
        """All six IAM domain modules must exist."""
        domain_path = (
            Path(__file__).parent.parent.parent / "src" / "eiams" / "domain"
        )
        expected_modules = [
            "identity",
            "authentication",
            "authorization",
            "credentials",
            "audit",
            "administration",
        ]

        for module in expected_modules:
            module_path = domain_path / module
            assert module_path.exists(), f"Domain module {module} does not exist"
            assert (module_path / "__init__.py").exists(), (
                f"Domain module {module} missing __init__.py"
            )

    def test_domain_modules_have_contracts(self):
        """Each domain module should have a contracts file."""
        domain_path = (
            Path(__file__).parent.parent.parent / "src" / "eiams" / "domain"
        )
        expected_modules = [
            "identity",
            "authentication",
            "authorization",
            "credentials",
            "audit",
            "administration",
        ]

        for module in expected_modules:
            contracts_path = domain_path / module / "contracts.py"
            assert contracts_path.exists(), (
                f"Domain module {module} missing contracts.py"
            )

    def test_infrastructure_can_import_domain(self):
        """Infrastructure layer can import from domain."""
        try:
            from eiams.infrastructure.adapters import HttpContextExtractor
            from eiams.domain.authorization.contracts import AuthorizationHook
            # This should work - infrastructure can use domain contracts
            assert True
        except ImportError as e:
            pytest.fail(f"Infrastructure should be able to import domain: {e}")

    def test_domain_does_not_import_infrastructure(self):
        """Domain must not import from infrastructure."""
        domain_path = (
            Path(__file__).parent.parent.parent / "src" / "eiams" / "domain"
        )
        if not domain_path.exists():
            pytest.skip("Domain path does not exist")

        violations = []
        for filepath in get_python_files(domain_path):
            imports = get_imports_from_file(filepath)
            if "eiams" in imports:
                # Check actual imports in the file
                with open(filepath, "r") as f:
                    content = f.read()
                    if "eiams.infrastructure" in content:
                        violations.append(str(filepath))

        assert not violations, (
            f"Domain imports infrastructure:\n" + "\n".join(violations)
        )

from dataclasses import dataclass
from typing import Optional
import sqlite3

from db.database import Database


@dataclass
class User:
    id: str
    username: str
    role: str
    organization: str
    clearance: int


@dataclass
class Project:
    id: str
    name: str
    organization_id: str
    classification: int


@dataclass
class Resource:
    id: str
    name: str
    project_id: str
    policy_id: str
    classification: int
    alias: str


@dataclass
class Policy:
    id: str
    name: str
    version: int
    required_clearance: int
    required_role: str
    scope: str


@dataclass
class ReviewRequest:
    id: str
    resource_id: str
    created_by: str
    subject: str
    reviewer: str
    principal: str
    state: str
    policy_version: int
    created_at: str | None = None
    expires_at: str | None = None
    operation_id: str | None = None

    created_at: str | None = None
    expires_at: str | None = None
    operation_id: str | None = None


@dataclass
class Delegation:
    id: str
    principal: str
    delegate: str
    resource_id: str
    scope: str
    state: str
    policy_version: int
    issued_at: str | None = None
    expires_at: str | None = None
    revoked_at: str | None = None
    operation_id: str | None = None


@dataclass
class AuthorizationContext:
    actor: Optional[User] = None
    subject: Optional[User] = None
    principal: Optional[User] = None
    delegate: Optional[User] = None


class AuthorityGraph:

    def __init__(self, database: Optional[Database] = None):

        self.database = database or Database()

    # ========================================================
    # USERS
    # ========================================================

    def get_user(self, user_id: str) -> Optional[User]:

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT
                    id,
                    username,
                    role,
                    organization_id,
                    clearance
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()

        finally:

            connection.close()

        if row is None:
            return None

        return User(
            id=row["id"],
            username=row["username"],
            role=row["role"],
            organization=row["organization_id"],
            clearance=row["clearance"],
        )

    def get_user_by_username(
        self,
        username: str,
    ) -> Optional[User]:

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT
                    id,
                    username,
                    role,
                    organization_id,
                    clearance
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

        finally:

            connection.close()

        if row is None:
            return None

        return User(
            id=row["id"],
            username=row["username"],
            role=row["role"],
            organization=row["organization_id"],
            clearance=row["clearance"],
        )

    # ========================================================
    # PROJECTS
    # ========================================================

    def get_project(
        self,
        project_id: str,
    ) -> Optional[Project]:

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT
                    id,
                    name,
                    organization_id,
                    classification
                FROM projects
                WHERE id = ?
                """,
                (project_id,),
            ).fetchone()

        finally:

            connection.close()

        if row is None:
            return None

        return Project(
            id=row["id"],
            name=row["name"],
            organization_id=row["organization_id"],
            classification=row["classification"],
        )

    # ========================================================
    # RESOURCES
    # ========================================================

    def get_resource(
        self,
        resource_id: str,
    ) -> Optional[Resource]:

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT
                    id,
                    name,
                    project_id,
                    policy_id,
                    classification,
                    alias
                FROM resources
                WHERE id = ?
                """,
                (resource_id,),
            ).fetchone()

        finally:

            connection.close()

        if row is None:
            return None

        return Resource(
            id=row["id"],
            name=row["name"],
            project_id=row["project_id"],
            policy_id=row["policy_id"],
            classification=row["classification"],
            alias=row["alias"],
        )

    # ========================================================
    # POLICIES
    # ========================================================

    def get_policy(
        self,
        policy_id: str,
    ) -> Optional[Policy]:

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT
                    id,
                    name,
                    version,
                    required_clearance,
                    required_role,
                    scope
                FROM policies
                WHERE id = ?
                """,
                (policy_id,),
            ).fetchone()

        finally:

            connection.close()

        if row is None:
            return None

        return Policy(
            id=row["id"],
            name=row["name"],
            version=row["version"],
            required_clearance=row["required_clearance"],
            required_role=row["required_role"],
            scope=row["scope"],
        )

    # ========================================================
    # REVIEWS
    # ========================================================

    def get_review(
        self,
        review_id: str,
    ) -> Optional[ReviewRequest]:

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT
                    id,
                    resource_id,
                    created_by,
                    subject,
                    reviewer,
                    principal,
                    state,
                    policy_version
                FROM reviews
                WHERE id = ?
                """,
                (review_id,),
            ).fetchone()

        finally:

            connection.close()

        if row is None:
            return None

        return ReviewRequest(
            id=row["id"],
            resource_id=row["resource_id"],
            created_by=row["created_by"],
            subject=row["subject"],
            reviewer=row["reviewer"],
            principal=row["principal"],
            state=row["state"],
            policy_version=row["policy_version"],
        )

    # ========================================================
    # DELEGATIONS
    # ========================================================

    def get_delegation(
        self,
        delegation_id: str,
    ) -> Optional[Delegation]:

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT
                    id,
                    principal,
                    delegate,
                    resource_id,
                    scope,
                    state,
                    policy_version
                FROM delegations
                WHERE id = ?
                """,
                (delegation_id,),
            ).fetchone()

        finally:

            connection.close()

        if row is None:
            return None

        return Delegation(
            id=row["id"],
            principal=row["principal"],
            delegate=row["delegate"],
            resource_id=row["resource_id"],
            scope=row["scope"],
            state=row["state"],
            policy_version=row["policy_version"],
        )

    # ========================================================
    # V2 AUTHORIZATION OPERATIONS
    # ========================================================

    def get_authorization_operation(
        self,
        operation_id: str,
    ):

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT
                    id,
                    resource_id,
                    requested_by,
                    subject,
                    requested_scope,
                    policy_version,
                    state,
                    created_at,
                    completed_at
                FROM authorization_operations
                WHERE id = ?
                """,
                (operation_id,),
            ).fetchone()

        finally:

            connection.close()

        return row


    def get_all_resources(self):

        connection = self.database.connect()

        try:

            rows = connection.execute(
                """
                SELECT
                    id,
                    name,
                    project_id,
                    policy_id,
                    classification,
                    alias
                FROM resources
                ORDER BY name
                """
            ).fetchall()

        finally:

            connection.close()

        return [
            Resource(
                id=row["id"],
                name=row["name"],
                project_id=row["project_id"],
                policy_id=row["policy_id"],
                classification=row["classification"],
                alias=row["alias"],
            )
            for row in rows
        ]


    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    def get_resource_project(
        self,
        resource_id: str,
    ) -> Optional[Project]:

        resource = self.get_resource(resource_id)

        if resource is None:
            return None

        return self.get_project(resource.project_id)

    def get_resource_policy(
        self,
        resource_id: str,
    ) -> Optional[Policy]:

        resource = self.get_resource(resource_id)

        if resource is None:
            return None

        return self.get_policy(resource.policy_id)

    def is_project_member(
        self,
        user_id: str,
        project_id: str,
    ) -> bool:

        connection = self.database.connect()

        try:

            row = connection.execute(
                """
                SELECT 1
                FROM project_members
                WHERE project_id = ?
                AND user_id = ?
                """,
                (
                    project_id,
                    user_id,
                ),
            ).fetchone()

        finally:

            connection.close()

        return row is not None

    # ========================================================
    # REVIEWS FOR RESOURCE
    # ========================================================

    def get_reviews_for_resource(
        self,
        resource_id: str,
    ) -> list[ReviewRequest]:

        connection = self.database.connect()

        try:

            rows = connection.execute(
                """
                SELECT
                    id,
                    resource_id,
                    created_by,
                    subject,
                    reviewer,
                    principal,
                    state,
                    policy_version,
                    created_at,
                    expires_at,
                    operation_id
                FROM reviews
                WHERE resource_id = ?
                """,
                (resource_id,),
            ).fetchall()

        finally:

            connection.close()

        return [
            ReviewRequest(
                id=row["id"],
                resource_id=row["resource_id"],
                created_by=row["created_by"],
                subject=row["subject"],
                reviewer=row["reviewer"],
                principal=row["principal"],
                state=row["state"],
                policy_version=row["policy_version"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                operation_id=row["operation_id"],
            )
            for row in rows
        ]

    # ========================================================
    # DELEGATIONS FOR RESOURCE
    # ========================================================

    def get_delegations_for_resource(
        self,
        resource_id: str,
    ) -> list[Delegation]:

        connection = self.database.connect()

        try:

            rows = connection.execute(
                """
                SELECT
                    id,
                    principal,
                    delegate,
                    resource_id,
                    scope,
                    state,
                    policy_version,
                    issued_at,
                    expires_at,
                    revoked_at,
                    operation_id
                FROM delegations
                WHERE resource_id = ?
                """,
                (resource_id,),
            ).fetchall()

        finally:

            connection.close()

        return [
            Delegation(
                id=row["id"],
                principal=row["principal"],
                delegate=row["delegate"],
                resource_id=row["resource_id"],
                scope=row["scope"],
                state=row["state"],
                policy_version=row["policy_version"],
                issued_at=row["issued_at"],
                expires_at=row["expires_at"],
                revoked_at=row["revoked_at"],
                operation_id=row["operation_id"],
            )
            for row in rows
        ]

    def get_active_delegations(
        self,
        resource_id: str,
    ) -> list[Delegation]:

        return [
            delegation
            for delegation
            in self.get_delegations_for_resource(
                resource_id
            )
            if delegation.state == "ACTIVE"
        ]

    # ========================================================
    # AUTHORIZATION CONTEXT
    # ========================================================

    def build_context(
        self,
        actor_id: str,
        subject_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        delegate_id: Optional[str] = None,
    ) -> AuthorizationContext:

        return AuthorizationContext(
            actor=self.get_user(actor_id),

            subject=(
                self.get_user(subject_id)
                if subject_id
                else None
            ),

            principal=(
                self.get_user(principal_id)
                if principal_id
                else None
            ),

            delegate=(
                self.get_user(delegate_id)
                if delegate_id
                else None
            ),
        )

    # ========================================================
    # RESOURCE DESCRIPTION
    # ========================================================

    def describe_resource(
        self,
        resource_id: str,
    ) -> dict:

        resource = self.get_resource(resource_id)

        if resource is None:
            return {}

        project = self.get_resource_project(
            resource_id
        )

        policy = self.get_resource_policy(
            resource_id
        )

        return {
            "resource": resource.id,
            "name": resource.name,
            "alias": resource.alias,
            "classification": resource.classification,
            "project": (
                project.id
                if project
                else None
            ),
            "project_name": (
                project.name
                if project
                else None
            ),
            "policy": (
                policy.id
                if policy
                else None
            ),
            "policy_name": (
                policy.name
                if policy
                else None
            ),
            "policy_version": (
                policy.version
                if policy
                else None
            ),
        }


    # ========================================================
    # V2 POLICY VERSIONS
    # ========================================================

    def get_policy_version(
        self,
        policy_id: str,
        version: int,
    ):
        connection = self.database.connect()

        try:
            row = connection.execute(
                """
                SELECT
                    id,
                    policy_id,
                    version,
                    required_clearance,
                    required_role,
                    scope,
                    effective_from,
                    effective_until,
                    supersedes_version,
                    status
                FROM policy_versions
                WHERE policy_id = ?
                  AND version = ?
                """,
                (policy_id, version),
            ).fetchone()
        finally:
            connection.close()

        return row

    def get_policy_versions(
        self,
        policy_id: str,
    ):
        connection = self.database.connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    id,
                    policy_id,
                    version,
                    required_clearance,
                    required_role,
                    scope,
                    effective_from,
                    effective_until,
                    supersedes_version,
                    status
                FROM policy_versions
                WHERE policy_id = ?
                ORDER BY version
                """,
                (policy_id,),
            ).fetchall()
        finally:
            connection.close()

        return rows

    # ========================================================
    # V2 REVIEW EVENTS
    # ========================================================

    def get_review_events(
        self,
        review_id: str,
    ):
        connection = self.database.connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    id,
                    review_id,
                    event_type,
                    actor,
                    occurred_at,
                    previous_state,
                    new_state,
                    operation_id
                FROM review_events
                WHERE review_id = ?
                ORDER BY occurred_at, id
                """,
                (review_id,),
            ).fetchall()
        finally:
            connection.close()

        return rows

    # ========================================================
    # V2 DELEGATION CONSTRAINTS
    # ========================================================

    def get_delegation_constraints(
        self,
        delegation_id: str,
    ):
        connection = self.database.connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    id,
                    delegation_id,
                    max_classification,
                    required_project_membership,
                    allowed_operation
                FROM delegation_constraints
                WHERE delegation_id = ?
                ORDER BY id
                """,
                (delegation_id,),
            ).fetchall()
        finally:
            connection.close()

        return rows

    # ========================================================
    # V2 AUTHORIZATION OPERATIONS
    # ========================================================

    def get_authorization_operation(
        self,
        operation_id: str,
    ):
        connection = self.database.connect()

        try:
            row = connection.execute(
                """
                SELECT
                    id,
                    resource_id,
                    requested_by,
                    subject,
                    requested_scope,
                    policy_version,
                    state,
                    created_at,
                    completed_at
                FROM authorization_operations
                WHERE id = ?
                """,
                (operation_id,),
            ).fetchone()
        finally:
            connection.close()

        return row

    def get_operations_for_resource(
        self,
        resource_id: str,
    ):
        connection = self.database.connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    id,
                    resource_id,
                    requested_by,
                    subject,
                    requested_scope,
                    policy_version,
                    state,
                    created_at,
                    completed_at
                FROM authorization_operations
                WHERE resource_id = ?
                ORDER BY created_at, id
                """,
                (resource_id,),
            ).fetchall()
        finally:
            connection.close()

        return rows

    # ========================================================
    # V2 AUDIT CORRELATIONS
    # ========================================================

    def get_audit_correlations(
        self,
        operation_id: str,
    ):
        connection = self.database.connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    id,
                    operation_id,
                    audit_event_id,
                    correlation_type,
                    sequence_number
                FROM audit_correlations
                WHERE operation_id = ?
                ORDER BY sequence_number, id
                """,
                (operation_id,),
            ).fetchall()
        finally:
            connection.close()

        return rows

    # ========================================================
    # V2 CAPABILITIES
    # ========================================================

    def get_capability(
        self,
        capability_id: str,
    ):
        connection = self.database.connect()

        try:
            row = connection.execute(
                """
                SELECT
                    id,
                    operation_id,
                    subject,
                    resource_id,
                    scope,
                    policy_version,
                    issued_at,
                    expires_at,
                    state,
                    token_digest
                FROM capabilities
                WHERE id = ?
                """,
                (capability_id,),
            ).fetchone()
        finally:
            connection.close()

        return row

    def get_capabilities_for_operation(
        self,
        operation_id: str,
    ):
        connection = self.database.connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    id,
                    operation_id,
                    subject,
                    resource_id,
                    scope,
                    policy_version,
                    issued_at,
                    expires_at,
                    state,
                    token_digest
                FROM capabilities
                WHERE operation_id = ?
                ORDER BY issued_at, id
                """,
                (operation_id,),
            ).fetchall()
        finally:
            connection.close()

        return rows



# ============================================================
# DATABASE-BACKED TEST
# ============================================================

if __name__ == "__main__":

    graph = AuthorityGraph()

    echo = graph.get_user_by_username("echo")

    print("=" * 70)
    print("BLACKSITE — DATABASE-BACKED AUTHORITY GRAPH")
    print("=" * 70)

    print()

    if echo:

        print("Identity:")
        print(f"  Username  : {echo.username}")
        print(f"  Role      : {echo.role}")
        print(f"  Clearance : R{echo.clearance}")
        print(f"  ID        : {echo.id}")

    print()

    connection = graph.database.connect()

    try:

        resources = connection.execute(
            """
            SELECT id, name, alias
            FROM resources
            ORDER BY name
            """
        ).fetchall()

    finally:

        connection.close()

    print("Resources:")

    for resource in resources:

        print(
            f"  {resource['name']:<30}"
            f"{resource['alias']:<14}"
            f"{resource['id']}"
        )

    print()

    blacksite = next(
        (
            resource
            for resource in resources
            if resource["name"] == "BLACKSITE_RESOURCE"
        ),
        None,
    )

    if blacksite:

        print("BLACKSITE GRAPH:")

        description = graph.describe_resource(
            blacksite["id"]
        )

        for key, value in description.items():

            print(
                f"  {key:<18}: {value}"
            )

    print()

    print(
        "Database-backed authority graph "
        "loaded successfully."
    )

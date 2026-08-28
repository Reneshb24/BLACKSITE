import sqlite3
from pathlib import Path


class Database:

    def __init__(self, path=None):

        if path is None:
            project_root = Path(__file__).resolve().parent.parent
            path = project_root / "data" / "blacksite.db"

        self.path = Path(path)

    def connect(self):

        connection = sqlite3.connect(
            self.path
        )

        connection.row_factory = sqlite3.Row

        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    def initialize(self):

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        connection = self.connect()

        try:

            connection.executescript(
                """

                PRAGMA foreign_keys = ON;


                -- ==================================================
                -- ORGANIZATIONS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS organizations (

                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE

                );


                -- ==================================================
                -- USERS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS users (

                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    organization_id TEXT NOT NULL,
                    clearance INTEGER NOT NULL,

                    FOREIGN KEY (
                        organization_id
                    )
                    REFERENCES organizations(id)

                );


                -- ==================================================
                -- PROJECTS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS projects (

                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    organization_id TEXT NOT NULL,
                    classification INTEGER NOT NULL,

                    FOREIGN KEY (
                        organization_id
                    )
                    REFERENCES organizations(id)

                );


                -- ==================================================
                -- PROJECT MEMBERS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS project_members (

                    project_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,

                    PRIMARY KEY (
                        project_id,
                        user_id
                    ),

                    FOREIGN KEY (
                        project_id
                    )
                    REFERENCES projects(id),

                    FOREIGN KEY (
                        user_id
                    )
                    REFERENCES users(id)

                );


                -- ==================================================
                -- CURRENT POLICIES
                -- ==================================================

                CREATE TABLE IF NOT EXISTS policies (

                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    required_clearance INTEGER NOT NULL,
                    required_role TEXT NOT NULL,
                    scope TEXT NOT NULL

                );


                -- ==================================================
                -- HISTORICAL POLICY VERSIONS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS policy_versions (

                    id TEXT PRIMARY KEY,

                    policy_id TEXT NOT NULL,
                    version INTEGER NOT NULL,

                    required_clearance INTEGER NOT NULL,
                    required_role TEXT NOT NULL,
                    scope TEXT NOT NULL,

                    effective_from TEXT,
                    effective_until TEXT,

                    supersedes_version INTEGER,
                    status TEXT NOT NULL,

                    FOREIGN KEY (
                        policy_id
                    )
                    REFERENCES policies(id),

                    UNIQUE (
                        policy_id,
                        version
                    )

                );


                -- ==================================================
                -- RESOURCES
                -- ==================================================

                CREATE TABLE IF NOT EXISTS resources (

                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    classification INTEGER NOT NULL,
                    alias TEXT NOT NULL UNIQUE,

                    FOREIGN KEY (
                        project_id
                    )
                    REFERENCES projects(id),

                    FOREIGN KEY (
                        policy_id
                    )
                    REFERENCES policies(id)

                );


                -- ==================================================
                -- REVIEWS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS reviews (

                    id TEXT PRIMARY KEY,

                    resource_id TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    reviewer TEXT NOT NULL,
                    principal TEXT NOT NULL,

                    state TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,

                    created_at TEXT,
                    expires_at TEXT,

                    operation_id TEXT,

                    FOREIGN KEY (
                        resource_id
                    )
                    REFERENCES resources(id),

                    FOREIGN KEY (
                        created_by
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        subject
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        reviewer
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        principal
                    )
                    REFERENCES users(id)

                );


                -- ==================================================
                -- REVIEW EVENTS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS review_events (

                    id TEXT PRIMARY KEY,

                    review_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,

                    actor TEXT NOT NULL,

                    occurred_at TEXT NOT NULL,

                    previous_state TEXT,
                    new_state TEXT,

                    operation_id TEXT,

                    FOREIGN KEY (
                        review_id
                    )
                    REFERENCES reviews(id),

                    FOREIGN KEY (
                        actor
                    )
                    REFERENCES users(id)

                );


                -- ==================================================
                -- DELEGATIONS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS delegations (

                    id TEXT PRIMARY KEY,

                    principal TEXT NOT NULL,
                    delegate TEXT NOT NULL,

                    resource_id TEXT NOT NULL,

                    scope TEXT NOT NULL,
                    state TEXT NOT NULL,

                    policy_version INTEGER NOT NULL,

                    issued_at TEXT,
                    expires_at TEXT,
                    revoked_at TEXT,

                    operation_id TEXT,

                    FOREIGN KEY (
                        principal
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        delegate
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        resource_id
                    )
                    REFERENCES resources(id)

                );


                -- ==================================================
                -- DELEGATION CONSTRAINTS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS delegation_constraints (

                    id TEXT PRIMARY KEY,

                    delegation_id TEXT NOT NULL,

                    max_classification INTEGER,
                    required_project_membership INTEGER NOT NULL DEFAULT 0,

                    allowed_operation TEXT,

                    FOREIGN KEY (
                        delegation_id
                    )
                    REFERENCES delegations(id)

                );


                -- ==================================================
                -- AUTHORIZATION OPERATIONS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS authorization_operations (

                    id TEXT PRIMARY KEY,

                    resource_id TEXT NOT NULL,

                    requested_by TEXT NOT NULL,
                    subject TEXT NOT NULL,

                    requested_scope TEXT NOT NULL,

                    policy_version INTEGER NOT NULL,

                    state TEXT NOT NULL,

                    created_at TEXT NOT NULL,
                    completed_at TEXT,

                    FOREIGN KEY (
                        resource_id
                    )
                    REFERENCES resources(id),

                    FOREIGN KEY (
                        requested_by
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        subject
                    )
                    REFERENCES users(id)

                );


                -- ==================================================
                -- AUDIT EVENTS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS audit_events (

                    id TEXT PRIMARY KEY,

                    event_type TEXT NOT NULL,

                    actor TEXT NOT NULL,
                    subject TEXT NOT NULL,

                    resource_id TEXT NOT NULL,

                    result TEXT NOT NULL,
                    message TEXT NOT NULL,

                    operation_id TEXT,

                    occurred_at TEXT,

                    FOREIGN KEY (
                        actor
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        subject
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        resource_id
                    )
                    REFERENCES resources(id)

                );


                -- ==================================================
                -- AUDIT CORRELATIONS
                -- ==================================================

                CREATE TABLE IF NOT EXISTS audit_correlations (

                    id TEXT PRIMARY KEY,

                    operation_id TEXT NOT NULL,

                    audit_event_id TEXT NOT NULL,

                    correlation_type TEXT NOT NULL,

                    sequence_number INTEGER NOT NULL,

                    FOREIGN KEY (
                        operation_id
                    )
                    REFERENCES authorization_operations(id),

                    FOREIGN KEY (
                        audit_event_id
                    )
                    REFERENCES audit_events(id)

                );


                -- ==================================================
                -- CAPABILITIES
                -- ==================================================

                CREATE TABLE IF NOT EXISTS capabilities (

                    id TEXT PRIMARY KEY,

                    operation_id TEXT NOT NULL,

                    subject TEXT NOT NULL,

                    resource_id TEXT NOT NULL,

                    scope TEXT NOT NULL,

                    policy_version INTEGER NOT NULL,

                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,

                    state TEXT NOT NULL,

                    token_digest TEXT NOT NULL,

                    FOREIGN KEY (
                        operation_id
                    )
                    REFERENCES authorization_operations(id),

                    FOREIGN KEY (
                        subject
                    )
                    REFERENCES users(id),

                    FOREIGN KEY (
                        resource_id
                    )
                    REFERENCES resources(id)

                );


                -- ==================================================
                -- CHALLENGE METADATA
                -- ==================================================

                CREATE TABLE IF NOT EXISTS challenge_meta (

                    id INTEGER PRIMARY KEY,

                    instance_id TEXT NOT NULL,

                    flag_secret TEXT NOT NULL,

                    scenario_time TEXT NOT NULL

                );


                -- ==================================================
                -- INDEXES
                -- ==================================================

                CREATE INDEX IF NOT EXISTS
                    idx_policy_versions_policy
                ON policy_versions(policy_id);


                CREATE INDEX IF NOT EXISTS
                    idx_reviews_resource
                ON reviews(resource_id);


                CREATE INDEX IF NOT EXISTS
                    idx_review_events_review
                ON review_events(review_id);


                CREATE INDEX IF NOT EXISTS
                    idx_delegations_resource
                ON delegations(resource_id);


                CREATE INDEX IF NOT EXISTS
                    idx_operations_resource
                ON authorization_operations(resource_id);


                CREATE INDEX IF NOT EXISTS
                    idx_audit_operation
                ON audit_events(operation_id);


                CREATE INDEX IF NOT EXISTS
                    idx_capabilities_operation
                ON capabilities(operation_id);


                """
            )

            connection.commit()

        finally:

            connection.close()

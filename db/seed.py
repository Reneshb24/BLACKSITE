
from generator.world import build_world, validate_world
from db.database import Database


def seed_database():
    """
    Generate one V2 BLACKSITE world and persist it to SQLite.
    """

    world = build_world()
    validate_world(world)

    database = Database()
    database.initialize()

    connection = database.connect()

    try:

        # ====================================================
        # RESET CURRENT CHALLENGE
        # ====================================================

        connection.executescript(
            """
            DELETE FROM capabilities;
            DELETE FROM audit_correlations;
            DELETE FROM review_events;
            DELETE FROM delegation_constraints;
            DELETE FROM authorization_operations;

            DELETE FROM audit_events;
            DELETE FROM delegations;
            DELETE FROM reviews;
            DELETE FROM resources;
            DELETE FROM project_members;
            DELETE FROM projects;

            DELETE FROM policy_versions;
            DELETE FROM policies;

            DELETE FROM users;
            DELETE FROM organizations;

            DELETE FROM challenge_meta;
            """
        )

        # ====================================================
        # CHALLENGE META
        # ====================================================

        connection.execute(
            """
            INSERT INTO challenge_meta (
                id,
                instance_id,
                flag_secret,
                scenario_time
            )
            VALUES (1, ?, ?, ?)
            """,
            (
                world.instance_id,
                world.flag_secret,
                world.scenario_time,
            ),
        )

        # ====================================================
        # ORGANIZATIONS
        # ====================================================

        for organization in world.organizations:

            connection.execute(
                """
                INSERT INTO organizations (
                    id,
                    name
                )
                VALUES (?, ?)
                """,
                (
                    organization.id,
                    organization.name,
                ),
            )

        # ====================================================
        # USERS
        # ====================================================

        for user in world.users:

            connection.execute(
                """
                INSERT INTO users (
                    id,
                    username,
                    role,
                    organization_id,
                    clearance
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    user.id,
                    user.username,
                    user.role,
                    user.organization,
                    user.clearance,
                ),
            )

        # ====================================================
        # PROJECTS + MEMBERS
        # ====================================================

        for project in world.projects:

            connection.execute(
                """
                INSERT INTO projects (
                    id,
                    name,
                    organization_id,
                    classification
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    project.id,
                    project.name,
                    project.organization_id,
                    project.classification,
                ),
            )

            for user_id in project.members:

                connection.execute(
                    """
                    INSERT INTO project_members (
                        project_id,
                        user_id
                    )
                    VALUES (?, ?)
                    """,
                    (
                        project.id,
                        user_id,
                    ),
                )

        # ====================================================
        # CURRENT POLICIES
        # ====================================================

        for policy in world.policies:

            connection.execute(
                """
                INSERT INTO policies (
                    id,
                    name,
                    version,
                    required_clearance,
                    required_role,
                    scope
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    policy.id,
                    policy.name,
                    policy.version,
                    policy.required_clearance,
                    policy.required_role,
                    policy.scope,
                ),
            )

        # ====================================================
        # POLICY HISTORY
        # ====================================================

        for version in world.policy_versions:

            connection.execute(
                """
                INSERT INTO policy_versions (
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
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    version.id,
                    version.policy_id,
                    version.version,
                    version.required_clearance,
                    version.required_role,
                    version.scope,
                    version.effective_from,
                    version.effective_until,
                    version.supersedes_version,
                    version.status,
                ),
            )

        # ====================================================
        # RESOURCES
        # ====================================================

        for resource in world.resources:

            connection.execute(
                """
                INSERT INTO resources (
                    id,
                    name,
                    project_id,
                    policy_id,
                    classification,
                    alias
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    resource.id,
                    resource.name,
                    resource.project_id,
                    resource.policy_id,
                    resource.classification,
                    resource.alias,
                ),
            )

        # ====================================================
        # AUTHORIZATION OPERATIONS
        # ====================================================

        for operation in world.authorization_operations:

            connection.execute(
                """
                INSERT INTO authorization_operations (
                    id,
                    resource_id,
                    requested_by,
                    subject,
                    requested_scope,
                    policy_version,
                    state,
                    created_at,
                    completed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation.id,
                    operation.resource_id,
                    operation.requested_by,
                    operation.subject,
                    operation.requested_scope,
                    operation.policy_version,
                    operation.state,
                    operation.created_at,
                    operation.completed_at,
                ),
            )

        # ====================================================
        # REVIEWS
        # ====================================================

        for review in world.reviews:

            connection.execute(
                """
                INSERT INTO reviews (
                    id,
                    resource_id,
                    created_by,
                    subject,
                    reviewer,
                    principal,
                    state,
                    policy_version
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    review.id,
                    review.resource_id,
                    review.created_by,
                    review.subject,
                    review.reviewer,
                    review.principal,
                    review.state,
                    review.policy_version,
                ),
            )

        # ====================================================
        # REVIEW EVENTS
        # ====================================================

        for event in world.review_events:

            connection.execute(
                """
                INSERT INTO review_events (
                    id,
                    review_id,
                    event_type,
                    actor,
                    occurred_at,
                    previous_state,
                    new_state,
                    operation_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.review_id,
                    event.event_type,
                    event.actor,
                    event.occurred_at,
                    event.previous_state,
                    event.new_state,
                    event.operation_id,
                ),
            )

        # ====================================================
        # DELEGATIONS
        # ====================================================

        for delegation in world.delegations:

            connection.execute(
                """
                INSERT INTO delegations (
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
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delegation.id,
                    delegation.principal,
                    delegation.delegate,
                    delegation.resource_id,
                    delegation.scope,
                    delegation.state,
                    delegation.policy_version,
                    delegation.issued_at,
                    delegation.expires_at,
                    delegation.revoked_at,
                    delegation.operation_id,
                ),
            )

        # ====================================================
        # DELEGATION CONSTRAINTS
        # ====================================================

        for constraint in world.delegation_constraints:

            connection.execute(
                """
                INSERT INTO delegation_constraints (
                    id,
                    delegation_id,
                    max_classification,
                    required_project_membership,
                    allowed_operation
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    constraint.id,
                    constraint.delegation_id,
                    constraint.max_classification,
                    int(
                        constraint.required_project_membership
                    ),
                    constraint.allowed_operation,
                ),
            )

        # ====================================================
        # AUDIT EVENTS
        # ====================================================

        for event in world.audit_events:

            connection.execute(
                """
                INSERT INTO audit_events (
                    id,
                    event_type,
                    actor,
                    subject,
                    resource_id,
                    result,
                    message,
                    operation_id,
                    occurred_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.event_type,
                    event.actor,
                    event.subject,
                    event.resource_id,
                    event.result,
                    event.message,
                    None,
                    None,
                ),
            )

        # ====================================================
        # AUDIT CORRELATIONS
        # ====================================================

        for correlation in world.audit_correlations:

            connection.execute(
                """
                INSERT INTO audit_correlations (
                    id,
                    operation_id,
                    audit_event_id,
                    correlation_type,
                    sequence_number
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    correlation.id,
                    correlation.operation_id,
                    correlation.audit_event_id,
                    correlation.correlation_type,
                    correlation.sequence_number,
                ),
            )

        # ====================================================
        # CAPABILITIES
        # ====================================================

        for capability in world.capabilities:

            connection.execute(
                """
                INSERT INTO capabilities (
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
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    capability.id,
                    capability.operation_id,
                    capability.subject,
                    capability.resource_id,
                    capability.scope,
                    capability.policy_version,
                    capability.issued_at,
                    capability.expires_at,
                    capability.state,
                    capability.token_digest,
                ),
            )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return world


if __name__ == "__main__":

    world = seed_database()

    print("=" * 70)
    print("AEGIS BLACKSITE — V2 DATABASE SEED")
    print("=" * 70)

    print()
    print("Instance            :", world.instance_id)
    print("Organizations       :", len(world.organizations))
    print("Users               :", len(world.users))
    print("Projects            :", len(world.projects))
    print("Policies            :", len(world.policies))
    print("Policy versions     :", len(world.policy_versions))
    print("Resources           :", len(world.resources))
    print("Reviews             :", len(world.reviews))
    print("Review events       :", len(world.review_events))
    print("Delegations         :", len(world.delegations))
    print("Delegation rules    :", len(world.delegation_constraints))
    print("Operations          :", len(world.authorization_operations))
    print("Audit events        :", len(world.audit_events))
    print("Audit correlations  :", len(world.audit_correlations))
    print("Capabilities        :", len(world.capabilities))

    print()
    print("V2 database seeded successfully.")

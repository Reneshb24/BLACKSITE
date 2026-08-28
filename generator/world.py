from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from secrets import choice, token_hex
from uuid import uuid4
from typing import List

# ============================================================
# BLACKSITE — CONTROLLED RANDOM WORLD GENERATOR
# ============================================================

ROLES = [
    "researcher",
    "reviewer",
    "archivist",
    "operator",
    "auditor",
    "administrator",
]

PROJECT_NAMES = [
    "ORION",
    "HELIOS",
    "LANTERN",
    "MIRROR",
    "NIGHTFALL",
    "AEGIS",
    "BLACKSITE",
]


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"
def iso_time(offset_minutes=0):
    """
    Return a deterministic UTC timestamp relative to a fixed
    challenge reference time.
    """
    base = datetime(
        2026,
        8,
        28,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    return (
        base + timedelta(minutes=offset_minutes)
    ).isoformat()

# ============================================================
# MODELS
# ============================================================

@dataclass
class User:
    id: str
    username: str
    role: str
    organization: str
    clearance: int


@dataclass
class Organization:
    id: str
    name: str


@dataclass
class Project:
    id: str
    name: str
    organization_id: str
    classification: int
    members: List[str] = field(default_factory=list)


@dataclass
class Policy:
    id: str
    name: str
    version: int
    required_clearance: int
    required_role: str
    scope: str

@dataclass
class PolicyVersion:
    id: str
    policy_id: str
    version: int
    required_clearance: int
    required_role: str
    scope: str
    effective_from: str
    effective_until: str | None
    supersedes_version: int | None
    status: str


@dataclass
class ReviewEvent:
    id: str
    review_id: str
    event_type: str
    actor: str
    occurred_at: str
    previous_state: str | None
    new_state: str | None
    operation_id: str | None


@dataclass
class DelegationConstraint:
    id: str
    delegation_id: str
    max_classification: int | None
    required_project_membership: bool
    allowed_operation: str | None


@dataclass
class AuthorizationOperation:
    id: str
    resource_id: str
    requested_by: str
    subject: str
    requested_scope: str
    policy_version: int
    state: str
    created_at: str
    completed_at: str | None


@dataclass
class AuditCorrelation:
    id: str
    operation_id: str
    audit_event_id: str
    correlation_type: str
    sequence_number: int


@dataclass
class Capability:
    id: str
    operation_id: str
    subject: str
    resource_id: str
    scope: str
    policy_version: int
    issued_at: str
    expires_at: str
    state: str
    token_digest: str
@dataclass
class Resource:
    id: str
    name: str
    project_id: str
    policy_id: str
    classification: int
    alias: str


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
class AuditEvent:
    id: str
    event_type: str
    actor: str
    subject: str
    resource_id: str
    result: str
    message: str

    operation_id: str | None = None
    occurred_at: str | None = None


@dataclass
class World:
    instance_id: str
    flag_secret: str
    scenario_time: str = "2026-08-28T09:15:00+00:00"

    users: List[User] = field(default_factory=list)
    organizations: List[Organization] = field(default_factory=list)
    projects: List[Project] = field(default_factory=list)
    policies: List[Policy] = field(default_factory=list)
    resources: List[Resource] = field(default_factory=list)
    reviews: List[ReviewRequest] = field(default_factory=list)
    delegations: List[Delegation] = field(default_factory=list)
    audit_events: List[AuditEvent] = field(default_factory=list)

    policy_versions: List[PolicyVersion] = field(default_factory=list)
    review_events: List[ReviewEvent] = field(default_factory=list)
    delegation_constraints: List[DelegationConstraint] = field(default_factory=list)
    authorization_operations: List[AuthorizationOperation] = field(default_factory=list)
    audit_correlations: List[AuditCorrelation] = field(default_factory=list)
    capabilities: List[Capability] = field(default_factory=list)
# ============================================================
# WORLD GENERATOR
# ============================================================

def build_world() -> World:

    world = World(
        instance_id=new_id("world"),
        flag_secret=token_hex(8).upper(),
        scenario_time="2026-08-28T09:15:00+00:00",
    )

    # --------------------------------------------------------
    # ORGANIZATIONS
    # --------------------------------------------------------

    organizations = [
        Organization(new_id("org"), "AEGIS-RESEARCH"),
        Organization(new_id("org"), "BLACKSITE-OPS"),
        Organization(new_id("org"), "LEGACY-SYSTEMS"),
        Organization(new_id("org"), "FIELD-OPERATIONS"),
    ]

    world.organizations.extend(organizations)

    research_org = organizations[0]
    blacksite_org = organizations[1]
    legacy_org = organizations[2]
    field_org = organizations[3]

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    echo = User(
        new_id("usr"),
        "echo",
        "researcher",
        research_org.id,
        2,
    )

    nova = User(
        new_id("usr"),
        "nova",
        "reviewer",
        research_org.id,
        4,
    )

    warden = User(
        new_id("usr"),
        "warden",
        "administrator",
        blacksite_org.id,
        5,
    )

    archivist = User(
        new_id("usr"),
        "archivist",
        "archivist",
        legacy_org.id,
        3,
    )

    operator = User(
        new_id("usr"),
        "operator",
        "operator",
        blacksite_org.id,
        4,
    )

    auditor = User(
        new_id("usr"),
        "auditor",
        "auditor",
        field_org.id,
        3,
    )

    analyst = User(
        new_id("usr"),
        "analyst",
        "researcher",
        research_org.id,
        2,
    )

    custodian = User(
        new_id("usr"),
        "custodian",
        "operator",
        blacksite_org.id,
        4,
    )

    users = [
        echo,
        nova,
        warden,
        archivist,
        operator,
        auditor,
        analyst,
        custodian,
    ]

    world.users.extend(users)

    # --------------------------------------------------------
    # PROJECTS
    # --------------------------------------------------------

    # The target project is intentionally selected from the
    # generated set, but its surrounding graph is noisy.

    project_specs = [
        ("ORION", research_org, 2, [echo.id]),
        ("HELIOS", research_org, 4, [nova.id]),
        ("LANTERN", legacy_org, 3, [archivist.id]),
        ("MIRROR", field_org, 3, [auditor.id]),
        ("NIGHTFALL", research_org, 2, [analyst.id]),
        ("AEGIS", blacksite_org, 4, [operator.id, custodian.id]),
        ("BLACKSITE", blacksite_org, 5, [warden.id]),
    ]

    for name, org, classification, members in project_specs:

        project = Project(
            id=new_id("prj"),
            name=name,
            organization_id=org.id,
            classification=classification,
            members=members,
        )

        world.projects.append(project)

    # --------------------------------------------------------
    # POLICIES
    # --------------------------------------------------------

    policy_specs = [
        ("ORION-RESEARCH", 3, 2, "researcher", "PROJECT"),
        ("HELIOS-MIGRATION", 6, 4, "reviewer", "MIGRATION"),
        ("LANTERN-ARCHIVE", 4, 3, "archivist", "ARCHIVE"),
        ("MIRROR-AUDIT", 5, 3, "auditor", "AUDIT"),
        ("NIGHTFALL-RESEARCH", 2, 2, "researcher", "PROJECT"),
        ("AEGIS-OPS", 7, 4, "operator", "CONTROL"),
        ("BLACKSITE-CONTROL", 8, 5, "administrator", "VAULT"),
    ]

    for name, version, clearance, role, scope in policy_specs:

        world.policies.append(
            Policy(
                id=new_id("pol"),
                name=name,
                version=version,
                required_clearance=clearance,
                required_role=role,
                scope=scope,
            )
        )

    # --------------------------------------------------------
    # RESOURCES
    # --------------------------------------------------------

    for project, policy in zip(
        world.projects,
        world.policies,
    ):

        world.resources.append(
            Resource(
                id=new_id("res"),
                name=f"{project.name}_RESOURCE",
                project_id=project.id,
                policy_id=policy.id,
                classification=project.classification,
                alias=f"ARC-{token_hex(3).upper()}",
            )
        )

    # --------------------------------------------------------
    # LOCATE THE TARGET RESOURCE
    # --------------------------------------------------------

    blacksite_project = next(
        p for p in world.projects
        if p.name == "BLACKSITE"
    )

    blacksite_resource = next(
        r for r in world.resources
        if r.project_id == blacksite_project.id
    )
    
        # ========================================================
    # V2 POLICY HISTORY
    # ========================================================

    policy_offsets = {
        policy.name: list(
            range(
                max(1, policy.version - 2),
                policy.version + 1,
            )
        )
        for policy in world.policies
    }

    for policy in world.policies:

        versions = policy_offsets[policy.name]

        for index, version in enumerate(versions):

            if version == policy.version:
                status = "ACTIVE"
                effective_until = None
            else:
                status = "SUPERSEDED"
                effective_until = iso_time(
                    (index + 1) * 100
                )

            historical_clearance = policy.required_clearance
            historical_role = policy.required_role

            # BLACKSITE-CONTROL v7 had a weaker granting
            # authority model than the current v8 policy.
            # The current policy remains administrator/R5,
            # while the historical review authority was
            # reviewer/R4.
            if (
                policy.name == "BLACKSITE-CONTROL"
                and version == policy.version - 1
            ):
                historical_clearance = 4
                historical_role = "reviewer"

            world.policy_versions.append(
                PolicyVersion(
                    id=new_id("pver"),
                    policy_id=policy.id,
                    version=version,
                    required_clearance=historical_clearance,
                    required_role=historical_role,
                    scope=policy.scope,
                    effective_from=iso_time(
                        -((len(versions) - index) * 100)
                    ),
                    effective_until=effective_until,
                    supersedes_version=(
                        versions[index - 1]
                        if index > 0
                        else None
                    ),
                    status=status,
                )
            )

    # ========================================================
    # ========================================================
    # V2 REVIEW / DELEGATION DATA
    # ========================================================
    #
    # The target contains several plausible authorization
    # histories. Only one complete chain is internally coherent.
    # ========================================================

    target_policy = next(
        p for p in world.policies
        if p.id == blacksite_resource.policy_id
    )

    current_version = target_policy.version
    historical_version = current_version - 1

    # --------------------------------------------------------
    # TARGET PROJECT MEMBERSHIP
    # --------------------------------------------------------

    if echo.id not in blacksite_project.members:
        blacksite_project.members.append(echo.id)

    # --------------------------------------------------------
    # HELPERS
    # --------------------------------------------------------

    def add_operation(
        *,
        state,
        version,
        scope="VAULT",
        subject=echo.id,
        requested_by=echo.id,
        created_offset=-300,
        completed_offset=-250,
    ):
        operation = AuthorizationOperation(
            id=new_id("op"),
            resource_id=blacksite_resource.id,
            requested_by=requested_by,
            subject=subject,
            requested_scope=scope,
            policy_version=version,
            state=state,
            created_at=iso_time(created_offset),
            completed_at=(
                iso_time(completed_offset)
                if completed_offset is not None
                else None
            ),
        )

        world.authorization_operations.append(operation)
        return operation

    def add_review(
        *,
        reviewer,
        principal,
        state,
        version,
        operation_id,
        created_by=echo.id,
        subject=echo.id,
    ):
        review = ReviewRequest(
            id=new_id("rev"),
            resource_id=blacksite_resource.id,
            created_by=created_by,
            subject=subject,
            reviewer=reviewer,
            principal=principal,
            state=state,
            policy_version=version,
        )

        world.reviews.append(review)

        return review

    def add_review_history(
        review,
        operation_id,
        *,
        approved_by,
        valid=True,
        created_offset=-200,
        approval_offset=-190,
    ):
        world.review_events.append(
            ReviewEvent(
                id=new_id("rve"),
                review_id=review.id,
                event_type="CREATED",
                actor=review.created_by,
                occurred_at=iso_time(created_offset),
                previous_state=None,
                new_state="PENDING",
                operation_id=operation_id,
            )
        )

        if valid:

            previous_state = "PENDING"

        else:

            previous_state = "DRAFT"

        world.review_events.append(
            ReviewEvent(
                id=new_id("rve"),
                review_id=review.id,
                event_type="APPROVED",
                actor=approved_by,
                occurred_at=iso_time(approval_offset),
                previous_state=previous_state,
                new_state="APPROVED",
                operation_id=operation_id,
            )
        )

    def add_delegation(
        *,
        principal,
        delegate,
        scope,
        state,
        version,
        operation_id,
        issued_offset,
        expiry_offset,
        revoked_offset=None,
    ):
        delegation = Delegation(
            id=new_id("del"),
            principal=principal,
            delegate=delegate,
            resource_id=blacksite_resource.id,
            scope=scope,
            state=state,
            policy_version=version,
            issued_at=iso_time(issued_offset),
            expires_at=(
                iso_time(expiry_offset)
                if expiry_offset is not None
                else None
            ),
            revoked_at=(
                iso_time(revoked_offset)
                if revoked_offset is not None
                else None
            ),
            operation_id=operation_id,
        )

        world.delegations.append(delegation)
        return delegation

    def add_constraint(
        delegation,
        *,
        max_classification,
        required_project_membership,
        allowed_operation,
    ):
        constraint = DelegationConstraint(
            id=new_id("dcon"),
            delegation_id=delegation.id,
            max_classification=max_classification,
            required_project_membership=(
                required_project_membership
            ),
            allowed_operation=allowed_operation,
        )

        world.delegation_constraints.append(constraint)
        return constraint

    # ========================================================
    # REAL CHAIN
    # ========================================================
    #
    # This is the only internally coherent historical chain.
    #
    # operation
    #    ↓
    # review
    #    ↓
    # approved review history
    #    ↓
    # delegation
    #    ↓
    # delegation constraints
    # ========================================================

    real_operation = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        subject=echo.id,
        requested_by=echo.id,
        created_offset=-240,
        completed_offset=-180,
    )

    real_review = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=real_operation.id,
    )

    add_review_history(
        real_review,
        real_operation.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-230,
        approval_offset=-190,
    )

    real_delegation = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="VAULT",
        state="ACTIVE",
        version=historical_version,
        operation_id=real_operation.id,
        issued_offset=-185,
        expiry_offset=180,
    )

    add_constraint(
        real_delegation,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 1
    # VALID LOOKING RECORDS + BROKEN REVIEW HISTORY
    # ========================================================

    op_1 = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        created_offset=-500,
        completed_offset=-450,
    )

    review_1 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_1.id,
    )

    add_review_history(
        review_1,
        op_1.id,
        approved_by=nova.id,
        valid=False,
        created_offset=-495,
        approval_offset=-490,
    )

    delegation_1 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="VAULT",
        state="ACTIVE",
        version=historical_version,
        operation_id=op_1.id,
        issued_offset=-440,
        expiry_offset=100,
    )

    add_constraint(
        delegation_1,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 2
    # REVIEWER / PRINCIPAL SEPARATION-OF-DUTIES VIOLATION
    # ========================================================

    op_2 = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        created_offset=-420,
        completed_offset=-400,
    )

    review_2 = add_review(
        reviewer=warden.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_2.id,
    )

    add_review_history(
        review_2,
        op_2.id,
        approved_by=warden.id,
        valid=True,
        created_offset=-415,
        approval_offset=-405,
    )

    delegation_2 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="VAULT",
        state="ACTIVE",
        version=historical_version,
        operation_id=op_2.id,
        issued_offset=-395,
        expiry_offset=100,
    )

    add_constraint(
        delegation_2,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 3
    # WRONG HISTORICAL POLICY REVISION
    # ========================================================

    wrong_version = max(
        1,
        historical_version - 1,
    )

    op_3 = add_operation(
        state="COMPLETED",
        version=wrong_version,
        scope="VAULT",
        created_offset=-360,
        completed_offset=-340,
    )

    review_3 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=wrong_version,
        operation_id=op_3.id,
    )

    add_review_history(
        review_3,
        op_3.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-355,
        approval_offset=-345,
    )

    delegation_3 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="VAULT",
        state="ACTIVE",
        version=wrong_version,
        operation_id=op_3.id,
        issued_offset=-335,
        expiry_offset=100,
    )

    add_constraint(
        delegation_3,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 4
    # WRONG SCOPE
    # ========================================================

    op_4 = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="CONTROL",
        created_offset=-315,
        completed_offset=-295,
    )

    review_4 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_4.id,
    )

    add_review_history(
        review_4,
        op_4.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-310,
        approval_offset=-300,
    )

    delegation_4 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="CONTROL",
        state="ACTIVE",
        version=historical_version,
        operation_id=op_4.id,
        issued_offset=-290,
        expiry_offset=100,
    )

    add_constraint(
        delegation_4,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="CONTROL",
    )

    # ========================================================
    # DECOY 5
    # EXPIRED DELEGATION
    # ========================================================

    op_5 = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        created_offset=-270,
        completed_offset=-250,
    )

    review_5 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_5.id,
    )

    add_review_history(
        review_5,
        op_5.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-265,
        approval_offset=-255,
    )

    delegation_5 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="VAULT",
        state="EXPIRED",
        version=historical_version,
        operation_id=op_5.id,
        issued_offset=-245,
        expiry_offset=-200,
    )

    add_constraint(
        delegation_5,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 6
    # REVOKED DELEGATION
    # ========================================================

    op_6 = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        created_offset=-225,
        completed_offset=-205,
    )

    review_6 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_6.id,
    )

    add_review_history(
        review_6,
        op_6.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-220,
        approval_offset=-210,
    )

    delegation_6 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="VAULT",
        state="REVOKED",
        version=historical_version,
        operation_id=op_6.id,
        issued_offset=-200,
        expiry_offset=100,
        revoked_offset=-180,
    )

    add_constraint(
        delegation_6,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 7
    # CLASSIFICATION LIMIT
    # ========================================================

    op_7 = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        created_offset=-170,
        completed_offset=-150,
    )

    review_7 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_7.id,
    )

    add_review_history(
        review_7,
        op_7.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-165,
        approval_offset=-155,
    )

    delegation_7 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="VAULT",
        state="ACTIVE",
        version=historical_version,
        operation_id=op_7.id,
        issued_offset=-145,
        expiry_offset=100,
    )

    add_constraint(
        delegation_7,
        max_classification=4,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 8
    # OPERATION / DELEGATION MISMATCH
    # ========================================================

    op_8a = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        created_offset=-130,
        completed_offset=-110,
    )

    op_8b = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        created_offset=-125,
        completed_offset=-105,
    )

    review_8 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_8a.id,
    )

    add_review_history(
        review_8,
        op_8a.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-120,
        approval_offset=-115,
    )

    delegation_8 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="VAULT",
        state="ACTIVE",
        version=historical_version,
        operation_id=op_8b.id,
        issued_offset=-100,
        expiry_offset=100,
    )

    add_constraint(
        delegation_8,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 9
    # PROJECT MEMBERSHIP FAILURE
    # ========================================================

    op_9 = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="VAULT",
        subject=analyst.id,
        requested_by=analyst.id,
        created_offset=-90,
        completed_offset=-70,
    )

    review_9 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_9.id,
        subject=analyst.id,
        created_by=analyst.id,
    )

    add_review_history(
        review_9,
        op_9.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-85,
        approval_offset=-75,
    )

    delegation_9 = add_delegation(
        principal=warden.id,
        delegate=analyst.id,
        scope="VAULT",
        state="ACTIVE",
        version=historical_version,
        operation_id=op_9.id,
        issued_offset=-65,
        expiry_offset=100,
    )

    add_constraint(
        delegation_9,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_VAULT",
    )

    # ========================================================
    # DECOY 10
    # NON-VAULT OPERATION
    # ========================================================

    op_10 = add_operation(
        state="COMPLETED",
        version=historical_version,
        scope="PROJECT",
        created_offset=-55,
        completed_offset=-35,
    )

    review_10 = add_review(
        reviewer=nova.id,
        principal=warden.id,
        state="APPROVED",
        version=historical_version,
        operation_id=op_10.id,
    )

    add_review_history(
        review_10,
        op_10.id,
        approved_by=nova.id,
        valid=True,
        created_offset=-50,
        approval_offset=-40,
    )

    delegation_10 = add_delegation(
        principal=warden.id,
        delegate=echo.id,
        scope="PROJECT",
        state="ACTIVE",
        version=historical_version,
        operation_id=op_10.id,
        issued_offset=-30,
        expiry_offset=100,
    )

    add_constraint(
        delegation_10,
        max_classification=5,
        required_project_membership=True,
        allowed_operation="READ_PROJECT",
    )

    # ========================================================
    # ADDITIONAL AMBIGUOUS DELEGATIONS
    # ========================================================

    for scope, operation_name in [
        ("PROJECT", "READ_PROJECT"),
        ("CONTROL", "READ_CONTROL"),
        ("ARCHIVE", "READ_ARCHIVE"),
        ("AUDIT", "READ_AUDIT"),
        ("PROJECT", "LIST_PROJECT"),
        ("CONTROL", "LIST_CONTROL"),
    ]:

        delegation = add_delegation(
            principal=warden.id,
            delegate=echo.id,
            scope=scope,
            state="ACTIVE",
            version=historical_version,
            operation_id=None,
            issued_offset=-20,
            expiry_offset=200,
        )

        add_constraint(
            delegation,
            max_classification=5,
            required_project_membership=True,
            allowed_operation=operation_name,
        )

    # ========================================================
    # GENUINE CAPABILITY
    # ========================================================

    world.capabilities.append(
        Capability(
            id=new_id("cap"),
            operation_id=real_operation.id,
            subject=echo.id,
            resource_id=blacksite_resource.id,
            scope="VAULT",
            policy_version=historical_version,
            issued_at=iso_time(-170),
            expires_at=iso_time(180),
            state="ACTIVE",
            token_digest=token_hex(32),
        )
    )

    # ========================================================
    # CAPABILITY DECOYS
    # ========================================================

    capability_specs = [
        (
            op_1.id,
            echo.id,
            "VAULT",
            historical_version,
            "ACTIVE",
            -440,
            500,
        ),
        (
            op_2.id,
            echo.id,
            "VAULT",
            historical_version,
            "ACTIVE",
            -395,
            500,
        ),
        (
            op_3.id,
            echo.id,
            "VAULT",
            wrong_version,
            "ACTIVE",
            -335,
            500,
        ),
        (
            op_5.id,
            echo.id,
            "VAULT",
            historical_version,
            "EXPIRED",
            -245,
            -200,
        ),
        (
            op_6.id,
            echo.id,
            "VAULT",
            historical_version,
            "REVOKED",
            -200,
            500,
        ),
        (
            op_7.id,
            echo.id,
            "VAULT",
            historical_version,
            "ACTIVE",
            -145,
            500,
        ),
        (
            op_10.id,
            echo.id,
            "PROJECT",
            historical_version,
            "ACTIVE",
            -30,
            500,
        ),
    ]

    for (
        operation_id,
        subject,
        scope,
        version,
        state,
        issued_offset,
        expiry_offset,
    ) in capability_specs:

        world.capabilities.append(
            Capability(
                id=new_id("cap"),
                operation_id=operation_id,
                subject=subject,
                resource_id=blacksite_resource.id,
                scope=scope,
                policy_version=version,
                issued_at=iso_time(issued_offset),
                expires_at=iso_time(expiry_offset),
                state=state,
                token_digest=token_hex(32),
            )
        )


    # ========================================================
    # V2 AUDIT EVENT GENERATION
    # ========================================================
    #
    # The audit system is intentionally noisy.
    #
    # Some operations have incomplete histories.
    # Some have explicit denials.
    # Some have inconsistent correlation sequences.
    # Some have unrelated correlation types.
    #
    # Only the intended operation has a complete, ordered,
    # internally consistent authorization trace.
    # ========================================================

    def add_audit_event(
        *,
        operation_id,
        event_type,
        actor,
        subject,
        result,
        message,
        occurred_offset,
    ):
        event = AuditEvent(
            id=new_id("audit"),
            event_type=event_type,
            actor=actor,
            subject=subject,
            resource_id=blacksite_resource.id,
            result=result,
            message=message,
            operation_id=operation_id,
            occurred_at=iso_time(occurred_offset),
        )

        world.audit_events.append(event)

        return event

    def add_correlation(
        *,
        operation_id,
        event,
        correlation_type,
        sequence_number,
    ):
        world.audit_correlations.append(
            AuditCorrelation(
                id=new_id("corr"),
                operation_id=operation_id,
                audit_event_id=event.id,
                correlation_type=correlation_type,
                sequence_number=sequence_number,
            )
        )

    # ========================================================
    # REAL OPERATION
    # ========================================================

    real_audit_trace = [
        (
            "AUTH_REQUEST",
            "ALLOW",
            "authorization request accepted",
            -240,
        ),
        (
            "POLICY_EVALUATION",
            "ALLOW",
            "policy revision resolved",
            -225,
        ),
        (
            "REVIEW_APPROVAL",
            "ALLOW",
            "review approval confirmed",
            -210,
        ),
        (
            "DELEGATION_CHECK",
            "ALLOW",
            "delegation constraints satisfied",
            -195,
        ),
        (
            "CAPABILITY_ISSUED",
            "ALLOW",
            "capability issued",
            -180,
        ),
    ]

    for sequence, (
        event_type,
        result,
        message,
        occurred_offset,
    ) in enumerate(
        real_audit_trace,
        start=1,
    ):

        event = add_audit_event(
            operation_id=real_operation.id,
            event_type=event_type,
            actor=echo.id,
            subject=echo.id,
            result=result,
            message=message,
            occurred_offset=occurred_offset,
        )

        add_correlation(
            operation_id=real_operation.id,
            event=event,
            correlation_type="OPERATION_TRACE",
            sequence_number=sequence,
        )

    # ========================================================
    # DECOY AUDIT TRACES
    # ========================================================

    decoy_traces = [
        (
            op_1,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("DELEGATION_CHECK", "ALLOW"),
                ("CAPABILITY_ISSUED", "ALLOW"),
            ],
        ),
        (
            op_2,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "DENY"),
                ("REVIEW_APPROVAL", "ALLOW"),
                ("DELEGATION_CHECK", "ALLOW"),
            ],
        ),
        (
            op_3,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("REVIEW_APPROVAL", "ALLOW"),
                ("DELEGATION_CHECK", "DENY"),
            ],
        ),
        (
            op_4,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("REVIEW_APPROVAL", "ALLOW"),
                ("DELEGATION_CHECK", "ALLOW"),
                ("CAPABILITY_ISSUED", "DENY"),
            ],
        ),
        (
            op_5,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("REVIEW_APPROVAL", "ALLOW"),
                ("DELEGATION_CHECK", "DENY"),
                ("CAPABILITY_ISSUED", "DENY"),
            ],
        ),
        (
            op_6,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("REVIEW_APPROVAL", "ALLOW"),
                ("DELEGATION_REVOKED", "DENY"),
                ("CAPABILITY_ISSUED", "DENY"),
            ],
        ),
        (
            op_7,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("REVIEW_APPROVAL", "ALLOW"),
                ("DELEGATION_CHECK", "DENY"),
            ],
        ),
        (
            op_8a,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("REVIEW_APPROVAL", "ALLOW"),
            ],
        ),
        (
            op_8b,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("DELEGATION_CHECK", "ALLOW"),
            ],
        ),
        (
            op_9,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("REVIEW_APPROVAL", "ALLOW"),
                ("DELEGATION_CHECK", "ALLOW"),
                ("CAPABILITY_ISSUED", "ALLOW"),
            ],
        ),
        (
            op_10,
            [
                ("AUTH_REQUEST", "ALLOW"),
                ("POLICY_EVALUATION", "ALLOW"),
                ("REVIEW_APPROVAL", "ALLOW"),
                ("DELEGATION_CHECK", "ALLOW"),
                ("CAPABILITY_ISSUED", "ALLOW"),
            ],
        ),
    ]

    for trace_index, (
        operation_ref,
        trace,
    ) in enumerate(decoy_traces):

        for sequence, (
            event_type,
            result,
        ) in enumerate(
            trace,
            start=1,
        ):

            event = add_audit_event(
                operation_id=operation_ref.id,
                event_type=event_type,
                actor=echo.id,
                subject=operation_ref.subject,
                result=result,
                message="authorization event recorded",
                occurred_offset=(
                    -700
                    + trace_index * 25
                    + sequence * 4
                ),
            )

            # ------------------------------------------------
            # Correlation defects
            # ------------------------------------------------

            if operation_ref is op_4 and sequence == 4:

                correlation_type = "OPERATION_TRACE"
                correlation_sequence = sequence + 2

            elif operation_ref is op_10:

                correlation_type = "SECONDARY_TRACE"
                correlation_sequence = sequence

            else:

                correlation_type = "OPERATION_TRACE"
                correlation_sequence = sequence

            add_correlation(
                operation_id=operation_ref.id,
                event=event,
                correlation_type=correlation_type,
                sequence_number=correlation_sequence,
            )

    # ========================================================
    # ADDITIONAL REALISTIC NOISE
    # ========================================================

    noise_events = [
        ("SESSION_REFRESH", "ALLOW"),
        ("RESOURCE_LOOKUP", "ALLOW"),
        ("POLICY_CACHE_READ", "ALLOW"),
        ("METADATA_READ", "ALLOW"),
        ("ACCESS_ATTEMPT", "DENY"),
        ("SESSION_REFRESH", "ALLOW"),
        ("RESOURCE_LOOKUP", "ALLOW"),
        ("POLICY_CACHE_READ", "ALLOW"),
        ("ACCESS_ATTEMPT", "DENY"),
        ("METADATA_READ", "ALLOW"),
        ("RESOURCE_LOOKUP", "ALLOW"),
        ("SESSION_REFRESH", "ALLOW"),
        ("POLICY_CACHE_READ", "ALLOW"),
        ("METADATA_READ", "ALLOW"),
        ("ACCESS_ATTEMPT", "DENY"),
    ]

    for index, (
        event_type,
        result,
    ) in enumerate(noise_events):

        add_audit_event(
            operation_id=None,
            event_type=event_type,
            actor=echo.id,
            subject=echo.id,
            result=result,
            message="system activity recorded",
            occurred_offset=-50 + index * 2,
        )


    return world





# ============================================================
# V2 AUTHORIZATION CHAIN VALIDATION
# ============================================================

def validate_authorization_chains(world: World) -> bool:
    """
    Prove that the generated world contains exactly one
    internally coherent BLACKSITE VAULT authorization chain.
    """

    blacksite_resource = next(
        r for r in world.resources
        if r.name == "BLACKSITE_RESOURCE"
    )

    policy = next(
        p for p in world.policies
        if p.id == blacksite_resource.policy_id
    )

    valid_candidates = []

    for operation in world.authorization_operations:

        if operation.resource_id != blacksite_resource.id:
            continue

        if operation.requested_scope != "VAULT":
            continue

        if operation.state != "COMPLETED":
            continue

        # ----------------------------------------------------
        # Matching review
        # ----------------------------------------------------

        reviews = [
            review
            for review in world.reviews
            if (
                review.resource_id
                == blacksite_resource.id
                and review.operation_id == operation.id
                and review.subject == operation.subject
                and review.policy_version
                == operation.policy_version
                and review.state == "APPROVED"
            )
        ]

        if len(reviews) != 1:
            continue

        review = reviews[0]

        # ----------------------------------------------------
        # Review history
        # ----------------------------------------------------

        events = [
            event
            for event in world.review_events
            if (
                event.review_id == review.id
                and event.operation_id == operation.id
            )
        ]

        events = sorted(
            events,
            key=lambda event: event.occurred_at
        )

        if len(events) != 2:
            continue

        if events[0].new_state != "PENDING":
            continue

        if events[1].previous_state != "PENDING":
            continue

        if events[1].new_state != "APPROVED":
            continue

        if events[0].occurred_at >= events[1].occurred_at:
            continue

        if events[1].actor != review.reviewer:
            continue

        # ----------------------------------------------------
        # Separation of duties
        # ----------------------------------------------------

        if review.reviewer == review.principal:
            continue

        # ----------------------------------------------------
        # Policy revision
        # ----------------------------------------------------

        policy_version = next(
            (
                version
                for version in world.policy_versions
                if (
                    version.policy_id == policy.id
                    and version.version
                    == operation.policy_version
                )
            ),
            None,
        )

        if policy_version is None:
            continue

        if policy_version.status != "SUPERSEDED":
            continue

        if policy_version.version != policy.version - 1:
            continue

        if policy_version.scope != "VAULT":
            continue

        # ----------------------------------------------------
        # Matching delegation
        # ----------------------------------------------------

        delegations = [
            delegation
            for delegation in world.delegations
            if (
                delegation.resource_id
                == blacksite_resource.id
                and delegation.operation_id
                == operation.id
                and delegation.delegate
                == operation.subject
                and delegation.principal
                == review.principal
                and delegation.scope == "VAULT"
                and delegation.policy_version
                == operation.policy_version
                and delegation.state == "ACTIVE"
            )
        ]

        if len(delegations) != 1:
            continue

        delegation = delegations[0]

        # ----------------------------------------------------
        # Temporal delegation validity
        # ----------------------------------------------------

        if delegation.issued_at is None:
            continue

        if delegation.expires_at is None:
            continue

        if not (
            operation.created_at
            <= delegation.issued_at
            <= operation.completed_at
            <= delegation.expires_at
        ):
            continue

        if delegation.revoked_at is not None:
            continue

        # ----------------------------------------------------
        # Delegation constraints
        # ----------------------------------------------------

        constraints = [
            constraint
            for constraint in world.delegation_constraints
            if constraint.delegation_id == delegation.id
        ]

        if len(constraints) != 1:
            continue

        constraint = constraints[0]

        if (
            constraint.max_classification is not None
            and blacksite_resource.classification
            > constraint.max_classification
        ):
            continue

        if not constraint.required_project_membership:
            continue

        project = next(
            p for p in world.projects
            if p.id == blacksite_resource.project_id
        )

        if operation.subject not in project.members:
            continue

        if constraint.allowed_operation != "READ_VAULT":
            continue

        # ----------------------------------------------------
        # Audit correlation
        # ----------------------------------------------------

        correlations = [
            correlation
            for correlation in world.audit_correlations
            if correlation.operation_id == operation.id
        ]

        correlations = sorted(
            correlations,
            key=lambda correlation:
                correlation.sequence_number
        )

        if len(correlations) != 5:
            continue

        if [
            correlation.sequence_number
            for correlation in correlations
        ] != [1, 2, 3, 4, 5]:
            continue

        if any(
            correlation.correlation_type
            != "OPERATION_TRACE"
            for correlation in correlations
        ):
            continue

        audit_events = []

        try:

            for correlation in correlations:

                event = next(
                    event
                    for event in world.audit_events
                    if event.id
                    == correlation.audit_event_id
                )

                if event.operation_id != operation.id:
                    raise ValueError

                audit_events.append(event)

        except (StopIteration, ValueError):

            continue

        expected_events = [
            "AUTH_REQUEST",
            "POLICY_EVALUATION",
            "REVIEW_APPROVAL",
            "DELEGATION_CHECK",
            "CAPABILITY_ISSUED",
        ]

        if [
            event.event_type
            for event in audit_events
        ] != expected_events:
            continue

        if any(
            event.result != "ALLOW"
            for event in audit_events
        ):
            continue

        if any(
            audit_events[index].occurred_at
            >= audit_events[index + 1].occurred_at
            for index in range(
                len(audit_events) - 1
            )
        ):
            continue

        # ----------------------------------------------------
        # Capability
        # ----------------------------------------------------

        capabilities = [
            capability
            for capability in world.capabilities
            if (
                capability.operation_id == operation.id
                and capability.resource_id
                == blacksite_resource.id
                and capability.subject
                == operation.subject
                and capability.scope == "VAULT"
                and capability.policy_version
                == operation.policy_version
                and capability.state == "ACTIVE"
            )
        ]

        if len(capabilities) != 1:
            continue

        capability = capabilities[0]

        # Capability is issued after operation completion.
        if capability.issued_at < operation.completed_at:
            continue

        if capability.expires_at <= capability.issued_at:
            continue

        valid_candidates.append(operation)

    assert len(valid_candidates) == 1, (
        "expected exactly one coherent BLACKSITE "
        f"authorization chain, found {len(valid_candidates)}"
    )

    return True


# ============================================================
# WORLD VALIDATION
# ============================================================

def validate_world(world: World) -> bool:
    """
    Verify that the generated world contains the required
    BLACKSITE objects and relationships.
    """

    assert len(world.users) >= 8
    assert len(world.projects) >= 7
    assert len(world.resources) >= 7
    assert len(world.policies) >= 7

    blacksite_projects = [
        p for p in world.projects
        if p.name == "BLACKSITE"
    ]

    assert len(blacksite_projects) == 1

    blacksite = blacksite_projects[0]

    blacksite_resources = [
        r for r in world.resources
        if r.project_id == blacksite.id
    ]

    assert len(blacksite_resources) == 1

    target_resource = blacksite_resources[0]

    # --------------------------------------------------------
    # V2 AUTHORIZATION OBJECTS
    # --------------------------------------------------------

    target_reviews = [
        r for r in world.reviews
        if r.resource_id == target_resource.id
        and r.state == "APPROVED"
    ]

    assert len(target_reviews) >= 1

    target_delegations = [
        d for d in world.delegations
        if d.resource_id == target_resource.id
        and d.scope == "VAULT"
        and d.state == "ACTIVE"
    ]

    assert len(target_delegations) >= 1

    target_operations = [
        op for op in world.authorization_operations
        if op.resource_id == target_resource.id
        and op.state == "COMPLETED"
    ]

    assert len(target_operations) >= 1

    target_constraints = [
        c for c in world.delegation_constraints
        if any(
            c.delegation_id == d.id
            for d in target_delegations
        )
    ]

    assert len(target_constraints) >= 1

    target_capabilities = [
        c for c in world.capabilities
        if c.resource_id == target_resource.id
    ]

    assert len(target_capabilities) >= 1

    return True


# ============================================================
# DEVELOPMENT DISPLAY
# ============================================================

def print_world(world: World) -> None:

    print("=" * 75)
    print("AEGIS BLACKSITE — CONTROLLED RANDOM WORLD")
    print("=" * 75)

    print()
    print(f"INSTANCE : {world.instance_id}")
    print(f"FLAG     : {world.flag_secret}")

    print()
    print(f"USERS          : {len(world.users)}")
    print(f"ORGANIZATIONS  : {len(world.organizations)}")
    print(f"PROJECTS       : {len(world.projects)}")
    print(f"POLICIES       : {len(world.policies)}")
    print(f"RESOURCES      : {len(world.resources)}")
    print(f"REVIEWS        : {len(world.reviews)}")
    print(f"DELEGATIONS    : {len(world.delegations)}")
    print(f"AUDIT EVENTS   : {len(world.audit_events)}")

    print()
    print("PROJECTS")
    print("-" * 75)

    for project in world.projects:
        print(
            f"{project.name:<15}"
            f"R{project.classification}  "
            f"{project.id}"
        )

    print()
    print("RESOURCES")
    print("-" * 75)

    for resource in world.resources:
        print(
            f"{resource.name:<30}"
            f"{resource.alias:<12}"
            f"{resource.id}"
        )

    print()
    print("REVIEWS")
    print("-" * 75)

    for review in world.reviews:
        print(
            f"{review.id:<24}"
            f"{review.state:<12}"
            f"policy=v{review.policy_version}"
        )

    print()
    print("DELEGATIONS")
    print("-" * 75)

    for delegation in world.delegations:
        print(
            f"{delegation.id:<24}"
            f"{delegation.state:<12}"
            f"{delegation.scope:<10}"
            f"policy=v{delegation.policy_version}"
        )

    print()
    print("=" * 75)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    generated_world = build_world()

    validate_world(generated_world)

    print_world(generated_world)

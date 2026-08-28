
from dataclasses import dataclass
from datetime import datetime, timezone

from authz.graph import (
    AuthorityGraph,
    User,
    Resource,
    Policy,
    ReviewRequest,
    Delegation,
)


# ============================================================
# V2 AUTHORIZATION ENGINE
# ============================================================

@dataclass
class AuthorizationCheck:
    name: str
    passed: bool
    reason: str


@dataclass
class AuthorizationDecision:
    allowed: bool
    reason: str
    checks: list[AuthorizationCheck]


class PolicyEngine:

    def __init__(self, graph: AuthorityGraph):
        self.graph = graph

    # ========================================================
    # INTERNAL HELPERS
    # ========================================================

    @staticmethod
    def _check(
        name: str,
        passed: bool,
        reason: str,
    ) -> AuthorizationCheck:

        return AuthorizationCheck(
            name=name,
            passed=passed,
            reason=reason,
        )

    @staticmethod
    def _parse_time(value: str | None):
        if not value:
            return None

        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

    # ========================================================
    # DIRECT RESOURCE ACCESS
    # ========================================================

    def can_read(
        self,
        actor: User,
        resource: Resource,
    ) -> AuthorizationDecision:

        checks = []

        checks.append(
            self._check(
                "identity",
                actor is not None,
                "authenticated identity required",
            )
        )

        checks.append(
            self._check(
                "resource",
                resource is not None,
                "resource must exist",
            )
        )

        if actor is None or resource is None:

            return AuthorizationDecision(
                False,
                "identity or resource unavailable",
                checks,
            )

        policy = self.graph.get_resource_policy(
            resource.id
        )

        if policy is None:

            checks.append(
                self._check(
                    "policy",
                    False,
                    "resource policy not found",
                )
            )

            return AuthorizationDecision(
                False,
                "resource policy not found",
                checks,
            )

        checks.append(
            self._check(
                "clearance",
                actor.clearance >= policy.required_clearance,
                "clearance requirement evaluated",
            )
        )

        checks.append(
            self._check(
                "role",
                actor.role == policy.required_role,
                "role requirement evaluated",
            )
        )

        project = self.graph.get_resource_project(
            resource.id
        )

        member = False

        if project is not None:

            member = self.graph.is_project_member(
                actor.id,
                project.id,
            )

        checks.append(
            self._check(
                "project_membership",
                member,
                "project membership evaluated",
            )
        )

        failed = [
            check
            for check in checks
            if not check.passed
        ]

        if failed:

            return AuthorizationDecision(
                False,
                failed[0].reason,
                checks,
            )

        return AuthorizationDecision(
            True,
            "direct authorization successful",
            checks,
        )

    # ========================================================
    # VAULT AUTHORIZATION
    # ========================================================

    def can_enter_vault(
        self,
        actor: User,
        resource_id: str,
        operation_id: str | None = None,
    ) -> AuthorizationDecision:

        checks: list[AuthorizationCheck] = []

        # ----------------------------------------------------
        # IDENTITY
        # ----------------------------------------------------

        checks.append(
            self._check(
                "identity",
                actor is not None,
                "authenticated identity required",
            )
        )

        if actor is None:

            return AuthorizationDecision(
                False,
                "authenticated identity required",
                checks,
            )

        # ----------------------------------------------------
        # RESOURCE
        # ----------------------------------------------------

        resource = self.graph.get_resource(
            resource_id
        )

        checks.append(
            self._check(
                "resource",
                resource is not None,
                "target resource must exist",
            )
        )

        if resource is None:

            return AuthorizationDecision(
                False,
                "target resource not found",
                checks,
            )

        # ----------------------------------------------------
        # CURRENT POLICY
        # ----------------------------------------------------

        policy = self.graph.get_resource_policy(
            resource.id
        )

        checks.append(
            self._check(
                "current_policy",
                policy is not None,
                "current resource policy must exist",
            )
        )

        if policy is None:

            return AuthorizationDecision(
                False,
                "current policy unavailable",
                checks,
            )

        # ----------------------------------------------------
        # CURRENT CLEARANCE
        # ----------------------------------------------------

        checks.append(
            self._check(
                "clearance",
                actor.clearance >= policy.required_clearance,
                "clearance requirement",
            )
        )

        # ----------------------------------------------------
        # CURRENT ROLE
        # ----------------------------------------------------

        checks.append(
            self._check(
                "role",
                actor.role == policy.required_role,
                "role requirement",
            )
        )

        # ----------------------------------------------------
        # PROJECT MEMBERSHIP
        # ----------------------------------------------------

        project = self.graph.get_resource_project(
            resource.id
        )

        project_member = False

        if project is not None:

            project_member = (
                self.graph.is_project_member(
                    actor.id,
                    project.id,
                )
            )

        checks.append(
            self._check(
                "project_membership",
                project_member,
                "project membership required",
            )
        )

        # ----------------------------------------------------
        # FAIL FAST FOR CURRENT POLICY
        # ----------------------------------------------------

        current_failures = [
            c for c in checks
            if not c.passed
        ]

        if current_failures:

            return AuthorizationDecision(
                False,
                current_failures[0].reason,
                checks,
            )

        # ----------------------------------------------------
        # OPTIONAL OPERATION VALIDATION
        # ----------------------------------------------------

        if operation_id is None:

            checks.append(
                self._check(
                    "operation",
                    False,
                    "authorization operation required",
                )
            )

            return AuthorizationDecision(
                False,
                "authorization operation required",
                checks,
            )

        operation = self.graph.get_authorization_operation(
            operation_id
        )

        checks.append(
            self._check(
                "operation",
                operation is not None,
                "authorization operation exists",
            )
        )

        if operation is None:

            return AuthorizationDecision(
                False,
                "authorization operation not found",
                checks,
            )

        # ----------------------------------------------------
        # OPERATION BINDING
        # ----------------------------------------------------

        operation_resource_match = (
            operation.resource_id == resource.id
        )

        checks.append(
            self._check(
                "operation_resource",
                operation_resource_match,
                "operation resource binding",
            )
        )

        operation_subject_match = (
            operation.subject == actor.id
        )

        checks.append(
            self._check(
                "operation_subject",
                operation_subject_match,
                "operation subject binding",
            )
        )

        scope_match = (
            operation.requested_scope == "VAULT"
        )

        checks.append(
            self._check(
                "operation_scope",
                scope_match,
                "operation scope",
            )
        )

        state_ok = (
            operation.state == "COMPLETED"
        )

        checks.append(
            self._check(
                "operation_state",
                state_ok,
                "operation state",
            )
        )

        # ----------------------------------------------------
        # FINAL RESULT
        # ----------------------------------------------------

        failures = [
            c for c in checks
            if not c.passed
        ]

        if failures:

            return AuthorizationDecision(
                False,
                failures[0].reason,
                checks,
            )

        return AuthorizationDecision(
            True,
            "vault authorization successful",
            checks,
        )



    # ========================================================
    # V2 OPERATION RECONSTRUCTION
    # ========================================================

    def evaluate_operation(
        self,
        actor,
        operation_id: str,
    ) -> AuthorizationDecision:

        checks = []

        def add(name, passed, reason):
            checks.append(
                self._check(
                    name,
                    passed,
                    reason,
                )
            )

        # ----------------------------------------------------
        # Identity
        # ----------------------------------------------------

        add(
            "identity",
            actor is not None,
            "authenticated identity",
        )

        if actor is None:
            return AuthorizationDecision(
                False,
                "authenticated identity required",
                checks,
            )

        # ----------------------------------------------------
        # Operation
        # ----------------------------------------------------

        operation = self.graph.get_authorization_operation(
            operation_id
        )

        add(
            "operation_exists",
            operation is not None,
            "authorization operation exists",
        )

        if operation is None:
            return AuthorizationDecision(
                False,
                "authorization operation not found",
                checks,
            )

        add(
            "operation_subject",
            operation["subject"] == actor.id,
            "operation is bound to authenticated subject",
        )

        add(
            "operation_requester",
            operation["requested_by"] == actor.id,
            "operation requester matches actor",
        )

        add(
            "operation_state",
            operation["state"] == "COMPLETED",
            "operation reached completed state",
        )

        add(
            "operation_scope",
            operation["requested_scope"] == "VAULT",
            "operation requests vault scope",
        )

        if operation["state"] != "COMPLETED":
            return AuthorizationDecision(
                False,
                "operation is not complete",
                checks,
            )

        # ----------------------------------------------------
        # Resource
        # ----------------------------------------------------

        resource = self.graph.get_resource(
            operation["resource_id"]
        )

        add(
            "resource_exists",
            resource is not None,
            "operation resource exists",
        )

        if resource is None:
            return AuthorizationDecision(
                False,
                "operation resource not found",
                checks,
            )

        add(
            "resource_target",
            resource.name == "BLACKSITE_RESOURCE",
            "target resource is BLACKSITE",
        )

        # ----------------------------------------------------
        # Project membership
        # ----------------------------------------------------

        project = self.graph.get_resource_project(
            resource.id
        )

        membership = False

        if project is not None:
            membership = self.graph.is_project_member(
                actor.id,
                project.id,
            )

        add(
            "project_membership",
            membership,
            "actor belongs to resource project",
        )

        # ----------------------------------------------------
        # Current policy
        # ----------------------------------------------------

        current_policy = self.graph.get_resource_policy(
            resource.id
        )

        add(
            "current_policy",
            current_policy is not None,
            "resource has current policy",
        )

        if current_policy is None:
            return AuthorizationDecision(
                False,
                "resource policy not found",
                checks,
            )

        add(
            "current_scope",
            current_policy.scope == "VAULT",
            "current policy governs vault scope",
        )

        # ----------------------------------------------------
        # Historical policy revision
        # ----------------------------------------------------

        historical_policy = self.graph.get_policy_version(
            resource.policy_id,
            operation["policy_version"],
        )

        add(
            "historical_policy",
            historical_policy is not None,
            "historical policy revision exists",
        )

        if historical_policy is None:
            return AuthorizationDecision(
                False,
                "historical policy revision not found",
                checks,
            )

        add(
            "historical_scope",
            historical_policy["scope"] == "VAULT",
            "historical revision permits vault scope",
        )

        add(
            "historical_revision",
            historical_policy["version"]
            == current_policy.version - 1,
            "operation uses immediately preceding policy revision",
        )

        # ----------------------------------------------------
        # Delegate identity
        # ----------------------------------------------------
        #
        # The historical policy governs the authority that
        # approved/issued the authorization. The delegated
        # subject is intentionally evaluated separately.
        #
        # Direct current-policy access remains handled by
        # can_read() / can_enter_vault().
        # ----------------------------------------------------

        add(
            "delegated_subject",
            actor.id == operation["subject"],
            "authenticated actor is delegated subject",
        )

        # ----------------------------------------------------
        # Matching review
        # ----------------------------------------------------

        candidate_reviews = [
            review
            for review in self.graph.get_reviews_for_resource(
                resource.id
            )
            if (
                review.policy_version
                == operation["policy_version"]
                and review.subject
                == operation["subject"]
                and review.principal
                != review.reviewer
            )
        ]

        bound_reviews = []

        for review in candidate_reviews:

            events = self.graph.get_review_events(
                review.id
            )

            operation_ids = {
                event["operation_id"]
                for event in events
                if event["operation_id"] is not None
            }

            if operation_id in operation_ids:
                bound_reviews.append(review)

        add(
            "review_binding",
            len(bound_reviews) == 1,
            "exactly one review is bound to operation",
        )

        if len(bound_reviews) != 1:
            return AuthorizationDecision(
                False,
                "review chain is ambiguous or invalid",
                checks,
            )

        review = bound_reviews[0]

        add(
            "review_state",
            review.state == "APPROVED",
            "review is approved",
        )

        add(
            "review_principal",
            review.principal is not None,
            "review contains a principal",
        )

        # ----------------------------------------------------
        # Review history
        # ----------------------------------------------------

        review_events = self.graph.get_review_events(
            review.id
        )

        review_events = sorted(
            review_events,
            key=lambda row: row["occurred_at"],
        )

        add(
            "review_event_count",
            len(review_events) == 2,
            "review has expected lifecycle events",
        )

        review_history_valid = (
            len(review_events) == 2
            and review_events[0]["new_state"] == "PENDING"
            and review_events[1]["previous_state"] == "PENDING"
            and review_events[1]["new_state"] == "APPROVED"
            and review_events[0]["operation_id"] == operation_id
            and review_events[1]["operation_id"] == operation_id
            and review_events[0]["occurred_at"]
            < review_events[1]["occurred_at"]
        )

        add(
            "review_history",
            review_history_valid,
            "review lifecycle reconstructs cleanly",
        )

        reviewer_authority = False

        if review.reviewer:

            reviewer = self.graph.get_user(
                review.reviewer
            )

            if reviewer is not None:

                reviewer_authority = (
                    reviewer.clearance
                    >= historical_policy[
                        "required_clearance"
                    ]
                    and reviewer.role
                    == historical_policy[
                        "required_role"
                    ]
                )

        add(
            "reviewer_authority",
            reviewer_authority,
            "reviewer satisfies historical policy requirement",
        )

        # ----------------------------------------------------
        # Principal
        # ----------------------------------------------------

        principal = self.graph.get_user(
            review.principal
        )

        add(
            "principal_exists",
            principal is not None,
            "delegation principal exists",
        )

        if principal is not None:

            # The delegation principal is an independent authority
            # from the reviewer. The historical policy describes the
            # authority required to approve the review; the principal
            # must instead possess a strong enough administrative
            # authority to issue the delegation.
            add(
                "principal_clearance",
                principal.clearance >= current_policy.required_clearance,
                "principal satisfies current clearance threshold",
            )

            add(
                "principal_role",
                principal.role == current_policy.required_role,
                "principal satisfies current administrative role",
            )

        # ----------------------------------------------------
        # Delegation
        # ----------------------------------------------------

        delegations = [
            delegation
            for delegation
            in self.graph.get_delegations_for_resource(
                resource.id
            )
            if (
                delegation.delegate
                == operation["subject"]
                and delegation.principal
                == review.principal
                and delegation.scope == "VAULT"
                and delegation.policy_version
                == operation["policy_version"]
                and delegation.operation_id
                == operation_id
            )
        ]

        add(
            "delegation_binding",
            len(delegations) == 1,
            "exactly one matching delegation found",
        )

        if len(delegations) != 1:
            return AuthorizationDecision(
                False,
                "delegation chain is ambiguous or invalid",
                checks,
            )

        delegation = delegations[0]

        add(
            "delegation_state",
            delegation.state == "ACTIVE",
            "delegation is active",
        )

        # ----------------------------------------------------
        # Temporal validity
        # ----------------------------------------------------

        created_at = self._parse_time(
            operation["created_at"]
        )

        issued_at = self._parse_time(
            delegation.issued_at
        )

        expires_at = self._parse_time(
            delegation.expires_at
        )

        completed_at = self._parse_time(
            operation["completed_at"]
        )

        temporal_valid = (
            created_at is not None
            and issued_at is not None
            and expires_at is not None
            and completed_at is not None
            and created_at
            <= issued_at
            <= completed_at
            <= expires_at
        )

        add(
            "delegation_time",
            temporal_valid,
            "delegation covers operation lifetime",
        )

        add(
            "delegation_revocation",
            delegation.revoked_at is None,
            "delegation has not been revoked",
        )

        # ----------------------------------------------------
        # Delegation constraints
        # ----------------------------------------------------

        constraints = (
            self.graph.get_delegation_constraints(
                delegation.id
            )
        )

        constraint_valid = False

        for constraint in constraints:

            classification_ok = (
                constraint["max_classification"]
                is None
                or resource.classification
                <= constraint["max_classification"]
            )

            membership_ok = (
                not constraint[
                    "required_project_membership"
                ]
                or membership
            )

            operation_ok = (
                constraint["allowed_operation"]
                == "READ_VAULT"
            )

            if (
                classification_ok
                and membership_ok
                and operation_ok
            ):
                constraint_valid = True
                break

        add(
            "delegation_constraints",
            constraint_valid,
            "delegation constraints are satisfied",
        )

        # ----------------------------------------------------
        # Audit correlation
        # ----------------------------------------------------

        correlations = (
            self.graph.get_audit_correlations(
                operation_id
            )
        )

        correlations = sorted(
            correlations,
            key=lambda row: row["sequence_number"],
        )

        add(
            "audit_count",
            len(correlations) == 5,
            "operation has complete audit trace",
        )

        correlation_valid = (
            len(correlations) == 5
            and [
                row["sequence_number"]
                for row in correlations
            ]
            == [1, 2, 3, 4, 5]
            and all(
                row["correlation_type"]
                == "OPERATION_TRACE"
                for row in correlations
            )
        )

        add(
            "audit_correlation",
            correlation_valid,
            "audit correlation sequence is coherent",
        )

        # ----------------------------------------------------
        # Capability
        # ----------------------------------------------------

        capabilities = (
            self.graph.get_capabilities_for_operation(
                operation_id
            )
        )

        active_capabilities = []

        for capability in capabilities:

            capability_issued = self._parse_time(
                capability["issued_at"]
            )

            capability_expires = self._parse_time(
                capability["expires_at"]
            )

            capability_valid = (
                capability["state"] == "ACTIVE"
                and capability["subject"]
                == actor.id
                and capability["resource_id"]
                == resource.id
                and capability["scope"]
                == "VAULT"
                and capability["policy_version"]
                == operation["policy_version"]
                and capability_issued is not None
                and capability_expires is not None
                and (
                    operation["completed_at"]
                    <= capability["issued_at"]
                )
                and capability_expires
                > capability_issued
            )

            if capability_valid:
                active_capabilities.append(
                    capability
                )

        add(
            "capability",
            len(active_capabilities) == 1,
            "exactly one valid capability is bound to operation",
        )

        # ----------------------------------------------------
        # Final result
        # ----------------------------------------------------

        failures = [
            check
            for check in checks
            if not check.passed
        ]

        if failures:

            return AuthorizationDecision(
                False,
                failures[0].reason,
                checks,
            )

        return AuthorizationDecision(
            True,
            "authorization operation reconstructed successfully",
            checks,
        )


# ============================================================
# DEVELOPMENT TEST
# ============================================================

if __name__ == "__main__":

    graph = AuthorityGraph()

    engine = PolicyEngine(
        graph
    )

    echo = graph.get_user_by_username(
        "echo"
    )

    resource = graph.get_resource(
        next(
            r.id
            for r in (
                graph.get_all_resources()
            )
            if r.name == "BLACKSITE_RESOURCE"
        )
    )

    if echo is None or resource is None:

        print(
            "Unable to load development test objects."
        )

    else:

        decision = engine.can_read(
            echo,
            resource,
        )

        print("=" * 70)
        print("BLACKSITE — V2 POLICY ENGINE")
        print("=" * 70)

        print(
            "Allowed:",
            decision.allowed,
        )

        print(
            "Reason:",
            decision.reason,
        )

        print()
        print("AUTHORIZATION TRACE")

        for check in decision.checks:

            mark = (
                "PASS"
                if check.passed
                else "FAIL"
            )

            print(
                f"[{mark}] "
                f"{check.name:<24} "
                f"{check.reason}"
            )

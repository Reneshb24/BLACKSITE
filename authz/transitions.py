
from dataclasses import dataclass

from authz.graph import AuthorityGraph
from authz.policy import PolicyEngine


# ============================================================
# V2 STATE MACHINE
# ============================================================

@dataclass
class TransitionDecision:
    success: bool
    previous_state: str
    new_state: str
    reason: str


class StateMachine:

    REVIEW_TRANSITIONS = {
        "DRAFT": {
            "submit": "PENDING",
        },
        "PENDING": {
            "approve": "APPROVED",
            "reject": "REJECTED",
            "expire": "EXPIRED",
        },
        "APPROVED": {
            "consume": "CONSUMED",
            "revoke": "REVOKED",
        },
    }

    DELEGATION_TRANSITIONS = {
        "DRAFT": {
            "activate": "ACTIVE",
        },
        "ACTIVE": {
            "suspend": "SUSPENDED",
            "revoke": "REVOKED",
            "expire": "EXPIRED",
        },
        "SUSPENDED": {
            "activate": "ACTIVE",
            "revoke": "REVOKED",
            "expire": "EXPIRED",
        },
    }

    OPERATION_TRANSITIONS = {
        "REQUESTED": {
            "evaluate": "EVALUATING",
            "cancel": "CANCELLED",
        },
        "EVALUATING": {
            "complete": "COMPLETED",
            "fail": "FAILED",
            "cancel": "CANCELLED",
        },
    }

    def __init__(
        self,
        graph: AuthorityGraph,
        policy: PolicyEngine,
    ):
        self.graph = graph
        self.policy = policy

    # ========================================================
    # GENERIC TRANSITION CHECK
    # ========================================================

    @staticmethod
    def _transition(
        transitions,
        current_state: str,
        action: str,
    ) -> TransitionDecision:

        allowed = transitions.get(
            current_state,
            {},
        )

        new_state = allowed.get(
            action
        )

        if new_state is None:

            return TransitionDecision(
                False,
                current_state,
                current_state,
                (
                    f"invalid transition: "
                    f"{current_state} --{action}--> ?"
                ),
            )

        return TransitionDecision(
            True,
            current_state,
            new_state,
            "transition accepted",
        )

    # ========================================================
    # REVIEW TRANSITIONS
    # ========================================================

    def validate_review_transition(
        self,
        current_state: str,
        action: str,
    ) -> TransitionDecision:

        return self._transition(
            self.REVIEW_TRANSITIONS,
            current_state,
            action,
        )

    # ========================================================
    # DELEGATION TRANSITIONS
    # ========================================================

    def validate_delegation_transition(
        self,
        current_state: str,
        action: str,
    ) -> TransitionDecision:

        return self._transition(
            self.DELEGATION_TRANSITIONS,
            current_state,
            action,
        )

    # ========================================================
    # OPERATION TRANSITIONS
    # ========================================================

    def validate_operation_transition(
        self,
        current_state: str,
        action: str,
    ) -> TransitionDecision:

        return self._transition(
            self.OPERATION_TRANSITIONS,
            current_state,
            action,
        )

    # ========================================================
    # REVIEW EVENT RECONSTRUCTION
    # ========================================================

    def reconstruct_review_state(
        self,
        review_id: str,
    ):

        review = self.graph.get_review(
            review_id
        )

        if review is None:

            return {
                "valid": False,
                "state": None,
                "reason": "review not found",
            }

        events = self.graph.get_review_events(
            review_id
        )

        state = "DRAFT"

        for event in events:

            previous = event["previous_state"]
            new = event["new_state"]

            if previous is not None and previous != state:

                return {
                    "valid": False,
                    "state": state,
                    "reason": (
                        "review history contains "
                        "a state discontinuity"
                    ),
                }

            if new is None:

                return {
                    "valid": False,
                    "state": state,
                    "reason": (
                        "review event has no target state"
                    ),
                }

            state = new

        return {
            "valid": True,
            "state": state,
            "stored_state": review.state,
            "reason": "review history reconstructed",
        }

    # ========================================================
    # DELEGATION CONSTRAINT EVALUATION
    # ========================================================

    def check_delegation_constraints(
        self,
        delegation_id: str,
        resource_classification: int,
        actor_id: str,
        resource_project_id: str,
    ):

        delegation = self.graph.get_delegation(
            delegation_id
        )

        if delegation is None:

            return {
                "allowed": False,
                "reason": "delegation not found",
            }

        constraints = (
            self.graph.get_delegation_constraints(
                delegation_id
            )
        )

        for constraint in constraints:

            max_classification = (
                constraint["max_classification"]
            )

            if (
                max_classification is not None
                and resource_classification
                > max_classification
            ):

                return {
                    "allowed": False,
                    "reason": (
                        "resource classification "
                        "exceeds delegation constraint"
                    ),
                }

            if constraint[
                "required_project_membership"
            ]:

                if not self.graph.is_project_member(
                    actor_id,
                    resource_project_id,
                ):

                    return {
                        "allowed": False,
                        "reason": (
                            "required project membership "
                            "not satisfied"
                        ),
                    }

        return {
            "allowed": True,
            "reason": (
                "delegation constraints satisfied"
            ),
        }


# ============================================================
# DEVELOPMENT TEST
# ============================================================

if __name__ == "__main__":

    graph = AuthorityGraph()
    policy = PolicyEngine(graph)
    machine = StateMachine(
        graph,
        policy,
    )

    print("=" * 70)
    print("BLACKSITE — V2 STATE MACHINE")
    print("=" * 70)

    print()
    print("REVIEW TRANSITIONS")

    for state, actions in (
        machine.REVIEW_TRANSITIONS.items()
    ):

        for action, target in actions.items():

            result = (
                machine.validate_review_transition(
                    state,
                    action,
                )
            )

            print(
                f"  {state:<10}"
                f" --{action:<8}--> "
                f"{target:<10}"
                f" [{result.success}]"
            )

    print()
    print("DELEGATION TRANSITIONS")

    for state, actions in (
        machine.DELEGATION_TRANSITIONS.items()
    ):

        for action, target in actions.items():

            result = (
                machine.validate_delegation_transition(
                    state,
                    action,
                )
            )

            print(
                f"  {state:<10}"
                f" --{action:<8}--> "
                f"{target:<10}"
                f" [{result.success}]"
            )

    print()
    print("OPERATION TRANSITIONS")

    for state, actions in (
        machine.OPERATION_TRANSITIONS.items()
    ):

        for action, target in actions.items():

            result = (
                machine.validate_operation_transition(
                    state,
                    action,
                )
            )

            print(
                f"  {state:<12}"
                f" --{action:<10}--> "
                f"{target:<12}"
                f" [{result.success}]"
            )

    print()
    print("V2 state machine loaded successfully.")

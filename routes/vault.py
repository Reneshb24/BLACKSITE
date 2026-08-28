
from datetime import datetime, timezone

from flask import (
    current_app,
    redirect,
    render_template,
    request,
    url_for,
)

from app.session import current_user


# ============================================================
# BLACKSITE — V2 SEALED VAULT
# ============================================================

def register_vault_routes(app):

    @app.route(
        "/vault",
        methods=["GET", "POST"],
    )
    def vault():

        # ----------------------------------------------------
        # AUTHENTICATION
        # ----------------------------------------------------

        user = current_user()

        if user is None:
            return redirect(
                url_for(
                    "login",
                    next="/vault",
                )
            )

        graph = current_app.extensions[
            "blacksite_graph"
        ]

        policy = current_app.extensions[
            "blacksite_policy"
        ]

        message = None
        success = False
        flag = None

        # ----------------------------------------------------
        # GET
        # ----------------------------------------------------

        if request.method == "GET":

            return render_template(
                "vault.html",
                user=user,
                message=None,
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # INPUT
        # ----------------------------------------------------

        operation_id = (
            request.form
            .get("operation_id", "")
            .strip()
        )

        capability_id = (
            request.form
            .get("capability_id", "")
            .strip()
        )

        if not operation_id or not capability_id:

            message = "operation and capability required"

            return render_template(
                "vault.html",
                user=user,
                message=message,
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # OPERATION
        # ----------------------------------------------------

        operation = graph.get_authorization_operation(
            operation_id
        )

        if operation is None:

            return render_template(
                "vault.html",
                user=user,
                message="invalid authorization proof",
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # V2 AUTHORIZATION EVALUATION
        # ----------------------------------------------------

        decision = policy.evaluate_operation(
            user,
            operation_id,
        )

        if not decision.allowed:

            return render_template(
                "vault.html",
                user=user,
                message="authorization proof rejected",
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # CAPABILITY
        # ----------------------------------------------------

        capability = graph.get_capability(
            capability_id
        )

        if capability is None:

            return render_template(
                "vault.html",
                user=user,
                message="invalid capability",
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # CAPABILITY BINDING
        # ----------------------------------------------------

        binding_ok = (
            capability["operation_id"]
            == operation_id
            and capability["subject"]
            == user.id
            and capability["resource_id"]
            == operation["resource_id"]
            and capability["scope"]
            == operation["requested_scope"]
            and capability["policy_version"]
            == operation["policy_version"]
        )

        if not binding_ok:

            return render_template(
                "vault.html",
                user=user,
                message="capability binding rejected",
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # CAPABILITY STATE
        # ----------------------------------------------------

        if capability["state"] != "ACTIVE":

            return render_template(
                "vault.html",
                user=user,
                message="capability is not active",
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # CHALLENGE METADATA / SCENARIO CLOCK
        # ----------------------------------------------------

        connection = graph.database.connect()

        try:

            meta = connection.execute(
                """
                SELECT
                    instance_id,
                    flag_secret,
                    scenario_time
                FROM challenge_meta
                WHERE id = 1
                """
            ).fetchone()

        finally:

            connection.close()

        if meta is None:

            return render_template(
                "vault.html",
                user=user,
                message="challenge metadata unavailable",
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # CAPABILITY TIME
        # ----------------------------------------------------

        try:

            issued_at = datetime.fromisoformat(
                capability["issued_at"]
                .replace("Z", "+00:00")
            )

            expires_at = datetime.fromisoformat(
                capability["expires_at"]
                .replace("Z", "+00:00")
            )

            now = datetime.fromisoformat(
                meta["scenario_time"]
                .replace("Z", "+00:00")
            )

        except (
            AttributeError,
            TypeError,
            ValueError,
        ):

            return render_template(
                "vault.html",
                user=user,
                message="invalid capability timestamp",
                success=False,
                flag=None,
            )

        if issued_at > now:

            return render_template(
                "vault.html",
                user=user,
                message="capability not yet valid",
                success=False,
                flag=None,
            )

        if expires_at <= now:

            return render_template(
                "vault.html",
                user=user,
                message="capability expired",
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # OPERATION / CAPABILITY LIFETIME
        # ----------------------------------------------------

        try:

            completed_at = datetime.fromisoformat(
                operation["completed_at"]
                .replace("Z", "+00:00")
            )

        except (
            AttributeError,
            TypeError,
            ValueError,
        ):

            return render_template(
                "vault.html",
                user=user,
                message="invalid authorization timeline",
                success=False,
                flag=None,
            )

        if issued_at < completed_at:

            return render_template(
                "vault.html",
                user=user,
                message="capability predates completed authorization",
                success=False,
                flag=None,
            )

        # ----------------------------------------------------
        # OPEN VAULT
        # ----------------------------------------------------

        success = True

        flag = (
            "OSPC{"
            + meta["flag_secret"]
            + "}"
        )

        message = (
            "BLACKSITE vault authorization accepted"
        )

        return render_template(
            "vault.html",
            user=user,
            message=message,
            success=success,
            flag=flag,
        )

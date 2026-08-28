import hashlib
import hmac

from flask import (
    current_app,
    redirect,
    render_template,
    request,
    url_for,
)

from app.session import current_user


# ============================================================
# LEGACY AUTHORIZATION CONTROLLER
# ============================================================

def register_legacy_routes(app):

    @app.route(
        "/legacy",
        methods=["GET", "POST"],
    )
    def legacy_console():

        # ----------------------------------------------------
        # AUTHENTICATION
        # ----------------------------------------------------

        user = current_user()

        if user is None:

            return redirect(
                url_for(
                    "login",
                    next="/legacy",
                )
            )

        graph = current_app.extensions[
            "blacksite_graph"
        ]

        connection = graph.database.connect()

        try:

            # ------------------------------------------------
            # BLACKSITE RESOURCE
            # ------------------------------------------------

            context = connection.execute(
                """
                SELECT
                    r.id AS resource_id,
                    r.name AS resource_name,
                    r.alias AS resource_alias,
                    r.classification,

                    p.id AS policy_id,
                    p.name AS policy_name,
                    p.version AS current_policy_version,
                    p.required_role,
                    p.required_clearance,
                    p.scope

                FROM resources r

                JOIN policies p
                    ON p.id = r.policy_id

                WHERE r.name = 'BLACKSITE_RESOURCE'
                """
            ).fetchone()

        finally:

            connection.close()

        if context is None:

            return (
                "BLACKSITE resource unavailable",
                500,
            )

        message = None
        success = False
        token = None

        # ====================================================
        # FORM SUBMISSION
        # ====================================================

        if request.method == "POST":

            resource_id = (
                request.form
                .get("resource_id", "")
                .strip()
            )

            review_id = (
                request.form
                .get("review_id", "")
                .strip()
            )

            delegation_id = (
                request.form
                .get("delegation_id", "")
                .strip()
            )

            version_text = (
                request.form
                .get("version", "")
                .strip()
            )

            scope = (
                request.form
                .get("scope", "")
                .strip()
                .upper()
            )

            # ------------------------------------------------
            # VERSION FORMAT
            # ------------------------------------------------

            try:

                version = int(
                    version_text
                )

            except ValueError:

                message = (
                    "invalid historical policy version"
                )

                version = None

            # ------------------------------------------------
            # DATABASE VALIDATION
            # ------------------------------------------------

            if message is None:

                connection = (
                    graph.database.connect()
                )

                try:

                    resource = connection.execute(
                        """
                        SELECT
                            id,
                            name,
                            alias,
                            classification,
                            policy_id
                        FROM resources
                        WHERE id = ?
                        """,
                        (resource_id,),
                    ).fetchone()

                    if resource is None:

                        message = (
                            "resource record not found"
                        )

                    # ----------------------------------------
                    # REVIEW
                    # ----------------------------------------

                    review = None

                    if message is None:

                        review = connection.execute(
                            """
                            SELECT
                                id,
                                resource_id,
                                reviewer,
                                principal,
                                state,
                                policy_version
                            FROM reviews
                            WHERE id = ?
                              AND resource_id = ?
                            """,
                            (
                                review_id,
                                resource_id,
                            ),
                        ).fetchone()

                        if review is None:

                            message = (
                                "review record not found"
                            )

                    # ----------------------------------------
                    # DELEGATION
                    # ----------------------------------------

                    delegation = None

                    if message is None:

                        delegation = connection.execute(
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
                              AND resource_id = ?
                            """,
                            (
                                delegation_id,
                                resource_id,
                            ),
                        ).fetchone()

                        if delegation is None:

                            message = (
                                "delegation record not found"
                            )

                    # ----------------------------------------
                    # HISTORICAL VERSION MATCH
                    # ----------------------------------------

                    if message is None:

                        if review["policy_version"] != version:

                            message = (
                                "review historical version mismatch"
                            )

                    if message is None:

                        if delegation["policy_version"] != version:

                            message = (
                                "delegation historical version mismatch"
                            )

                    # ----------------------------------------
                    # SCOPE
                    # ----------------------------------------

                    if message is None:

                        if delegation["scope"] != scope:

                            message = (
                                "delegation scope mismatch"
                            )

                    # ----------------------------------------
                    # AUTHORITY RELATIONSHIP
                    # ----------------------------------------

                    if message is None:

                        if (
                            review["principal"]
                            != delegation["principal"]
                        ):

                            message = (
                                "principal chain mismatch"
                            )

                    # ----------------------------------------
                    # LEGACY TRUST BOUNDARY
                    # ----------------------------------------
                    #
                    # IMPORTANT:
                    #
                    # This intentionally does NOT call:
                    #
                    #     PolicyEngine.can_enter_vault()
                    #
                    # The legacy controller trusts the
                    # historical authorization relationship.
                    #
                    # This is the controlled CTF vulnerability.
                    # ----------------------------------------

                    if message is None:

                        success = True

                finally:

                    connection.close()

        # ====================================================
        # DERIVE LEGACY TOKEN
        # ====================================================

        if success:

            connection = (
                graph.database.connect()
            )

            try:

                meta = connection.execute(
                    """
                    SELECT
                        instance_id,
                        flag_secret
                    FROM challenge_meta
                    WHERE id = 1
                    """
                ).fetchone()

            finally:

                connection.close()

            if meta is None:

                success = False

                message = (
                    "challenge metadata unavailable"
                )

            else:

                material = "|".join(
                    [
                        meta["instance_id"],
                        resource_id,
                        review_id,
                        delegation_id,
                        str(version),
                        scope,
                    ]
                )

                digest = hmac.new(
                    meta["flag_secret"].encode(),
                    material.encode(),
                    hashlib.sha256,
                ).hexdigest()

                token = digest[:32].upper()

                message = (
                    "historical authorization context accepted"
                )

        return render_template(
            "legacy.html",
            user=user,
            context=context,
            message=message,
            success=success,
            token=token,
        )

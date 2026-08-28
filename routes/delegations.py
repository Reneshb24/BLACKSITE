from flask import (
    current_app,
    render_template,
)

from app.session import current_user


def register_delegation_routes(app):

    @app.get("/delegations")
    def delegations():

        user = current_user()

        if user is None:
            return (
                "Authentication required",
                401,
            )

        graph = current_app.extensions[
            "blacksite_graph"
        ]

        connection = graph.database.connect()

        try:

            rows = connection.execute(
                """
                SELECT
                    d.id,
                    d.principal,
                    d.delegate,
                    d.resource_id,
                    d.scope,
                    d.state,
                    d.policy_version,
                    d.operation_id,

                    principal_user.username
                        AS principal_username,

                    delegate_user.username
                        AS delegate_username,

                    res.name
                        AS resource_name,

                    res.alias
                        AS resource_alias,

                    res.classification
                        AS resource_classification,

                    p.name
                        AS policy_name,

                    p.required_role,

                    p.required_clearance

                FROM delegations d

                LEFT JOIN users principal_user
                    ON principal_user.id = d.principal

                LEFT JOIN users delegate_user
                    ON delegate_user.id = d.delegate

                LEFT JOIN resources res
                    ON res.id = d.resource_id

                LEFT JOIN policies p
                    ON p.id = res.policy_id

                ORDER BY
                    CASE d.state
                        WHEN 'ACTIVE' THEN 0
                        WHEN 'INACTIVE' THEN 1
                        WHEN 'EXPIRED' THEN 2
                        ELSE 3
                    END,
                    d.id
                """
            ).fetchall()

        finally:

            connection.close()

        return render_template(
            "delegations.html",
            user=user,
            delegations=rows,
        )

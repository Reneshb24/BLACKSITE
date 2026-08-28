from flask import (
    current_app,
    render_template,
)

from app.session import current_user


def register_capability_routes(app):

    @app.get("/capabilities")
    def capabilities():

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
                    c.id,
                    c.operation_id,
                    c.subject,
                    c.resource_id,
                    c.scope,
                    c.policy_version,
                    c.issued_at,
                    c.expires_at,
                    c.state,

                    subject_user.username
                        AS subject_username,

                    r.name
                        AS resource_name,

                    r.alias
                        AS resource_alias,

                    r.classification
                        AS resource_classification,

                    p.name
                        AS policy_name

                FROM capabilities c

                LEFT JOIN users subject_user
                    ON subject_user.id = c.subject

                LEFT JOIN resources r
                    ON r.id = c.resource_id

                LEFT JOIN policies p
                    ON p.id = r.policy_id

                ORDER BY
                    CASE c.state
                        WHEN 'ACTIVE' THEN 0
                        WHEN 'EXPIRED' THEN 1
                        WHEN 'REVOKED' THEN 2
                        ELSE 3
                    END,
                    c.issued_at,
                    c.id
                """
            ).fetchall()

        finally:

            connection.close()

        return render_template(
            "capabilities.html",
            user=user,
            capabilities=rows,
        )

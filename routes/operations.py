from flask import current_app, render_template

from app.session import current_user


def register_operation_routes(app):

    @app.get("/operations")
    def operations():

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
                    ao.id,
                    ao.resource_id,
                    ao.requested_by,
                    ao.subject,
                    ao.requested_scope,
                    ao.policy_version,
                    ao.state,
                    ao.created_at,
                    ao.completed_at,

                    req.username AS requester_username,
                    subj.username AS subject_username,

                    r.name AS resource_name,
                    r.alias AS resource_alias,
                    r.classification AS resource_classification,

                    p.name AS policy_name

                FROM authorization_operations ao

                LEFT JOIN users req
                    ON req.id = ao.requested_by

                LEFT JOIN users subj
                    ON subj.id = ao.subject

                LEFT JOIN resources r
                    ON r.id = ao.resource_id

                LEFT JOIN policies p
                    ON p.id = r.policy_id

                ORDER BY
                    ao.created_at
                """
            ).fetchall()

        finally:
            connection.close()

        return render_template(
            "operations.html",
            user=user,
            operations=rows,
        )

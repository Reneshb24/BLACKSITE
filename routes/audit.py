from flask import current_app, render_template

from app.session import current_user


def register_audit_routes(app):

    @app.get("/audit")
    def audit():

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
                    a.id,
                    a.event_type,
                    a.actor,
                    a.subject,
                    a.resource_id,
                    a.result,
                    a.message,

                    actor_user.username
                        AS actor_username,

                    subject_user.username
                        AS subject_username,

                    r.name
                        AS resource_name,

                    r.alias
                        AS resource_alias,

                    ac.operation_id
                        AS operation_id,

                    ac.correlation_type
                        AS correlation_type,

                    ac.sequence_number
                        AS sequence_number

                FROM audit_events a

                LEFT JOIN audit_correlations ac
                    ON ac.audit_event_id = a.id

                LEFT JOIN users actor_user
                    ON actor_user.id = a.actor

                LEFT JOIN users subject_user
                    ON subject_user.id = a.subject

                LEFT JOIN resources r
                    ON r.id = a.resource_id

                ORDER BY
                    a.id
                """
            ).fetchall()

        finally:

            connection.close()

        return render_template(
            "audit.html",
            user=user,
            events=rows,
        )

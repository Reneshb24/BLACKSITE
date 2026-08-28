from flask import (
    current_app,
    render_template,
)

from app.session import current_user


def register_portal_routes(app):

    @app.get("/resources")
    def resources():

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
                    r.id,
                    r.name,
                    r.alias,
                    r.classification,
                    r.project_id,
                    p.name AS project_name,
                    r.policy_id,
                    pol.name AS policy_name,
                    pol.version AS policy_version
                FROM resources r

                LEFT JOIN projects p
                    ON p.id = r.project_id

                LEFT JOIN policies pol
                    ON pol.id = r.policy_id

                ORDER BY
                    r.name
                """
            ).fetchall()

        finally:

            connection.close()

        return render_template(
            "resources.html",
            user=user,
            resources=rows,
        )

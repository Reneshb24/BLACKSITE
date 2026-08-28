from flask import (
    current_app,
    render_template,
)

from app.session import current_user


def register_review_routes(app):

    @app.get("/reviews")
    def reviews():

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
                    r.resource_id,
                    r.created_by,
                    r.subject,
                    r.reviewer,
                    r.principal,
                    r.state,
                    r.policy_version,

                    res.name AS resource_name,
                    res.alias AS resource_alias,
                    res.classification AS resource_classification,

                    creator.username AS creator_username,
                    subject_user.username AS subject_username,
                    reviewer_user.username AS reviewer_username,
                    principal_user.username AS principal_username,

                    p.name AS policy_name,
                    p.required_role,
                    p.required_clearance,
                    p.scope

                FROM reviews r

                LEFT JOIN resources res
                    ON res.id = r.resource_id

                LEFT JOIN users creator
                    ON creator.id = r.created_by

                LEFT JOIN users subject_user
                    ON subject_user.id = r.subject

                LEFT JOIN users reviewer_user
                    ON reviewer_user.id = r.reviewer

                LEFT JOIN users principal_user
                    ON principal_user.id = r.principal

                LEFT JOIN resources policy_resource
                    ON policy_resource.id = r.resource_id

                LEFT JOIN policies p
                    ON p.id = policy_resource.policy_id

                ORDER BY
                    CASE r.state
                        WHEN 'PENDING' THEN 0
                        WHEN 'APPROVED' THEN 1
                        WHEN 'REJECTED' THEN 2
                        WHEN 'EXPIRED' THEN 3
                        ELSE 4
                    END,
                    r.id
                """
            ).fetchall()

        finally:

            connection.close()

        return render_template(
            "reviews.html",
            user=user,
            reviews=rows,
        )

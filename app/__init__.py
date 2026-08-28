from pathlib import Path

from flask import (
    Flask,
    redirect,
    render_template,
    request,
    url_for,
)
from routes.portal import register_portal_routes
from routes.reviews import register_review_routes
from routes.audit import register_audit_routes
from routes.delegations import register_delegation_routes
from routes.legacy import register_legacy_routes
from routes.vault import register_vault_routes
from routes.operations import register_operation_routes
from routes.capabilities import register_capability_routes
from authz.graph import AuthorityGraph
from authz.policy import PolicyEngine
from authz.transitions import StateMachine

from app.session import (
    login_user,
    logout_user,
    current_user,
)


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

TEMPLATE_DIR = PROJECT_ROOT / "templates"
STATIC_DIR = PROJECT_ROOT / "static"


# ============================================================
# APPLICATION FACTORY
# ============================================================

def create_app():

    app = Flask(
        __name__,
        template_folder=str(TEMPLATE_DIR),
        static_folder=str(STATIC_DIR),
    )

    # ========================================================
    # APPLICATION CONFIGURATION
    # ========================================================

    app.config["SECRET_KEY"] = (
        "aegis-blacksite-development-key"
    )

    # ========================================================
    # AUTHORIZATION COMPONENTS
    # ========================================================

    graph = AuthorityGraph()

    policy = PolicyEngine(
        graph
    )

    state_machine = StateMachine(
        graph,
        policy,
    )

    app.extensions[
        "blacksite_graph"
    ] = graph

    app.extensions[
        "blacksite_policy"
    ] = policy

    app.extensions[
        "blacksite_state_machine"
    ] = state_machine

    # ========================================================
    # HOME
    # ========================================================

    @app.get("/")
    def index():

        user = current_user()

        if user is not None:

            return redirect(
                url_for("dashboard")
            )

        return redirect(
            url_for("login")
        )

    # ========================================================
    # LOGIN
    # ========================================================

    @app.route(
        "/login",
        methods=["GET", "POST"],
    )
    def login():

        error = None

        if request.method == "POST":

            username = (
                request.form
                .get("username", "")
                .strip()
                .lower()
            )

            if login_user(username):

                destination = request.args.get(
                    "next"
                )

                if not destination:

                    destination = url_for(
                        "dashboard"
                    )

                return redirect(
                    destination
                )

            error = (
                "Unknown BLACKSITE identity."
            )

        return render_template(
            "login.html",
            error=error,
        )

    # ========================================================
    # LOGOUT
    # ========================================================

    @app.get("/logout")
    def logout():

        logout_user()

        return redirect(
            url_for("login")
        )

    # ========================================================
    # DASHBOARD
    # ========================================================

    @app.get("/dashboard")
    def dashboard():

        user = current_user()

        if user is None:

            return redirect(
                url_for("login")
            )

        return render_template(
            "dashboard.html",
            user=user,
        )

    # ========================================================
    # HEALTH CHECK
    # ========================================================

    @app.get("/health")
    def health():

        return {
            "status": "online",
            "system": "AEGIS BLACKSITE",
        }

    # ========================================================
    # TEMPORARY DATABASE DEBUG
    # ========================================================

    @app.get("/debug/database")
    def database_debug():

        connection = (
            graph.database.connect()
        )

        try:

            counts = {}

            tables = [
                "organizations",
                "users",
                "projects",
                "policies",
                "resources",
                "reviews",
                "delegations",
                "audit_events",
            ]

            for table in tables:

                row = connection.execute(
                    f"""
                    SELECT COUNT(*) AS count
                    FROM {table}
                    """
                ).fetchone()

                counts[table] = (
                    row["count"]
                )

        finally:

            connection.close()

        return {
            "database": "connected",
            "tables": counts,
        }

    # ========================================================
    # TEMPORARY ROUTE DEBUG
    # ========================================================

    @app.get("/debug/routes")
    def debug_routes():

        routes = []

        for rule in app.url_map.iter_rules():

            routes.append(
                {
                    "endpoint": rule.endpoint,
                    "methods": sorted(
                        rule.methods
                    ),
                    "path": str(rule),
                }
            )

        return {
            "routes": routes
        }
    register_portal_routes(app)
    register_review_routes(app)
    register_delegation_routes(app)
    register_audit_routes(app)
    register_legacy_routes(app)
    register_vault_routes(app)
    register_operation_routes(app)
    register_capability_routes(app)

    return app

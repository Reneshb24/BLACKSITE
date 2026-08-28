from flask import session

from authz.graph import AuthorityGraph


def login_user(username: str) -> bool:
    """
    Establish a BLACKSITE session for a valid fictional user.

    This challenge intentionally does not use real passwords.
    The event focuses on Authorization / Access Control.
    """

    graph = AuthorityGraph()

    user = graph.get_user_by_username(
        username
    )

    if user is None:
        return False

    # Remove any previous session information.
    session.clear()

    # Store only the immutable database identity.
    session["user_id"] = user.id

    return True


def logout_user():
    """
    Destroy the current BLACKSITE session.
    """

    session.clear()


def current_user():
    """
    Resolve the authenticated user from the database.
    """

    user_id = session.get("user_id")

    if not user_id:
        return None

    graph = AuthorityGraph()

    return graph.get_user(user_id)


def is_authenticated() -> bool:
    """
    Return True if the current session maps to
    a valid BLACKSITE user.
    """

    return current_user() is not None

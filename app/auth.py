from functools import wraps

from flask import (
    redirect,
    request,
    url_for,
)

from app.session import current_user


def login_required(function):
    """
    Require a valid authenticated BLACKSITE session.
    """

    @wraps(function)
    def wrapper(*args, **kwargs):

        user = current_user()

        if user is None:

            return redirect(
                url_for(
                    "login",
                    next=request.path,
                )
            )

        return function(
            *args,
            **kwargs,
        )

    return wrapper

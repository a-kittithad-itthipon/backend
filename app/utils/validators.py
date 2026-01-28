from functools import wraps
from flask import request
from app.utils.responses import error


def require_json_fields(fields):
    """
    A decorator to validate incoming JSON requests.
    Checks if the payload is valid JSON and contains all specified fields.

    :param fields: A list of strings representing the required fields.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Check if the request body is valid JSON
            body = request.get_json(silent=True)

            if body is None:
                return error(
                    message="Invalid JSON payload or Content-Type is not application/json",
                    error_code="INVALID_JSON",
                    status=400
                )

            # 2. Check for missing or empty fields
            missing = [field for field in fields if not body.get(field)]

            if missing:
                return error(
                    message=f"Missing required fields: {', '.join(missing)}",
                    error_code="MISSING_DATA",
                    status=400
                )

            # If all checks pass, proceed to the actual route function
            return f(*args, **kwargs)

        return decorated_function
    return decorator

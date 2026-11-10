import hashlib
import hmac
import logging
import os
from urllib.parse import urlparse

from flask import Blueprint
from flask import current_app
from flask import g
from flask import request
from flask import session
from itsdangerous import BadData
from itsdangerous import SignatureExpired
from itsdangerous import URLSafeTimedSerializer
from markupsafe import escape
from markupsafe import Markup
from werkzeug.exceptions import BadRequest
from wtforms import ValidationError
from wtforms.csrf.core import CSRF

__all__ = ("generate_csrf", "validate_csrf", "csrf_meta_tag", "CSRFProtect")
logger = logging.getLogger(__name__)


def generate_csrf(secret_key=None, token_key=None):
    """Generate a CSRF token. The token is cached for a request, so multiple
    calls to this function will generate the same token.

    During testing, it might be useful to access the signed token in
    ``g.csrf_token`` and the raw token in ``session['csrf_token']``.

    :param secret_key: Used to securely sign the token. Default is
        ``WTF_CSRF_SECRET_KEY`` or ``SECRET_KEY``.
    :param token_key: Key where token is stored in session for comparison.
        Default is ``WTF_CSRF_FIELD_NAME`` or ``'csrf_token'``.
    """

    secret_key = _get_config(
        secret_key,
        "WTF_CSRF_SECRET_KEY",
        current_app.secret_key,
        message="A secret key is required to use CSRF.",
    )
    field_name = _get_config(
        token_key,
        "WTF_CSRF_FIELD_NAME",
        "csrf_token",
        message="A field name is required to use CSRF.",
    )

    if field_name not in g:
        s = URLSafeTimedSerializer(secret_key, salt="wtf-csrf-token")

        if field_name not in session:
            session[field_name] = hashlib.sha1(os.urandom(64)).hexdigest()

        try:
            token = s.dumps(session[field_name])
        except TypeError:
            session[field_name] = hashlib.sha1(os.urandom(64)).hexdigest()
            token = s.dumps(session[field_name])

        setattr(g, field_name, token)

    return g.get(field_name)


def validate_csrf(data, secret_key=None, time_limit=None, token_key=None):
    """Check if the given data is a valid CSRF token. This compares the given
    signed token to the one stored in the session.

    :param data: The signed CSRF token to be checked.
    :param secret_key: Used to securely sign the token. Default is
        ``WTF_CSRF_SECRET_KEY`` or ``SECRET_KEY``.
    :param time_limit: Number of seconds that the token is valid. Default is
        ``WTF_CSRF_TIME_LIMIT`` or 3600 seconds (60 minutes).
    :param token_key: Key where token is stored in session for comparison.
        Default is ``WTF_CSRF_FIELD_NAME`` or ``'csrf_token'``.

    :raises ValidationError: Contains the reason that validation failed.

    .. versionchanged:: 0.14
        Raises ``ValidationError`` with a specific error message rather than
        returning ``True`` or ``False``.
    """

    secret_key = _get_config(
        secret_key,
        "WTF_CSRF_SECRET_KEY",
        current_app.secret_key,
        message="A secret key is required to use CSRF.",
    )
    field_name = _get_config(
        token_key,
        "WTF_CSRF_FIELD_NAME",
        "csrf_token",
        message="A field name is required to use CSRF.",
    )
    time_limit = _get_config(time_limit, "WTF_CSRF_TIME_LIMIT", 3600, required=False)

    if not data:
        raise ValidationError("The CSRF token is missing.")

    if field_name not in session:
        raise ValidationError("The CSRF session token is missing.")

    s = URLSafeTimedSerializer(secret_key, salt="wtf-csrf-token")

    try:
        token = s.loads(data, max_age=time_limit)
    except SignatureExpired as e:
        raise ValidationError("The CSRF token has expired.") from e
    except BadData as e:
        raise ValidationError("The CSRF token is invalid.") from e

    if not hmac.compare_digest(session[field_name], token):
        raise ValidationError("The CSRF tokens do not match.")


def csrf_meta_tag(name=None, secret_key=None, token_key=None):
    """Render an HTML ``<meta>`` tag carrying the CSRF token, following the
    convention used by Rails and recommended by OWASP for SPA and AJAX clients.

    Extract the token client-side with
    ``document.querySelector('meta[name="csrf-token"]').content`` and send it
    in the ``X-CSRFToken`` header of state-changing requests.

    :param name: Value of the meta tag's ``name`` attribute. Default is
        ``WTF_CSRF_META_NAME`` or ``'csrf-token'``.
    :param secret_key: Forwarded to :func:`generate_csrf`.
    :param token_key: Forwarded to :func:`generate_csrf`.
    """

    name = _get_config(name, "WTF_CSRF_META_NAME", "csrf-token")
    token = generate_csrf(secret_key=secret_key, token_key=token_key)
    return Markup(f'<meta name="{escape(name)}" content="{escape(token)}">')


def _get_config(
    value, config_name, default=None, required=True, message="CSRF is not configured."
):
    """Find config value based on provided value, Flask config, and default
    value.

    :param value: already provided config value
    :param config_name: Flask ``config`` key
    :param default: default value if not provided or configured
    :param required: whether the value must not be ``None``
    :param message: error message if required config is not found
    :raises KeyError: if required config is not found
    """

    if value is None:
        value = current_app.config.get(config_name, default)

    if required and value is None:
        raise RuntimeError(message)

    return value


class _FlaskFormCSRF(CSRF):
    def setup_form(self, form):
        self.meta = form.meta
        return super().setup_form(form)

    def generate_csrf_token(self, csrf_token_field):
        return generate_csrf(
            secret_key=self.meta.csrf_secret, token_key=self.meta.csrf_field_name
        )

    def validate_csrf_token(self, form, field):
        if g.get("csrf_valid", False):
            # already validated by CSRFProtect
            return

        try:
            validate_csrf(
                field.data,
                self.meta.csrf_secret,
                self.meta.csrf_time_limit,
                self.meta.csrf_field_name,
            )
        except ValidationError as e:
            logger.info(e.args[0])
            raise


class CSRFProtect:
    """Enable CSRF protection globally for a Flask app.

    ::

        app = Flask(__name__)
        csrf = CSRFProtect(app)

    Checks the ``csrf_token`` field sent with forms, or the ``X-CSRFToken``
    header sent with JavaScript requests. Render the token in templates using
    ``{{ csrf_token() }}``.

    See the :ref:`csrf` documentation.
    """

    def __init__(self, app=None):
        # Exempt view function objects, matched by identity. This avoids
        # accidental sharing when two distinct views report the same
        # ``__module__.__name__`` (e.g. decorators using ``functools.wraps``).
        self._exempt_views = set()
        # Exempt endpoint names, matched exactly against ``request.endpoint``.
        self._exempt_endpoints = set()
        # Exempt Blueprint objects, matched by identity. Registering the same
        # blueprint under several names exempts all of them, while another
        # blueprint with the same name stays protected.
        self._exempt_blueprints = set()

        if app:
            self.init_app(app)

    def init_app(self, app):
        app.extensions["csrf"] = self

        app.config.setdefault("WTF_CSRF_ENABLED", True)
        app.config.setdefault("WTF_CSRF_CHECK_DEFAULT", True)
        app.config["WTF_CSRF_METHODS"] = set(
            app.config.get("WTF_CSRF_METHODS", ["POST", "PUT", "PATCH", "DELETE"])
        )
        app.config.setdefault("WTF_CSRF_FIELD_NAME", "csrf_token")
        app.config.setdefault("WTF_CSRF_HEADERS", ["X-CSRFToken", "X-CSRF-Token"])
        app.config.setdefault("WTF_CSRF_META_NAME", "csrf-token")
        app.config.setdefault("WTF_CSRF_TIME_LIMIT", 3600)
        app.config.setdefault("WTF_CSRF_SSL_STRICT", True)

        app.jinja_env.globals["csrf_token"] = generate_csrf
        app.jinja_env.globals["csrf_meta_tag"] = csrf_meta_tag
        app.context_processor(
            lambda: {"csrf_token": generate_csrf, "csrf_meta_tag": csrf_meta_tag}
        )

        @app.before_request
        def csrf_protect():
            if not app.config["WTF_CSRF_ENABLED"]:
                return

            if not app.config["WTF_CSRF_CHECK_DEFAULT"]:
                return

            self.protect(apply_exemptions=True)

    def _get_csrf_token(self):
        # find the token in the form data
        field_name = current_app.config["WTF_CSRF_FIELD_NAME"]
        base_token = request.form.get(field_name)

        if base_token:
            return base_token

        # if the form has a prefix, the name will be {prefix}-csrf_token
        for key in request.form:
            if key.endswith(field_name):
                csrf_token = request.form[key]

                if csrf_token:
                    return csrf_token

        # find the token in the headers
        for header_name in current_app.config["WTF_CSRF_HEADERS"]:
            csrf_token = request.headers.get(header_name)

            if csrf_token:
                return csrf_token

        return None

    def protect(self, apply_exemptions=False):
        """Validate CSRF on the current request.

        When ``apply_exemptions`` is ``True``, the view, endpoint, and
        blueprint exemptions registered with :meth:`exempt` are evaluated
        against the endpoint selected by real URL matching, and matching
        requests are skipped. This lets you combine a custom
        ``before_request`` hook (or any manual call) with the declarative
        ``@csrf.exempt`` decorator.

        Exemptions are never applied when this is called without the flag,
        so a manual call always validates unless the caller opts in.
        """

        if apply_exemptions:
            if not request.endpoint:
                return

            if self._is_exempt():
                return

        if request.method not in current_app.config["WTF_CSRF_METHODS"]:
            return

        try:
            validate_csrf(self._get_csrf_token())
        except ValidationError as e:
            logger.info(e.args[0])
            self._error_response(e.args[0])

        if request.is_secure and current_app.config["WTF_CSRF_SSL_STRICT"]:
            if not request.referrer:
                self._error_response("The referrer header is missing.")

            good_referrer = f"https://{request.host}/"

            if not same_origin(request.referrer, good_referrer):
                self._error_response("The referrer does not match the host.")

        g.csrf_valid = True  # mark this request as CSRF valid

    def _is_exempt(self):
        # Blueprint scope: the blueprint handling the matched request, found
        # through the current app so blueprint aliases resolve to the same
        # Blueprint object.
        if current_app.blueprints.get(request.blueprint) in self._exempt_blueprints:
            return True

        # Endpoint scope: the endpoint name chosen by real URL matching.
        if request.endpoint in self._exempt_endpoints:
            return True

        # View scope: the exact view function registered for this endpoint.
        # Identity matching ignores ``__name__`` collisions; a wrapper applied
        # outside ``@csrf.exempt`` is a different object and stays protected.
        view = current_app.view_functions.get(request.endpoint)
        return view is not None and view in self._exempt_views

    def exempt(self, view):
        """Mark a view, endpoint, or blueprint to be excluded from CSRF
        protection.

        The three argument types have distinct, non-overlapping scopes:

        - A view function (the usual ``@csrf.exempt`` decorator) exempts that
          exact function object. If it is registered on several endpoints,
          every endpoint serving it is exempt; another view with the same
          ``__module__.__name__`` is not affected, even when
          :func:`functools.wraps` copies the name.
        - A string exempts one endpoint name, as resolved by real URL
          matching (for example ``'account.login'``). Only that endpoint is
          exempt, in every app this ``CSRFProtect`` is initialized on.
        - A :class:`~flask.Blueprint` exempts every endpoint of that
          blueprint, including when the same blueprint is registered under
          different names.

        ::

            @app.route('/some-view', methods=['POST'])
            @csrf.exempt
            def some_view():
                ...

        ::

            csrf.exempt('account.login')

        ::

            bp = Blueprint(...)
            csrf.exempt(bp)

        """

        if isinstance(view, Blueprint):
            self._exempt_blueprints.add(view)
            return view

        if isinstance(view, str):
            self._exempt_endpoints.add(view)
            return view

        self._exempt_views.add(view)
        return view

    def _error_response(self, reason):
        raise CSRFError(reason)


class CSRFError(BadRequest):
    """Raise if the client sends invalid CSRF data with the request.

    Generates a 400 Bad Request response with the failure reason by default.
    Customize the response by registering a handler with
    :meth:`flask.Flask.errorhandler`.
    """

    description = "CSRF validation failed."


def same_origin(current_uri, compare_uri):
    current = urlparse(current_uri)
    compare = urlparse(compare_uri)

    return (
        current.scheme == compare.scheme
        and current.hostname == compare.hostname
        and current.port == compare.port
    )

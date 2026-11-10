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

__all__ = (
    "generate_csrf",
    "validate_csrf",
    "csrf_meta_tag",
    "CSRFProtect",
    "CSRFError",
    "CSRFMetadataError",
)
logger = logging.getLogger(__name__)

# Methods that cannot cause a state change, per RFC 9110.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


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
        self._exempt_views = set()
        self._exempt_blueprints = set()
        self._cross_site_views = set()
        self._cross_site_blueprints = set()

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
        app.config.setdefault("WTF_CSRF_FETCH_METADATA", False)
        app.config.setdefault("WTF_CSRF_FETCH_METADATA_MISSING", "allow")

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

        When ``apply_exemptions`` is ``True``, views and blueprints marked with
        :meth:`exempt` are skipped. This lets you combine a custom
        ``before_request`` hook (or any manual call) with the declarative
        ``@csrf.exempt`` decorator.
        """

        if apply_exemptions:
            if not request.endpoint:
                return

            if self._is_exempt():
                return

        if request.method not in current_app.config["WTF_CSRF_METHODS"]:
            return

        if current_app.config["WTF_CSRF_FETCH_METADATA"]:
            reason = self._fetch_metadata_reason()

            if reason is not None:
                logger.info(reason)
                self._metadata_error_response(reason)

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
        if current_app.blueprints.get(request.blueprint) in self._exempt_blueprints:
            return True

        view = current_app.view_functions.get(request.endpoint)
        if view is None:
            return False

        dest = f"{view.__module__}.{view.__name__}"
        return dest in self._exempt_views

    def _is_cross_site_allowed(self):
        blueprint = current_app.blueprints.get(request.blueprint)

        if blueprint in self._cross_site_blueprints:
            return True

        view = current_app.view_functions.get(request.endpoint)
        if view is None:
            return False

        dest = f"{view.__module__}.{view.__name__}"
        return dest in self._cross_site_views

    def _fetch_metadata_reason(self):
        """Return a rejection reason based on the Fetch Metadata headers.

        Only requests for a protected, state-changing method reach this point;
        safe methods are allowed before any metadata evaluation. A ``None``
        result means the request proceeds to the regular CSRF token check.
        """

        if self._is_cross_site_allowed():
            return None

        site = request.headers.get("Sec-Fetch-Site")

        if site is None:
            if current_app.config["WTF_CSRF_FETCH_METADATA_MISSING"] == "reject":
                return "The Sec-Fetch-Site header is missing."

            return None

        site = site.lower()

        if site in {"same-origin", "same-site"}:
            # Fetch Metadata identifies the context, it does not authenticate
            # the request, so the CSRF token is still required.
            return None

        if site == "none":
            if request.method in _SAFE_METHODS:
                return None

            return "Cross-site state-changing request rejected by Fetch Metadata."

        if site == "cross-site":
            is_navigation = (
                request.headers.get("Sec-Fetch-Mode", "").lower() == "navigate"
                and request.headers.get("Sec-Fetch-Dest", "").lower() == "document"
            )

            if is_navigation and request.method in _SAFE_METHODS:
                return None

            return "Cross-site state-changing request rejected by Fetch Metadata."

        return "The Sec-Fetch-Site header has an unrecognized value."

    def exempt(self, view):
        """Mark a view or blueprint to be excluded from CSRF protection.

        ::

            @app.route('/some-view', methods=['POST'])
            @csrf.exempt
            def some_view():
                ...

        ::

            bp = Blueprint(...)
            csrf.exempt(bp)

        """

        if isinstance(view, Blueprint):
            self._exempt_blueprints.add(view)
            return view

        if isinstance(view, str):
            view_location = view
        else:
            view_location = ".".join((view.__module__, view.__name__))

        self._exempt_views.add(view_location)
        return view

    def allow_cross_site(self, view):
        """Mark a view or blueprint as an accepted cross-site entry point.

        Fetch Metadata protection will not reject requests to the target based
        on ``Sec-Fetch-Site``; every other CSRF check, including the token,
        still applies unless the target is also :meth:`exempt`. ::

            @app.route('/webhook', methods=['POST'])
            @csrf.allow_cross_site
            def webhook():
                ...

        ::

            bp = Blueprint(...)
            csrf.allow_cross_site(bp)
        """

        if isinstance(view, Blueprint):
            self._cross_site_blueprints.add(view)
            return view

        if isinstance(view, str):
            view_location = view
        else:
            view_location = ".".join((view.__module__, view.__name__))

        self._cross_site_views.add(view_location)
        return view

    def _error_response(self, reason):
        raise CSRFError(reason)

    def _metadata_error_response(self, reason):
        raise CSRFMetadataError(reason)


class CSRFError(BadRequest):
    """Raise if the client sends invalid CSRF data with the request.

    Generates a 400 Bad Request response with the failure reason by default.
    Customize the response by registering a handler with
    :meth:`flask.Flask.errorhandler`.
    """

    description = "CSRF validation failed."


class CSRFMetadataError(CSRFError):
    """Raise if a request is rejected by the Fetch Metadata policy before the
    request body is read.

    Subclassing :class:`CSRFError` keeps existing ``CSRFError`` handlers
    working, while a dedicated handler can distinguish a metadata policy
    rejection from an invalid or missing token.
    """

    description = "Fetch Metadata policy rejected the request."


def same_origin(current_uri, compare_uri):
    current = urlparse(current_uri)
    compare = urlparse(compare_uri)

    return (
        current.scheme == compare.scheme
        and current.hostname == compare.hostname
        and current.port == compare.port
    )

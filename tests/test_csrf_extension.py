import functools

import pytest
from flask import Blueprint
from flask import g
from flask import render_template_string
from flask import request

from flask_wtf import FlaskForm
from flask_wtf.csrf import csrf_meta_tag
from flask_wtf.csrf import CSRFError
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf


@pytest.fixture
def app(app):
    CSRFProtect(app)

    @app.route("/", methods=["GET", "POST"])
    def index():
        pass

    @app.after_request
    def add_csrf_header(response):
        response.headers.set("X-CSRF-Token", generate_csrf())
        return response

    return app


@pytest.fixture
def csrf(app):
    return app.extensions["csrf"]


def test_render_token(req_ctx):
    token = generate_csrf()
    assert render_template_string("{{ csrf_token() }}") == token


def test_csrf_meta_tag_default(req_ctx):
    token = generate_csrf()
    rendered = csrf_meta_tag()
    assert rendered == f'<meta name="csrf-token" content="{token}">'


def test_csrf_meta_tag_custom_name_param(req_ctx):
    token = generate_csrf()
    rendered = csrf_meta_tag(name="x-csrf")
    assert rendered == f'<meta name="x-csrf" content="{token}">'


def test_csrf_meta_tag_config(app, req_ctx):
    app.config["WTF_CSRF_META_NAME"] = "authenticity-token"
    token = generate_csrf()
    rendered = csrf_meta_tag()
    assert rendered == f'<meta name="authenticity-token" content="{token}">'


def test_csrf_meta_tag_param_overrides_config(app, req_ctx):
    app.config["WTF_CSRF_META_NAME"] = "from-config"
    token = generate_csrf()
    rendered = csrf_meta_tag(name="from-param")
    assert rendered == f'<meta name="from-param" content="{token}">'


def test_csrf_meta_tag_jinja(req_ctx):
    token = generate_csrf()
    assert (
        render_template_string("{{ csrf_meta_tag() }}")
        == f'<meta name="csrf-token" content="{token}">'
    )


def test_csrf_meta_tag_escapes_name(req_ctx):
    token = generate_csrf()
    rendered = csrf_meta_tag(name='"><script>alert(1)</script>')
    assert "<script>" not in rendered
    assert f'content="{token}"' in rendered


def test_protect(app, client, app_ctx):
    response = client.post("/")
    assert response.status_code == 400
    assert "The CSRF token is missing." in response.get_data(as_text=True)

    app.config["WTF_CSRF_ENABLED"] = False
    assert client.post("/").get_data() == b""
    app.config["WTF_CSRF_ENABLED"] = True

    app.config["WTF_CSRF_CHECK_DEFAULT"] = False
    assert client.post("/").get_data() == b""
    app.config["WTF_CSRF_CHECK_DEFAULT"] = True

    assert client.options("/").status_code == 200
    assert client.post("/not-found").status_code == 404

    response = client.get("/")
    assert response.status_code == 200
    token = response.headers["X-CSRF-Token"]
    assert client.post("/", data={"csrf_token": token}).status_code == 200
    assert client.post("/", data={"prefix-csrf_token": token}).status_code == 200
    assert client.post("/", data={"prefix-csrf_token": ""}).status_code == 400
    assert client.post("/", headers={"X-CSRF-Token": token}).status_code == 200


def test_same_origin(client):
    token = client.get("/").headers["X-CSRF-Token"]
    response = client.post(
        "/", base_url="https://localhost", headers={"X-CSRF-Token": token}
    )
    data = response.get_data(as_text=True)
    assert "The referrer header is missing." in data

    response = client.post(
        "/",
        base_url="https://localhost",
        headers={"X-CSRF-Token": token, "Referer": "http://localhost/"},
    )
    data = response.get_data(as_text=True)
    assert "The referrer does not match the host." in data

    response = client.post(
        "/",
        base_url="https://localhost",
        headers={"X-CSRF-Token": token, "Referer": "https://other/"},
    )
    data = response.get_data(as_text=True)
    assert "The referrer does not match the host." in data

    response = client.post(
        "/",
        base_url="https://localhost",
        headers={"X-CSRF-Token": token, "Referer": "https://localhost:8080/"},
    )
    data = response.get_data(as_text=True)
    assert "The referrer does not match the host." in data

    response = client.post(
        "/",
        base_url="https://localhost",
        headers={"X-CSRF-Token": token, "Referer": "https://localhost/"},
    )
    assert response.status_code == 200


def test_form_csrf_short_circuit(app, client):
    @app.route("/skip", methods=["POST"])
    def skip():
        assert g.get("csrf_valid")
        # don't pass the token, then validate the form
        # this would fail if CSRFProtect didn't run
        form = FlaskForm(None)
        assert form.validate()

    token = client.get("/").headers["X-CSRF-Token"]
    response = client.post("/skip", headers={"X-CSRF-Token": token})
    assert response.status_code == 200


def test_exempt_view(app, csrf, client):
    @app.route("/exempt", methods=["POST"])
    @csrf.exempt
    def exempt():
        pass

    response = client.post("/exempt")
    assert response.status_code == 200

    # A string is an endpoint name, resolved through real URL matching.
    csrf.exempt("index")
    response = client.post("/")
    assert response.status_code == 200


def test_manual_protect(app, csrf, client):
    @app.route("/manual", methods=["GET", "POST"])
    @csrf.exempt
    def manual():
        csrf.protect()

    response = client.get("/manual")
    assert response.status_code == 200

    response = client.post("/manual")
    assert response.status_code == 400


def test_protect_apply_exemptions(app, csrf, client):
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False

    @app.before_request
    def custom():
        if request.headers.get("Authorization", "").startswith("Bearer "):
            return
        csrf.protect(apply_exemptions=True)

    @app.route("/api", methods=["POST"])
    def api():
        pass

    @app.route("/webhook", methods=["POST"])
    @csrf.exempt
    def webhook():
        pass

    bp = Blueprint("public", __name__, url_prefix="/public")
    csrf.exempt(bp)

    @bp.route("/", methods=["POST"])
    def public():
        pass

    app.register_blueprint(bp)

    assert client.post("/api").status_code == 400
    assert client.post("/api", headers={"Authorization": "Bearer x"}).status_code == 200
    assert client.post("/webhook").status_code == 200
    assert client.post("/public/").status_code == 200
    assert client.post("/missing").status_code == 404


def test_exempt_blueprint(app, csrf, client):
    bp = Blueprint("exempt", __name__, url_prefix="/exempt")
    csrf.exempt(bp)

    @bp.route("/", methods=["POST"])
    def index():
        pass

    app.register_blueprint(bp)
    response = client.post("/exempt/")
    assert response.status_code == 200


def test_exempt_nested_blueprint(app, csrf, client):
    bp1 = Blueprint("exempt1", __name__, url_prefix="/")
    bp2 = Blueprint("exempt2", __name__, url_prefix="/exempt")
    csrf.exempt(bp2)

    @bp2.route("/", methods=["POST"])
    def index():
        pass

    bp1.register_blueprint(bp2)
    app.register_blueprint(bp1)

    response = client.post("/exempt/")
    assert response.status_code == 200


def test_error_handler(app, client):
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return e.description.lower()

    response = client.post("/")
    assert response.get_data(as_text=True) == "the csrf token is missing."


def test_validate_error_logged(client, monkeypatch):
    from flask_wtf.csrf import logger

    messages = []

    def assert_info(message):
        messages.append(message)

    monkeypatch.setattr(logger, "info", assert_info)

    client.post("/")
    assert len(messages) == 1
    assert messages[0] == "The CSRF token is missing."


def test_exempt_view_follows_view_onto_every_endpoint(app, csrf, client):
    @csrf.exempt
    def shared():
        pass

    app.add_url_rule("/one", endpoint="one", view_func=shared, methods=["POST"])
    app.add_url_rule("/two", endpoint="two", view_func=shared, methods=["POST"])

    assert client.post("/one").status_code == 200
    assert client.post("/two").status_code == 200


def test_exempt_endpoint_only_matches_that_endpoint(app, csrf, client):
    def shared():
        pass

    app.add_url_rule("/one", endpoint="one", view_func=shared, methods=["POST"])
    app.add_url_rule("/two", endpoint="two", view_func=shared, methods=["POST"])
    csrf.exempt("one")

    assert client.post("/one").status_code == 200
    assert client.post("/two").status_code == 400


def test_exempt_unknown_endpoint_does_not_match(app, csrf, client):
    csrf.exempt("does.not_exist")

    response = client.post("/")
    assert response.status_code == 400


def test_same_name_wrappers_do_not_share_exemption(app, csrf, client):
    def named_wrapper(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)

        wrapper.__name__ = "colliding_name"
        return wrapper

    @app.route("/exempt", endpoint="exempt_ep", methods=["POST"])
    @csrf.exempt
    @named_wrapper
    def exempt_view():
        pass

    @app.route("/protected", endpoint="protected_ep", methods=["POST"])
    @named_wrapper
    def protected_view():
        pass

    assert exempt_view.__name__ == protected_view.__name__ == "colliding_name"
    assert client.post("/exempt").status_code == 200
    assert client.post("/protected").status_code == 400


def test_wrapper_outside_exempt_stays_protected(app, csrf, client):
    def plain_wrapper(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)

        return wrapper

    @csrf.exempt
    def inner():
        pass

    app.add_url_rule(
        "/wrapped",
        endpoint="wrapped",
        view_func=plain_wrapper(inner),
        methods=["POST"],
    )

    # The registered view is the wrapper, not the object passed to exempt.
    assert app.view_functions["wrapped"] is not inner
    assert client.post("/wrapped").status_code == 400

    # Endpoint exemption is the precise escape hatch for this layout.
    csrf.exempt("wrapped")
    assert client.post("/wrapped").status_code == 200


def test_exempt_blueprint_object_ignores_registration_names(app, csrf, client):
    bp = Blueprint("bp", __name__)

    @bp.route("/", methods=["POST"])
    def index():
        pass

    csrf.exempt(bp)
    app.register_blueprint(bp, url_prefix="/first", name="first")
    app.register_blueprint(bp, url_prefix="/second", name="second")

    assert client.post("/first/").status_code == 200
    assert client.post("/second/").status_code == 200


def test_same_blueprint_name_different_object_stays_protected(app, csrf, client):
    exempt_bp = Blueprint("same_name", __name__)
    other_bp = Blueprint("same_name", __name__)

    @exempt_bp.route("/", methods=["POST"])
    def exempt_index():
        pass

    @other_bp.route("/", methods=["POST"])
    def other_index():
        pass

    csrf.exempt(exempt_bp)
    app.register_blueprint(exempt_bp, url_prefix="/exempt", name="exempt_bp")
    app.register_blueprint(other_bp, url_prefix="/other", name="other_bp")

    assert client.post("/exempt/").status_code == 200
    assert client.post("/other/").status_code == 400


def test_exemptions_are_scoped_per_app(app, csrf):
    other = app.__class__("other")
    other.secret_key = app.secret_key
    csrf.init_app(other)

    @csrf.exempt
    def shared_view():
        pass

    app.add_url_rule("/a", endpoint="a", view_func=shared_view, methods=["POST"])
    other.add_url_rule("/a", endpoint="a", view_func=shared_view, methods=["POST"])
    csrf.exempt("only_here")

    def only_view():
        pass

    app.add_url_rule(
        "/only", endpoint="only_here", view_func=only_view, methods=["POST"]
    )
    other.add_url_rule(
        "/only", endpoint="only_here", view_func=only_view, methods=["POST"]
    )

    bp = Blueprint("bp", __name__)

    @bp.route("/", methods=["POST"])
    def bp_index():
        pass

    csrf.exempt(bp)
    app.register_blueprint(bp, url_prefix="/bp", name="bp")
    other.register_blueprint(bp, url_prefix="/bp", name="bp")

    def local_view():
        pass

    other.add_url_rule(
        "/local", endpoint="local_endpoint", view_func=local_view, methods=["POST"]
    )

    first_client = app.test_client()
    second_client = other.test_client()

    # View and blueprint exemptions follow the shared objects everywhere.
    assert first_client.post("/a").status_code == 200
    assert second_client.post("/a").status_code == 200
    assert first_client.post("/bp/").status_code == 200
    assert second_client.post("/bp/").status_code == 200
    # Endpoint names are compared per app against the shared exemption set.
    assert first_client.post("/only").status_code == 200
    assert second_client.post("/only").status_code == 200
    # A view never registered as exempt stays protected in the second app.
    assert second_client.post("/local").status_code == 400


def test_init_app_twice_keeps_exemptions(app, csrf, client):
    @app.route("/twice", methods=["POST"])
    @csrf.exempt
    def twice():
        pass

    csrf.init_app(app)

    assert app.extensions["csrf"] is csrf
    assert client.post("/twice").status_code == 200
    # Default protection still runs for non-exempt views.
    assert client.post("/").status_code == 400


def test_manual_protect_ignores_exemptions_by_default(app, csrf, client):
    @app.route("/manual-exempt", methods=["POST"])
    @csrf.exempt
    def manual_exempt():
        csrf.protect()

    assert client.post("/manual-exempt").status_code == 400


def test_unknown_endpoint_with_apply_exemptions(app, csrf, client):
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False

    @app.before_request
    def manual():
        csrf.protect(apply_exemptions=True)

    csrf.exempt("missing")

    assert client.post("/missing").status_code == 404
    assert client.post("/").status_code == 400

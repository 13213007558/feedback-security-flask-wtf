import pytest
from flask import g
from flask import session
from types import SimpleNamespace
from wtforms import ValidationError

from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_wtf.csrf import validate_csrf


def test_csrf_requires_secret_key(app, req_ctx):
    # use secret key set by test setup
    generate_csrf()
    # fail with no key
    app.secret_key = None
    pytest.raises(RuntimeError, generate_csrf)
    # use WTF_CSRF config
    app.config["WTF_CSRF_SECRET_KEY"] = "wtf_secret"
    generate_csrf()
    del app.config["WTF_CSRF_SECRET_KEY"]
    # use direct argument
    generate_csrf(secret_key="direct")


def test_token_stored_by_generate(req_ctx):
    generate_csrf()
    assert "csrf_token" in session
    assert "csrf_token" in g


def test_custom_token_key(req_ctx):
    generate_csrf(token_key="oauth_token")
    assert "oauth_token" in session
    assert "oauth_token" in g


def test_token_cached(req_ctx):
    assert generate_csrf() == generate_csrf()


def test_generate_csrf_cached_per_policy(req_ctx):
    default_token = generate_csrf()
    other_token = generate_csrf(secret_key="other-secret")

    assert default_token != other_token
    # same policy still returns the cached token
    assert generate_csrf() == default_token
    assert generate_csrf(secret_key="other-secret") == other_token

    # each token only validates under its own policy
    validate_csrf(default_token)
    validate_csrf(other_token, secret_key="other-secret")

    e = pytest.raises(ValidationError, validate_csrf, other_token)
    assert str(e.value) == "The CSRF token is invalid."


def test_csrf_caches_do_not_store_secrets(req_ctx):
    generate_csrf(secret_key="first-secret")
    generate_csrf(secret_key="second-secret", token_key="other_token")
    validate_csrf(
        generate_csrf(secret_key="third-secret", token_key="third_token"),
        secret_key="third-secret",
        token_key="third_token",
    )

    cached = list(g.get("_csrf_token_cache", ())) + list(g.get("_csrf_validated", ()))

    for entry in cached:
        for secret in ("first-secret", "second-secret", "third-secret"):
            assert secret not in str(entry)


def test_validate(req_ctx):
    validate_csrf(generate_csrf())


def test_validation_errors(req_ctx):
    e = pytest.raises(ValidationError, validate_csrf, None)
    assert str(e.value) == "The CSRF token is missing."

    e = pytest.raises(ValidationError, validate_csrf, "no session")
    assert str(e.value) == "The CSRF session token is missing."

    token = generate_csrf()
    e = pytest.raises(ValidationError, validate_csrf, token, time_limit=-1)
    assert str(e.value) == "The CSRF token has expired."

    e = pytest.raises(ValidationError, validate_csrf, "invalid")
    assert str(e.value) == "The CSRF token is invalid."

    other_token = generate_csrf(token_key="other_csrf")
    e = pytest.raises(ValidationError, validate_csrf, other_token)
    assert str(e.value) == "The CSRF tokens do not match."


def test_form_csrf(app, client, app_ctx):
    @app.route("/", methods=["GET", "POST"])
    def index():
        f = FlaskForm()

        if f.validate_on_submit():
            return "good"

        if f.errors:
            return f.csrf_token.errors[0]

        return f.csrf_token.current_token

    response = client.get("/")
    assert response.get_data(as_text=True) == g.csrf_token

    response = client.post("/")
    assert response.get_data(as_text=True) == "The CSRF token is missing."

    response = client.post("/", data={"csrf_token": g.csrf_token})
    assert response.get_data(as_text=True) == "good"


def test_validate_error_logged(req_ctx, monkeypatch):
    from flask_wtf.csrf import logger

    messages = []

    def assert_info(message):
        messages.append(message)

    monkeypatch.setattr(logger, "info", assert_info)
    FlaskForm().validate()
    assert len(messages) == 1
    assert messages[0] == "The CSRF token is missing."


def test_protect_pass_does_not_exempt_custom_form(app, client):
    csrf = CSRFProtect(app)

    class CustomForm(FlaskForm):
        class Meta:
            csrf_secret = "form-secret"

    @app.route("/", methods=["GET", "POST"])
    def index():
        form = CustomForm()

        if form.validate_on_submit():
            return "good"

        if form.errors:
            return form.csrf_token.errors[0]

        return f"{generate_csrf()}|{form.csrf_token.current_token}"

    @app.route("/exempt", methods=["POST"])
    @csrf.exempt
    def exempt():
        form = CustomForm()

        if form.validate_on_submit():
            return "good"

        return form.csrf_token.errors[0]

    global_token, form_token = client.get("/").get_data(as_text=True).split("|")
    assert global_token != form_token

    # CSRFProtect accepts the global token, but the form must still run
    # its own validation and reject it under its own secret
    response = client.post("/", data={"csrf_token": global_token})
    assert response.get_data(as_text=True) == "The CSRF token is invalid."

    # the custom form accepts its own token when protect is not in the way
    response = client.post("/exempt", data={"csrf_token": form_token})
    assert response.get_data(as_text=True) == "good"

    # ... and still rejects the global token
    response = client.post("/exempt", data={"csrf_token": global_token})
    assert response.get_data(as_text=True) == "The CSRF token is invalid."


def test_two_forms_mixed_submission(app, client):
    csrf = CSRFProtect(app)

    class CustomForm(FlaskForm):
        class Meta:
            csrf_secret = "form-secret"
            csrf_field_name = "custom_csrf"

    @app.route("/", methods=["GET"])
    def index():
        default_form = FlaskForm()
        custom_form = CustomForm()
        return (
            f"{default_form.csrf_token.current_token}"
            f"|{custom_form.custom_csrf.current_token}"
        )

    @app.route("/default", methods=["POST"])
    def default_submit():
        form = FlaskForm()

        if form.validate_on_submit():
            return "default-good"

        return form.csrf_token.errors[0]

    @app.route("/custom", methods=["POST"])
    @csrf.exempt
    def custom_submit():
        form = CustomForm()

        if form.validate_on_submit():
            return "custom-good"

        return form.custom_csrf.errors[0]

    default_token, custom_token = client.get("/").get_data(as_text=True).split("|")
    assert default_token != custom_token

    # each form accepts its own token
    response = client.post("/default", data={"csrf_token": default_token})
    assert response.get_data(as_text=True) == "default-good"
    response = client.post("/custom", data={"custom_csrf": custom_token})
    assert response.get_data(as_text=True) == "custom-good"

    # cross-submitting tokens fails
    response = client.post("/default", data={"csrf_token": custom_token})
    assert response.status_code == 400
    response = client.post("/custom", data={"custom_csrf": default_token})
    assert response.get_data(as_text=True) == "The CSRF token is invalid."


def test_shorter_time_limit_not_exempted(app, client, monkeypatch):
    import itsdangerous.timed

    CSRFProtect(app)

    clock = SimpleNamespace(now=1_000_000)
    monkeypatch.setattr(
        itsdangerous.timed, "time", SimpleNamespace(time=lambda: clock.now)
    )

    class ShortLivedForm(FlaskForm):
        class Meta:
            csrf_time_limit = 60

    @app.route("/", methods=["GET", "POST"])
    def index():
        form = ShortLivedForm()

        if form.validate_on_submit():
            return "good"

        if form.errors:
            return form.csrf_token.errors[0]

        return form.csrf_token.current_token

    token = client.get("/").get_data(as_text=True)
    clock.now += 120  # beyond the form's limit, within the global limit

    response = client.post("/", data={"csrf_token": token})
    assert response.get_data(as_text=True) == "The CSRF token has expired."


def test_failed_validation_then_retry(app, client):
    class CustomForm(FlaskForm):
        class Meta:
            csrf_secret = "form-secret"

    @app.route("/", methods=["GET", "POST"])
    def index():
        form = CustomForm()

        if form.validate_on_submit():
            return "good"

        if form.errors:
            return form.csrf_token.errors[0]

        return form.csrf_token.current_token

    token = client.get("/").get_data(as_text=True)

    response = client.post("/", data={"csrf_token": "forged"})
    assert response.get_data(as_text=True) == "The CSRF token is invalid."

    response = client.post("/", data={"csrf_token": token})
    assert response.get_data(as_text=True) == "good"

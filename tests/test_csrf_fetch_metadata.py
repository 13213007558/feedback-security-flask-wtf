import pytest
from flask import Blueprint
from flask import request

from flask_wtf.csrf import CSRFError
from flask_wtf.csrf import CSRFMetadataError
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf

BOUNDARY = "----flaskwtffetchmetadataboundary"


class CountingStream:
    """Wrap ``wsgi.input`` and record every byte the application reads."""

    def __init__(self, stream):
        self._stream = stream
        self.bytes_read = 0

    def read(self, size=-1):
        data = self._stream.read(size)
        self.bytes_read += len(data)
        return data

    def readline(self, size=-1):
        data = self._stream.readline(size)
        self.bytes_read += len(data)
        return data

    def readlines(self, hint=-1):
        lines = self._stream.readlines(hint)

        for line in lines:
            self.bytes_read += len(line)

        return lines

    def __iter__(self):
        for line in self._stream:
            self.bytes_read += len(line)
            yield line

    def seekable(self):
        return self._stream.seekable()

    def seek(self, *args):
        return self._stream.seek(*args)

    def tell(self):
        return self._stream.tell()

    def close(self):
        return self._stream.close()


class CountingMiddleware:
    def __init__(self, app, streams):
        self.app = app
        self.streams = streams

    def __call__(self, environ, start_response):
        stream = CountingStream(environ["wsgi.input"])
        environ["wsgi.input"] = stream
        self.streams.append(stream)
        return self.app(environ, start_response)


def multipart_body(token=None):
    """Return raw multipart bytes carrying a one-megabyte file part."""

    parts = []

    if token is not None:
        parts.append(f"--{BOUNDARY}\r\n".encode())
        parts.append(
            b'Content-Disposition: form-data; name="csrf_token"\r\n\r\n'
        )
        parts.append(token.encode())
        parts.append(b"\r\n")

    parts.append(f"--{BOUNDARY}\r\n".encode())
    parts.append(
        b'Content-Disposition: form-data; name="file"; filename="big.bin"\r\n'
    )
    parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
    parts.append(b"x" * (1024 * 1024))
    parts.append(b"\r\n")
    parts.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(parts)


MULTIPART_HEADERS = {"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}


@pytest.fixture
def app(app):
    csrf = CSRFProtect(app)
    app.config["WTF_CSRF_FETCH_METADATA"] = True
    events = []

    @app.route("/", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def index():
        events.append(("index", request.method))
        return "ok"

    @app.route("/upload", methods=["POST"])
    def upload():
        events.append(("upload", request.files["file"].filename))
        return "ok"

    @app.route("/exempt", methods=["POST"])
    @csrf.exempt
    def exempt():
        events.append(("exempt", request.method))
        return "ok"

    @app.route("/cross-site", methods=["POST"])
    @csrf.allow_cross_site
    def cross_site():
        events.append(("cross-site", request.method))
        return "ok"

    bp = Blueprint("public", __name__, url_prefix="/public")
    csrf.allow_cross_site(bp)

    @bp.route("/", methods=["POST"])
    def public():
        events.append(("public", request.method))
        return "ok"

    app.register_blueprint(bp)

    @app.after_request
    def add_csrf_header(response):
        response.headers.set("X-CSRF-Token", generate_csrf())
        return response

    @app.errorhandler(CSRFMetadataError)
    def handle_metadata_error(error):
        return f"metadata:{error.description}", 400

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        return f"token:{error.description}", 400

    streams = []
    app.wsgi_app = CountingMiddleware(app.wsgi_app, streams)

    form_accesses = []

    class TrackingRequest(app.request_class):
        @property
        def form(self):
            form_accesses.append("form")
            return super().form

        @property
        def files(self):
            form_accesses.append("files")
            return super().files

    app.request_class = TrackingRequest
    app.extensions["csrf_test_state"] = {
        "events": events,
        "streams": streams,
        "form_accesses": form_accesses,
    }
    return app


@pytest.fixture
def csrf(app):
    return app.extensions["csrf"]


@pytest.fixture
def streams(app):
    return app.extensions["csrf_test_state"]["streams"]


@pytest.fixture
def events(app):
    return app.extensions["csrf_test_state"]["events"]


@pytest.fixture
def form_accesses(app):
    return app.extensions["csrf_test_state"]["form_accesses"]


def test_cross_site_write_rejected_without_touching_body(
    client, streams, events, form_accesses
):
    response = client.post(
        "/",
        data=multipart_body(),
        headers={**MULTIPART_HEADERS, "Sec-Fetch-Site": "cross-site"},
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("metadata:")
    assert streams[-1].bytes_read == 0
    assert form_accesses == []
    assert events == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_all_protected_methods_rejected_cross_site(
    client, streams, events, form_accesses, method
):
    response = client.open(
        "/",
        method=method,
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("metadata:")
    assert streams[-1].bytes_read == 0
    assert form_accesses == []
    assert events == []


def test_cross_site_form_submission_navigation_rejected(
    client, streams, events, form_accesses
):
    response = client.post(
        "/",
        data=multipart_body(),
        headers={
            **MULTIPART_HEADERS,
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document",
        },
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("metadata:")
    assert streams[-1].bytes_read == 0
    assert form_accesses == []
    assert events == []


def test_safe_methods_never_metadata_rejected(client, events):
    response = client.get("/", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 200

    response = client.options("/", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 200

    assert events == [("index", "GET")]


def test_none_write_rejected_safe_request_allowed(
    client, streams, events, form_accesses
):
    response = client.post(
        "/",
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "none",
        },
    )
    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("metadata:")
    assert streams[-1].bytes_read == 0
    assert form_accesses == []
    assert events == []

    response = client.get("/", headers={"Sec-Fetch-Site": "none"})
    assert response.status_code == 200


def test_none_safe_method_with_custom_protected_methods(app, client):
    app.config["WTF_CSRF_METHODS"] = {"GET", "POST"}

    response = client.get(
        "/",
        headers={"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"},
    )
    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("token:")


def test_same_site_still_requires_token(client, streams):
    response = client.post(
        "/",
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "same-site",
        },
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("token:")
    assert streams[-1].bytes_read > 0


def test_same_origin_still_requires_token(client, streams):
    response = client.post(
        "/",
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "same-origin",
        },
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("token:")
    assert streams[-1].bytes_read > 0


def test_same_origin_with_valid_token_passes_and_reads_body(
    client, streams, events, form_accesses
):
    token = client.get("/", headers={"Sec-Fetch-Site": "same-origin"}).headers[
        "X-CSRF-Token"
    ]

    response = client.post(
        "/upload",
        data=multipart_body(token),
        headers={**MULTIPART_HEADERS, "Sec-Fetch-Site": "same-origin"},
    )

    assert response.status_code == 200
    assert streams[-1].bytes_read > 0
    assert "files" in form_accesses
    assert ("upload", "big.bin") in events


def test_missing_header_defaults_to_token_check(client, streams):
    response = client.post(
        "/",
        data="field=value",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("token:")
    assert streams[-1].bytes_read > 0


def test_missing_header_can_be_rejected_before_body_read(
    app, client, streams, events, form_accesses
):
    app.config["WTF_CSRF_FETCH_METADATA_MISSING"] = "reject"

    response = client.post("/", data=multipart_body(), headers=MULTIPART_HEADERS)

    assert response.status_code == 400
    assert response.get_data(as_text=True) == (
        "metadata:The Sec-Fetch-Site header is missing."
    )
    assert streams[-1].bytes_read == 0
    assert form_accesses == []
    assert events == []


def test_unknown_site_value_rejected(client, streams, events, form_accesses):
    response = client.post(
        "/",
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "made-up-value",
        },
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("metadata:")
    assert streams[-1].bytes_read == 0
    assert form_accesses == []
    assert events == []


def test_allow_cross_site_view_skips_metadata_but_keeps_token(
    client, streams, events
):
    response = client.post(
        "/cross-site",
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("token:")
    assert streams[-1].bytes_read > 0
    assert events == []

    token = client.get("/").headers["X-CSRF-Token"]
    response = client.post(
        "/cross-site",
        headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": token},
    )

    assert response.status_code == 200
    assert ("cross-site", "POST") in events


def test_allow_cross_site_blueprint(client):
    response = client.post(
        "/public/",
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("token:")

    token = client.get("/").headers["X-CSRF-Token"]
    response = client.post(
        "/public/",
        headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": token},
    )

    assert response.status_code == 200


def test_exempt_view_remains_fully_exempt_cross_site(client, events):
    response = client.post(
        "/exempt",
        data=multipart_body(),
        headers={**MULTIPART_HEADERS, "Sec-Fetch-Site": "cross-site"},
    )

    assert response.status_code == 200
    assert ("exempt", "POST") in events


def test_disabled_policy_preserves_existing_behavior(app, client, streams):
    app.config["WTF_CSRF_FETCH_METADATA"] = False

    response = client.post(
        "/",
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("token:")
    assert streams[-1].bytes_read > 0


def test_manual_protect_runs_metadata_gate(
    app, csrf, client, streams, events, form_accesses
):
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False

    @app.before_request
    def manual():
        csrf.protect(apply_exemptions=True)

    response = client.post(
        "/",
        data=multipart_body(),
        headers={**MULTIPART_HEADERS, "Sec-Fetch-Site": "cross-site"},
    )

    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("metadata:")
    assert streams[-1].bytes_read == 0
    assert form_accesses == []
    assert events == []

    response = client.post(
        "/exempt", headers={"Sec-Fetch-Site": "cross-site"}
    )
    assert response.status_code == 200


def test_cross_site_navigation_allowed_when_method_protected(app, client):
    app.config["WTF_CSRF_METHODS"] = {"GET", "POST"}

    navigation_headers = {
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }

    response = client.get("/", headers=navigation_headers)
    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("token:")

    response = client.get(
        "/",
        headers={**navigation_headers, "Sec-Fetch-Mode": "cors"},
    )
    assert response.status_code == 400
    assert response.get_data(as_text=True).startswith("metadata:")


def test_metadata_error_is_csrf_error_subclass():
    assert issubclass(CSRFMetadataError, CSRFError)


def test_metadata_rejection_logged(client, monkeypatch):
    from flask_wtf.csrf import logger

    messages = []
    monkeypatch.setattr(logger, "info", messages.append)

    client.post(
        "/",
        data="field=value",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Sec-Fetch-Site": "cross-site",
        },
    )

    assert messages == [
        "Cross-site state-changing request rejected by Fetch Metadata."
    ]


def test_default_app_keeps_policy_disabled():
    from conftest import Flask

    fresh_app = Flask(__name__)
    CSRFProtect(fresh_app)

    assert fresh_app.config["WTF_CSRF_FETCH_METADATA"] is False
    assert fresh_app.config["WTF_CSRF_FETCH_METADATA_MISSING"] == "allow"

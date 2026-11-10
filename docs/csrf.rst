.. currentmodule:: flask_wtf.csrf

.. _csrf:

CSRF Protection
===============

Any view using :class:`~flask_wtf.FlaskForm` to process the request is already
getting CSRF protection. If you have views that don't use ``FlaskForm`` or make
AJAX requests, use the provided CSRF extension to protect those requests as
well.

Setup
-----

To enable CSRF protection globally for a Flask app, register the
:class:`CSRFProtect` extension. ::

    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect(app)

Like other Flask extensions, you can apply it lazily::

    csrf = CSRFProtect()

    def create_app():
        app = Flask(__name__)
        csrf.init_app(app)

.. note::

    CSRF protection requires a secret key to securely sign the token. By default
    this will use the Flask app's ``SECRET_KEY``. If you'd like to use a
    separate token you can set ``WTF_CSRF_SECRET_KEY``.

.. warning::

    Make sure your webserver cache policy wont't interfere with the CSRF protection.
    If pages are cached longer than the ``WTF_CSRF_TIME_LIMIT`` value, then user browsers
    may serve cached page including expired CSRF token, resulting in random *Invalid*
    or *Expired* CSRF errors.

HTML Forms
----------

When using a ``FlaskForm``, render the form's CSRF field like normal.

.. sourcecode:: html+jinja

    <form method="post">
        {{ form.csrf_token }}
    </form>

If the template doesn't use a ``FlaskForm``, render a hidden input with the
token in the form.

.. sourcecode:: html+jinja

    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    </form>

The ``name`` attribute must match the ``WTF_CSRF_FIELD_NAME`` setting
(``'csrf_token'`` by default). Otherwise the request fails with a
``Bad Request: CSRF token missing`` error. Change the setting if you need a
different field name.

HTML Meta Tag
-------------

For JavaScript clients, the recommended way to expose the token to the page is
to render it in a ``<meta>`` tag in the document ``<head>``. This is the
convention used by Rails and recommended by the
`OWASP CSRF prevention cheat sheet`_.

.. sourcecode:: html+jinja

    <head>
        {{ csrf_meta_tag() }}
    </head>

This renders ``<meta name="csrf-token" content="...">``. The attribute name is
configurable via the ``WTF_CSRF_META_NAME`` setting, or per-call with the
``name`` argument: ``{{ csrf_meta_tag(name="authenticity-token") }}``.

.. _OWASP CSRF prevention cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#storing-the-csrf-token-value-in-the-dom

JavaScript Requests
-------------------

When sending an AJAX request, read the token from the meta tag and send it in
the ``X-CSRFToken`` header. This pattern is compatible with a strict
``Content-Security-Policy`` since no inline script is required.

Using ``fetch``:

.. sourcecode:: javascript

    const token = document.querySelector('meta[name="csrf-token"]').content;

    fetch("/api/resource", {
        method: "POST",
        headers: { "X-CSRFToken": token, "Content-Type": "application/json" },
        body: JSON.stringify(data),
    });

Using Axios, configure the default header once at startup:

.. sourcecode:: javascript

    axios.defaults.headers.common["X-CSRFToken"] =
        document.querySelector('meta[name="csrf-token"]').content;

Reject cross-site requests early with Fetch Metadata
-----------------------------------------------------

Without any extra header, a cross-site form submission reaches the token check
only after the whole request body, including large multipart uploads, has been
parsed. Modern browsers send `Fetch Metadata`_ headers such as
``Sec-Fetch-Site``, which identify the request context before the body is read.
Enable an optional pre-token policy with
``WTF_CSRF_FETCH_METADATA = True`` to reject obvious cross-site write requests
up front.

The policy only runs for the methods in ``WTF_CSRF_METHODS``; safe methods
(``GET``, ``HEAD``, ``OPTIONS``, ``TRACE``) are always allowed. The
``Sec-Fetch-Site`` value is handled as follows:

- ``same-origin`` and ``same-site`` proceed to the normal CSRF token check.
  The header identifies the browsing context, it does not authenticate the
  request, so ``same-site`` is never an automatic token exemption.
- ``none`` is accepted for safe requests, for example a top-level URL typed by
  the user, and rejected for state-changing requests.
- ``cross-site`` is rejected, including top-level form-submission navigations,
  except for safe top-level document navigations.
- An unrecognized value is rejected.
- A missing header means the client may be an older browser or a non-browser
  caller. By default such requests fall through to the token check
  (``WTF_CSRF_FETCH_METADATA_MISSING = 'allow'``); set it to ``'reject'`` to
  refuse them before the body is read.

These headers cannot prove that a non-browser caller is trustworthy, since any
client can send arbitrary header values. They are an additional layer in front
of the token check, not a replacement for it.

A cross-site entry point that is expected to receive browser writes can be
declared with :meth:`~flask_wtf.csrf.CSRFProtect.allow_cross_site`. The target
skips the metadata decision but still goes through every other CSRF check; use
:meth:`~flask_wtf.csrf.CSRFProtect.exempt` as before to opt out completely. ::

    @app.route('/webhook', methods=['POST'])
    @csrf.allow_cross_site
    def webhook():
        ...

A metadata rejection raises :class:`CSRFMetadataError`, a subclass of
:class:`CSRFError`. Existing ``CSRFError`` handlers keep working, while a
dedicated handler can tell metadata rejections apart from invalid or missing
tokens.

.. _Fetch Metadata: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Fetch-Site

Customize the error response
----------------------------

When CSRF validation fails, it will raise a :class:`CSRFError`.
By default this returns a response with the failure reason and a 400 code.
You can customize the error response using Flask's
:meth:`~flask.Flask.errorhandler`. ::

    from flask_wtf.csrf import CSRFError

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template('csrf_error.html', reason=e.description), 400

Exclude views from protection
-----------------------------

We strongly suggest that you protect all your views with CSRF. But if
needed, you can exclude some views using a decorator. ::

    @app.route('/foo', methods=('GET', 'POST'))
    @csrf.exempt
    def my_handler():
        # ...
        return 'ok'

You can exclude all the views of a blueprint. ::

    csrf.exempt(account_blueprint)

You can disable CSRF protection in all views by default, by setting
``WTF_CSRF_CHECK_DEFAULT`` to ``False``, and selectively call
:meth:`~flask_wtf.csrf.CSRFProtect.protect` only when you need. This also enables you to do some
pre-processing on the requests before checking for the CSRF token. ::

    @app.before_request
    def check_csrf():
        if not is_oauth(request):
            csrf.protect()

Pass ``apply_exemptions=True`` to keep ``@csrf.exempt`` working in this mode.
The call will skip validation for views and blueprints marked as exempt. ::

    @app.before_request
    def check_csrf():
        if not is_oauth(request):
            csrf.protect(apply_exemptions=True)

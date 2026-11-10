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

Exemption scopes
~~~~~~~~~~~~~~~~

:meth:`~flask_wtf.csrf.CSRFProtect.exempt` accepts three kinds of arguments,
each with a precise scope. Matching always happens against the endpoint
selected by real URL matching during the request, never against a name lookup
at registration time.

- **View function** (the decorator form above): the exact function object is
  exempt, identified by object identity rather than its
  ``__module__.__name__`` string. Register the same function on several
  endpoints and every endpoint serving it is exempt. Two different functions
  that end up with the same name -- two wrappers built with
  :func:`functools.wraps`, for example -- never share an exemption.
- **Endpoint name** (a string): pass an endpoint such as
  ``csrf.exempt('account.login')`` and only that endpoint is exempt. An
  unknown or not-yet-registered name matches nothing.
- **Blueprint** (a :class:`~flask.Blueprint` object): every endpoint of that
  blueprint object is exempt, including when the same blueprint is registered
  on an app under several names. A different blueprint object that happens to
  share a name is not affected.

Because view exemptions track the registered object, apply the decorator to
the view Flask actually registers. Place it directly under the route
decorator::

    @app.route('/foo', methods=['POST'])
    @csrf.exempt
    def foo():
        ...

If another decorator wraps the view *outside* ``@csrf.exempt``, Flask
registers the wrapper instead, so the view stays protected. Either move
``@csrf.exempt`` outermost or exempt the endpoint by name::

    csrf.exempt('foo')

When one ``CSRFProtect`` instance is initialized on several apps, view and
blueprint exemptions follow the shared function and blueprint objects into
every app; endpoint-name exemptions are evaluated independently against each
app's URL map.

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
The call will skip validation for views, endpoints and blueprints marked as
exempt. A manual ``protect()`` without the flag never applies exemptions. ::

    @app.before_request
    def check_csrf():
        if not is_oauth(request):
            csrf.protect(apply_exemptions=True)

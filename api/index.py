import sys
import os
import traceback

# Make the root project directory importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app, db
    
    # Initialize the database (creates tables if they don't exist in Postgres)
    with app.app_context():
        db.create_all()

    # Vercel WSGI Proxy Fix
    class VercelProxyFix:
        def __init__(self, app):
            self.app = app
        def __call__(self, environ, start_response):
            # Vercel zero-config rewrites sometimes pass the destination path instead of the original
            path = environ.get('PATH_INFO', '')
            if path.startswith('/api/index'):
                # Try to recover the original path from Vercel headers
                # x-now-route-matches usually contains the original matched route
                # fallback to just removing /api/index
                environ['PATH_INFO'] = path.replace('/api/index', '', 1) or '/'
            return self.app(environ, start_response)
            
    app.wsgi_app = VercelProxyFix(app.wsgi_app)

except Exception as e:
    # Return the full traceback as an HTTP 500 so we can read it in the browser
    from flask import Flask, Response
    app = Flask(__name__)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def catch_all(path):
        tb = traceback.format_exc()
        return Response(f"<pre>IMPORT ERROR:\n{tb}</pre>", status=500, mimetype='text/html')

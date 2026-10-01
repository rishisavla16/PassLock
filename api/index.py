import sys
import os
import traceback

# Make the root project directory importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app
except Exception as e:
    # Return the full traceback as an HTTP 500 so we can read it in the browser
    from flask import Flask, Response
    app = Flask(__name__)

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def catch_all(path):
        tb = traceback.format_exc()
        return Response(f"<pre>IMPORT ERROR:\n{tb}</pre>", status=500, mimetype='text/html')

from flask import Flask
from flask_cors import CORS
from src.web.routes.api import api_blueprint
from src.web.routes.dashboard import dashboard_blueprint
from src.web.routes.webhooks import webhook_blueprint

def create_app():
    app = Flask(__name__)
    CORS(app)  # Enable CORS for all routes

    # Register blueprints for different routes
    app.register_blueprint(api_blueprint, url_prefix='/api')
    app.register_blueprint(dashboard_blueprint, url_prefix='/dashboard')
    app.register_blueprint(webhook_blueprint, url_prefix='/webhooks')

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
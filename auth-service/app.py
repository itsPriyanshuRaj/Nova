from flask import Flask, jsonify, request
from config import Config
from routes import auth_bp 
from mongoengine import connect 
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app():
    """
    Creates and configures the Flask application instance for the Auth Service.
    """
    app = Flask(__name__)
    app.config.from_object(Config) 

    try:
        connect(db=Config.MONGO_URI.split('/')[-1], host=Config.MONGO_URI)
        logger.info("Successfully connected to MongoDB for Auth Service.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB for Auth Service: {e}", exc_info=True)
        
    app.register_blueprint(auth_bp, url_prefix='/auth')

    @app.route('/health', methods=['GET'])
    def health_check():
        logger.info("Auth service health check requested.")
        return jsonify({"status": "Auth Service is up and running!"}), 200

    @app.errorhandler(400)
    def bad_request_error(error):
        logger.warning(f"400 Bad Request: {request.url} - {error}")
        return jsonify({"error": "Bad Request", "message": str(error)}), 400

    @app.errorhandler(401)
    def unauthorized_error(error):
        logger.warning(f"401 Unauthorized: {request.url} - {error}")
        return jsonify({"error": "Unauthorized", "message": "Authentication required or invalid credentials."}), 401

    @app.errorhandler(404)
    def not_found_error(error):
        logger.warning(f"404 Not Found: {request.url}")
        return jsonify({"error": "Not Found", "message": "The requested URL was not found on this server."}), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        logger.error(f"Internal Server Error: {error}", exc_info=True)
        return jsonify({"error": "Internal Server Error", "message": "Something went wrong on the server."}), 500

    logger.info("Auth Service application created and configured.")
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', port=Config.AUTH_SERVICE_PORT, debug=Config.DEBUG)
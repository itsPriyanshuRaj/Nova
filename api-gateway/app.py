from flask import Flask, request, jsonify, redirect
from config import Config
from services import GatewayService
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config) 

    gateway_service = GatewayService()

    @app.route('/health', methods=['GET'])
    def health_check():
        logger.info("API Gateway health check requested.")
        return jsonify({"status": "API Gateway is up and running!"}), 200

    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    def proxy_request(path):
        logger.info(f"Incoming request: {request.method} /{path}")

        auth_header = request.headers.get('Authorization')
        
        try:
            response_data, status_code, response_headers = gateway_service.forward_request(
                method=request.method,
                path=path,
                json_data=request.get_json(silent=True),
                headers=dict(request.headers)
            )
            
            response = jsonify(response_data)
            response.status_code = status_code
            
            excluded_headers = ['Content-Encoding', 'Content-Length', 'Transfer-Encoding', 'Connection']
            for key, value in response_headers.items():
                if key not in excluded_headers:
                    response.headers[key] = value

            logger.info(f"Forwarded request to /{path}, response status: {status_code}")
            return response

        except Exception as e:
            logger.error(f"Error processing request for path /{path}: {e}", exc_info=True)
            return jsonify({"error": "Gateway Error", "message": str(e)}), 500

    @app.errorhandler(404)
    def not_found_error(error):
        logger.warning(f"404 Not Found at Gateway: {request.url}")
        return jsonify({"error": "Not Found", "message": "The requested API endpoint does not exist."}), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        logger.error(f"Internal Server Error at Gateway: {error}", exc_info=True)
        return jsonify({"error": "Internal Server Error", "message": "Something went wrong in the API Gateway."}), 500

    logger.info("API Gateway application created and configured.")
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', port=Config.API_GATEWAY_PORT, debug=Config.DEBUG)
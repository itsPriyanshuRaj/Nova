from flask import Flask , jsonify, request
from config import Config
from routes import admin_bp
import logging


#configuration loggin for the appliation
logging.basicConfig(level = logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.register_blueprint(admin_bp, url_prefix='/admin')

    @app.route('/admin/health',methods=['GET'])
    def health_check():
        logger.info("Admin service health check requsted.")
        return jsonify({"status": "Admin service is up and running"}),200
    
    @app.errorhandler(404)
    def not_found_error(error):
        logger.warn(f"404 Not found : {request.url}")
        return jsonify({"error":"Not found" , "meesage": "The request URL is not available!!!"})
    
    @app.errorhandler(500)
    def internal_server_error(error):
        logger.eroor(f"Interal Server Error: {error}", exc_info=True)
        return jsonify({"error":"Internal Server error, Something went wrong"})
    
    logger.info("Admin service application created and configured")
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', port=Config.ADMIN_SERVICE_PORT, debug = Config.DEBUG)

from flask import Blueprint, request, jsonify
from services import AdminService
from functools import wraps
import logging

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin_bp', __name__)
admin_service = AdminService()

# helper for auth/authorization
def admin_req(f):
    @wraps(f)
    def decorated_func(*args, **kwargs):
        logger.debug(f"Admin required decorator: Request to {request.path}")
        return f(*args, **kwargs)
    return decorated_func

# Producy management routes
@admin_bp.route('/products', methods=['POST'])
@admin_req
def create_product():
    data  = request.get_json()
    if not data:
        return jsonify({"Message" : "Request must contain JSON data"}),400
    logger.info(f"Admin creating product: {data.get('name')}")

    try:
        product = admin_service.create_product(data)
        return jsonify(product),201
    except Exception as e:
        logger.error(f"Error cathcing product: {e}", exc_info=True)
        return jsonify({"message":"Failed to create product","error":str(e)}),500
    

@admin_bp.route('/products/<string:product_id>', methods=['PUT'])
@admin_req
def update_product(product_id):
    data = request.get_json()
    if not data:
        return jsonify({"message":"Request must contain JSON data"}),400
    logger.info(f"Admin updating product ID:{product_id}")

    try:
        product = admin_service.update_product(product_id,data)
        if product:
            return jsonify(product),200
        return jsonify({"message":"Product not found"}),400
    except Exception as e:
        logger.error(f"Error updating product {product_id}: {e}", exc_info=True)
        return jsonify({"message": "Failed to update product", "error": str(e)}), 500
    


                
    


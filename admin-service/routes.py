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
    
    
@admin_bp.route('/product/<string:product_id>',methods=['DELETE'])
@admin_req
def delete_product(product_id):
    logger.info(f"Admin deleting product ID:{product_id}")

    try:
        success = admin_service.delete_product(product_id)
        if success:
            return jsonify({"message": "Product deleted successfully"}), 204
        return jsonify({"message":"Product not found"}),404
    except Exception as e:
        logger.error(f"Error deleting product {product_id}: {e}", exc_info=True)
        return jsonify({"message": "Failed to delete product", "error": str(e)}), 500

@admin_bp.route("/products", methods=['GET'])
@admin_req
def get_all_products():
    logger.info("Admin requesting all products.")
    try:
        products = admin_service.get_all_products()
        return jsonify(products),200
    except Exception as e:
        logger.error(f"Error getting all products: {e}", exc_info=True)
        return jsonify({"message": "Failed to retrieve products", "error": str(e)}), 500


# User Management Routes

@admin_bp.route("/users", methods=['GET'])
@admin_req
def get_all_users():
    logger.info("Admin requesting all users")
    try:
        users = admin_service.get_all_users()
        return jsonify(users),200
    except Exception as e:
        logger.error(f"Error getting all users: {e}",exc_info=True)
        return jsonify({"message":"Failed to retrieve users","error":str(e)}),500
    

@admin_bp.route("/users/<string:user_id>", methods=['PUT'])
@admin_req
def update_user(user_id):
    data = request.get_json()
    if not data:
        return jsonify({"message": "Request must contain JSON data"}),400
    logger.info(f"admin updating userID: {user_id}")

    try:
        user = admin_service.update_user(user_id,data)
        if user:
            return jsonify(user),200
        return jsonify({"message":"user not found"}),404
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}",exc_info=True)
        return jsonify({"message":"Failed to update user", "error":str(e)}),500
    
# --- Order Management Routes ---

@admin_bp.route('/orders', methods=['GET'])
@admin_req
def get_all_orders():
    logger.info("Admin requesting all orders.")
    try:
        orders = admin_service.get_all_orders()
        return jsonify(orders), 200
    except Exception as e:
        logger.error(f"Error getting all orders: {e}", exc_info=True)
        return jsonify({"message": "Failed to retrieve orders", "error": str(e)}), 500

@admin_bp.route('/orders/<string:order_id>/status', methods=['PUT'])
@admin_req
def update_order_status(order_id):
   
    data = request.get_json()
    new_status = data.get('status')
    if not new_status:
        return jsonify({"message": "Status field is required"}), 400
    logger.info(f"Admin updating order {order_id} status to: {new_status}")
    try:
        order = admin_service.update_order_status(order_id, new_status)
        if order:
            return jsonify(order), 200
        return jsonify({"message": "Order not found"}), 404
    except Exception as e:
        logger.error(f"Error updating order {order_id} status: {e}", exc_info=True)
        return jsonify({"message": "Failed to update order status", "error": str(e)}), 500

# --- Other Admin Specific Routes (Examples) ---

@admin_bp.route('/analytics/sales', methods=['GET'])
@admin_req
def get_sales_analytics():
    
    logger.info("Admin requesting sales analytics.")
    try:
        analytics_data = admin_service.get_sales_analytics()
        return jsonify(analytics_data), 200
    except Exception as e:
        logger.error(f"Error getting sales analytics: {e}", exc_info=True)
        return jsonify({"message": "Failed to retrieve sales analytics", "error": str(e)}), 500

@admin_bp.route('/logs', methods=['GET'])
@admin_req
def get_admin_logs():
    logger.info("Admin requesting internal action logs.")
    try:
        logs = admin_service.get_admin_logs()
        return jsonify(logs), 200
    except Exception as e:
        logger.error(f"Error retrieving admin logs: {e}", exc_info=True)
        return jsonify({"message": "Failed to retrieve admin logs", "error": str(e)}), 500

                
    


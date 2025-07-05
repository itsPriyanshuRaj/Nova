from flask import Blueprint, request, jsonify
from service import AuthService
import logging

logger = logging.getLogger(__name__)

# Create a Blueprint for authentication routes.
auth_bp = Blueprint('auth_bp', __name__)

auth_service = AuthService()

@auth_bp.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    if not data:
        logger.warning("Register request: No JSON data provided.")
        return jsonify({"message": "Request must contain JSON data"}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        logger.warning("Register request: Missing required fields.")
        return jsonify({"message": "Missing username, email, or password"}), 400

    try:
        user = auth_service.register_user(username, email, password)
        logger.info(f"User registered successfully: {user.email}")
        return jsonify(user.to_dict()), 201
    except ValueError as e:
        logger.warning(f"Registration failed: {e}")
        return jsonify({"message": str(e)}), 409 
    except Exception as e:
        logger.error(f"Error during user registration: {e}", exc_info=True)
        return jsonify({"message": "Failed to register user", "error": str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data:
        logger.warning("Login request: No JSON data provided.")
        return jsonify({"message": "Request must contain JSON data"}), 400

    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        logger.warning("Login request: Missing email or password.")
        return jsonify({"message": "Missing email or password"}), 400

    try:
        user, access_token, refresh_token = auth_service.authenticate_user(email, password)
        logger.info(f"User logged in successfully: {user.email}")
        return jsonify({
            "user": user.to_dict(),
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 200
    except ValueError as e:
        logger.warning(f"Login failed: {e}")
        return jsonify({"message": str(e)}), 401 
    except Exception as e:
        logger.error(f"Error during user login: {e}", exc_info=True)
        return jsonify({"message": "Failed to log in", "error": str(e)}), 500


#to refresh auth token
@auth_bp.route('/refreshToken', methods=['POST'])
def refresh_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning("Refresh token request: Missing or malformed Authorization header.")
        return jsonify({"message": "Refresh token required"}), 401

    refresh_token = auth_header.split(" ")[1]

    try:
        new_access_token = auth_service.refresh_access_token(refresh_token)
        logger.info("Access token refreshed successfully.")
        return jsonify({"access_token": new_access_token}), 200
    except ValueError as e:
        logger.warning(f"Token refresh failed: {e}")
        return jsonify({"message": str(e)}), 401
    except Exception as e:
        logger.error(f"Error during token refresh: {e}", exc_info=True)
        return jsonify({"message": "Failed to refresh token", "error": str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout_user():
    access_token_header = request.headers.get('Authorization')
    refresh_token_header = request.headers.get('X-Refresh-Token') # Custom header for refresh token

    if not access_token_header or not access_token_header.startswith('Bearer '):
        logger.warning("Logout request: Missing or malformed access token header.")
        return jsonify({"message": "Access token required for logout"}), 401

    access_token = access_token_header.split(" ")[1]

    try:
        # Blacklist the access token
        auth_service.blacklist_token(access_token, 'access')

        if refresh_token_header and refresh_token_header.startswith('Bearer '):
            refresh_token = refresh_token_header.split(" ")[1]
            auth_service.blacklist_token(refresh_token, 'refresh')
            logger.info("Access and Refresh tokens blacklisted successfully.")
        else:
            logger.info("Access token blacklisted successfully.")

        return jsonify({"message": "Logged out successfully"}), 200
    except ValueError as e:
        logger.warning(f"Logout failed: {e}")
        return jsonify({"message": str(e)}), 400 
    except Exception as e:
        logger.error(f"Error during logout: {e}", exc_info=True)
        return jsonify({"message": "Failed to logout", "error": str(e)}), 500

@auth_bp.route('/me', methods=['GET'])
def get_current_user():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning("Get current user request: Missing or malformed Authorization header.")
        return jsonify({"message": "Access token required"}), 401

    access_token = auth_header.split(" ")[1]

    try:
        # This will validate the token and return its payload
        payload = auth_service.decode_token(access_token)
        user_id = payload.get('user_id')

        user = auth_service.get_user_by_id(user_id)
        if user:
            logger.info(f"Retrieved details for user: {user.email}")
            return jsonify(user.to_dict()), 200
        else:
            logger.warning(f"User not found for ID: {user_id} from token.")
            return jsonify({"message": "User not found"}), 404
    except ValueError as e:
        logger.warning(f"Failed to get current user: {e}")
        return jsonify({"message": str(e)}), 401 # Invalid/expired token
    except Exception as e:
        logger.error(f"Error retrieving current user: {e}", exc_info=True)
        return jsonify({"message": "Failed to retrieve user details", "error": str(e)}), 500
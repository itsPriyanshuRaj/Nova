import requests
import logging
import jwt # For JWT validation
from config import Config

logger = logging.getLogger(__name__)

class GatewayService:
    """
    Handles the core logic for the API Gateway, including request routing
    and authentication/authorization.
    """
    def __init__(self):
        self.service_routes = Config.SERVICE_ROUTES
        self.jwt_secret = Config.JWT_SECRET_KEY
        self.jwt_algorithm = Config.JWT_ALGORITHM

    def validate_token(self, auth_header):
        """
        Validates the JWT from the Authorization header.
        Returns the decoded payload if valid, None otherwise.
        """
        if not auth_header:
            logger.warning("No Authorization header provided.")
            return None

        try:
            # Expecting "Bearer <token>"
            token = auth_header.split(" ")[1]
            # Decode the token. This will raise an exception if invalid.
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            logger.info(f"Token validated for user: {payload.get('user_id')}")
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT has expired.")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT provided.")
            return None
        except IndexError:
            logger.warning("Malformed Authorization header.")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {e}", exc_info=True)
            return None

    def get_target_service_url(self, path):
        """
        Determines the target microservice URL based on the request path.
        Iterates through defined SERVICE_ROUTES to find the best match.
        """
        # Sort routes by length in descending order to match more specific paths first
        sorted_routes = sorted(self.service_routes.items(), key=lambda item: len(item[0]), reverse=True)

        for prefix, url in sorted_routes:
            if path.startswith(prefix.strip('/')): 
                remaining_path = path[len(prefix.strip('/')):].lstrip('/')
                target_url = f"{url}/{remaining_path}"
                logger.debug(f"Routing /{path} to {target_url}")
                return target_url
        
        logger.warning(f"No matching service found for path: /{path}")
        return None 

    def forward_request(self, method, path, json_data=None, headers=None):
        """
        Forwards the incoming request to the determined microservice.
        """
        target_url = self.get_target_service_url(path)
        if not target_url:
            raise ValueError("No target service found for the given path.")

        forward_headers = {}
        if headers:
            for key, value in headers.items():
              
                if key.lower() not in ['host', 'content-length', 'transfer-encoding', 'connection']:
                    forward_headers[key] = value
        
        if 'Authorization' in headers:
            forward_headers['Authorization'] = headers['Authorization']

        try:
            logger.info(f"Forwarding {method} request to {target_url} with data: {json_data}")
            response = requests.request(
                method=method,
                url=target_url,
                json=json_data,
                headers=forward_headers,
                timeout=Config.REQUEST_TIMEOUT 
            )
            response.raise_for_status() 

          
            return response.json(), response.status_code, response.headers
        except requests.exceptions.HTTPError as http_err:
            logger.error(f"HTTP error from backend service: {http_err} - Response: {response.text}", exc_info=True)
            return response.json() if response.text else {"message": "Backend service error"}, response.status_code, response.headers
        except requests.exceptions.ConnectionError as conn_err:
            logger.error(f"Connection error to backend service: {conn_err}", exc_info=True)
            raise Exception(f"Could not connect to backend service at {target_url}")
        except requests.exceptions.Timeout as timeout_err:
            logger.error(f"Timeout connecting to backend service: {timeout_err}", exc_info=True)
            raise Exception(f"Backend service at {target_url} timed out")
        except requests.exceptions.RequestException as req_err:
            logger.error(f"An unexpected request error occurred while forwarding: {req_err}", exc_info=True)
            raise Exception(f"An error occurred during request forwarding to {target_url}")
import bcrypt 
import jwt 
from datetime import datetime, timedelta
from models import User, TokenBlacklist 
from config import Config
import logging

logger = logging.getLogger(__name__)

class AuthService:
    def __init__(self):
        self.jwt_secret = Config.JWT_SECRET_KEY
        self.jwt_algorithm = Config.JWT_ALGORITHM
        self.access_token_expires = Config.JWT_ACCESS_TOKEN_EXPIRES
        self.refresh_token_expires = Config.JWT_REFRESH_TOKEN_EXPIRES

    def hash_password(self, password):
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password.decode('utf-8') 

#   Checks if a plain-text password matches a hashed password.
    def check_password(self, password, hashed_password):  
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

    def generate_tokens(self, user_id, roles):
        now = datetime.utcnow()

        # Access Token Payload
        access_payload = {
            'user_id': str(user_id),
            'roles': roles,
            'exp': now + self.access_token_expires,
            'iat': now,
            'jti': str(User.objects.get(id=user_id).id) + '_' + str(now.timestamp()) 
        }
        access_token = jwt.encode(access_payload, self.jwt_secret, algorithm=self.jwt_algorithm)

        refresh_payload = {
            'user_id': str(user_id),
            'exp': now + self.refresh_token_expires,
            'iat': now,
            'jti': str(User.objects.get(id=user_id).id) + '_refresh_' + str(now.timestamp())
        }
        refresh_token = jwt.encode(refresh_payload, self.jwt_secret, algorithm=self.jwt_algorithm)

        logger.debug(f"Generated tokens for user_id: {user_id}")
        return access_token, refresh_token

#   decode a JWt - validat its signature and expiration, chekc blacklisted
    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            
            # Check if token is blacklisted
            jti = payload.get('jti')
            if jti and TokenBlacklist.objects(jti=jti).first():
                logger.warning(f"Attempted to use blacklisted token with JTI: {jti}")
                raise ValueError("Token has been blacklisted.")
            
            logger.debug(f"Token decoded successfully for user_id: {payload.get('user_id')}")
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired.")
            raise ValueError("Token has expired.")
        except jwt.InvalidTokenError:
            logger.warning("Invalid token provided.")
            raise ValueError("Invalid token.")
        except Exception as e:
            logger.error(f"Error decoding token: {e}", exc_info=True)
            raise ValueError("Could not decode token.")

    def register_user(self, username, email, password):
        if User.objects(email=email).first():
            raise ValueError("User with this email already exists.")
        if User.objects(username=username).first():
            raise ValueError("User with this username already exists.")

        hashed_password = self.hash_password(password)
        user = User(
            username=username,
            email=email,
            password_hash=hashed_password,
            roles=['customer'] # Default role for new users
        )
        user.save()
        logger.info(f"New user registered: {user.email}")
        return user

    def authenticate_user(self, email, password):
        user = User.objects(email=email).first()
        if not user:
            logger.warning(f"Authentication failed: User not found for email {email}.")
            raise ValueError("Invalid credentials.")

        if not self.check_password(password, user.password_hash):
            logger.warning(f"Authentication failed: Incorrect password for email {email}.")
            raise ValueError("Invalid credentials.")

        access_token, refresh_token = self.generate_tokens(user.id, user.roles)
        logger.info(f"User {email} authenticated successfully.")
        return user, access_token, refresh_token

    def refresh_access_token(self, refresh_token):
        try:
            refresh_payload = self.decode_token(refresh_token) 
            user_id = refresh_payload.get('user_id')
            
            user = User.objects(id=user_id).first()
            if not user:
                logger.warning(f"Refresh failed: User {user_id} not found or inactive.")
                raise ValueError("Invalid refresh token.")

            # Generate new access token
            now = datetime.utcnow()
            access_payload = {
                'user_id': str(user.id),
                'roles': user.roles,
                'exp': now + self.access_token_expires,
                'iat': now,
                'jti': str(user.id) + '_' + str(now.timestamp())
            }
            new_access_token = jwt.encode(access_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            logger.info(f"Access token refreshed for user: {user_id}")
            return new_access_token
        except ValueError as e:
            logger.warning(f"Refresh token processing failed: {e}")
            raise ValueError(f"Invalid or expired refresh token: {e}")
        except Exception as e:
            logger.error(f"Error refreshing access token: {e}", exc_info=True)
            raise ValueError("Failed to refresh access token.")

    def blacklist_token(self, token, token_type):
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm], options={"verify_exp": False})
            jti = payload.get('jti')
            exp = payload.get('exp')

            if not jti or not exp:
                raise ValueError("Token missing JTI or expiration claim.")

            if TokenBlacklist.objects(jti=jti).first():
                logger.warning(f"Attempted to blacklist already blacklisted token with JTI: {jti}")
                raise ValueError("Token is already blacklisted.")
            
            blacklist_entry = TokenBlacklist(
                jti=jti,
                expires_at=datetime.fromtimestamp(exp)
            )
            blacklist_entry.save()
            logger.info(f"Token (type: {token_type}) with JTI {jti} blacklisted successfully.")
        except jwt.ExpiredSignatureError:
            # If token is expired, it's effectively blacklisted anyway, but we can still record it
            logger.info("Attempted to blacklist an expired token. Proceeding with blacklist record.")
            try:
                payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm], options={"verify_exp": False})
                jti = payload.get('jti')
                exp = payload.get('exp')
                if jti and exp:
                    blacklist_entry = TokenBlacklist(jti=jti, expires_at=datetime.fromtimestamp(exp))
                    blacklist_entry.save()
                    logger.info(f"Expired token (type: {token_type}) with JTI {jti} recorded as blacklisted.")
                else:
                    raise ValueError("Expired token missing JTI or expiration claim for blacklisting.")
            except Exception as e:
                logger.error(f"Failed to record expired token in blacklist: {e}", exc_info=True)
                raise ValueError(f"Invalid or malformed token for blacklisting: {e}")
        except jwt.InvalidTokenError:
            logger.warning("Attempted to blacklist an invalid token.")
            raise ValueError("Invalid token for blacklisting.")
        except Exception as e:
            logger.error(f"Error blacklisting token: {e}", exc_info=True)
            raise ValueError("Failed to blacklist token.")

    def get_user_by_id(self, user_id):
        """Retrieves a user by their ID."""
        try:
            user = User.objects(id=user_id).first()
            return user
        except Exception as e:
            logger.error(f"Error retrieving user by ID {user_id}: {e}", exc_info=True)
            return None

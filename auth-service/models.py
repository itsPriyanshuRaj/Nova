from mongoengine import Document, StringField, EmailField, DateTimeField, ListField, BooleanField
from datetime import datetime

class User(Document):
   
    username = StringField(required=True, unique=True, max_length=50)
    email = EmailField(required=True, unique=True)
    password_hash = StringField(required=True) 
    roles = ListField(StringField(), default=['customer']) 
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {'collection': 'users'} 

    def to_dict(self):
        """Converts the User document to a dictionary for API responses."""
        return {
            "id": str(self.id),
            "username": self.username,
            "email": self.email,
            "roles": self.roles,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }


#represents a blacklisted JWTToken
class TokenBlacklist(Document):
    jti = StringField(required=True, unique=True) 
    created_at = DateTimeField(default=datetime.utcnow)
    expires_at = DateTimeField(required=True) 

    meta = {'collection': 'token_blacklist'}

    def to_dict(self):
        """Converts the TokenBlacklist document to a dictionary."""
        return {
            "id": str(self.id),
            "jti": self.jti,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat()
        }
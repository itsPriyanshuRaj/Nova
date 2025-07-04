from mongoengine import Document, StringField, DateTimeField, ReferenceField, ListField, EmbeddedDocument, EmbeddedDocumentField
from datetime import datetime

class AdminActionLog(Document):
    
    admin_user_id= StringField(required=True)
    action_type = StringField(required=True, choices=('CREATE', 'UPDATE', 'DELETE', 'VIEW', 'LOGIN'))
    target_service = StringField(required=True)
    target_id = StringField()
    description = StringField()
    timestamp = DateTimeField(default=datetime.utcnow)
    ip_address = StringField()

    #mongoDB collection name
    meta = {'Collection':'admin_action_logs'}

    def to_dict(self):
        return{
            "id": str(self.id),
            "admin_user_id": self.admin_user_id,
            "action_type":self.action_type,
            "target_service":self.target_id,
            "description":self.description,
            "timestamp":self.timestamp.isoformat(),
            "ip_address":self.ip_address
        }
    

class AdminDashboardSetting(Document):
    admin_user_id = StringField(required=True, unique=True)
    dashboard_layout = ListField(StringField())
    default_filters = StringField()

    # mongoDB Collection name
    meta = {'collection':'admin_dashobard_settings'}

    def to_dict(self):
        return{
            "id": str(self.id),
            "admin_user_id": self.admin_user_id,
            "dashboard_layout": self.dashboard_layout,
            "default_filters": self.default_filters
        }
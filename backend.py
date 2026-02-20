from flask import Flask, request, jsonify, redirect, session, url_for, g
from flask import send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from openai import AzureOpenAI
from databricks import sql
import httpx
import time
import threading
import os
import json
import re
import hashlib
import jwt
from functools import wraps
from typing import Dict, List, Any
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
import msal
import requests 
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceNotFoundError, ResourceExistsError
from dotenv import load_dotenv
import logging, sys

logging.basicConfig(level = logging.INFO, handlers = [logging.StreamHandler(sys.stdout)])
logging.info("App Starting...")

DEMO_MODE = False

app = Flask(__name__, static_folder="dist", static_url_path="")
CORS(app)

app.secret_key = os.getenv('FLASK_SECRET_KEY')

BASE_API_URL = os.getenv('VITE_API_URL')

# Configuration
# Azure OpenAI Configuration (Enterprise)
AZURE_OPENAI_ENDPOINT = os.getenv('AZURE_OPENAI_ENDPOINT')
AZURE_OPENAI_API_KEY = os.getenv('AZURE_OPENAI_API_KEY')
AZURE_OPENAI_DEPLOYMENT = os.getenv('AZURE_OPENAI_DEPLOYMENT')
AZURE_OPENAI_API_VERSION = os.getenv('AZURE_OPENAI_API_VERSION')

# Service Principal for Azure OpenAI (if using AAD authentication instead of API key)
AZURE_OPENAI_USE_AAD = os.getenv('AZURE_OPENAI_USE_AAD', 'false').lower() == 'true'
#AZURE_SP_TENANT_ID = os.getenv('AZURE_SP_TENANT_ID')
AZURE_SP_CLIENT_ID = os.getenv('AZURE_SP_CLIENT_ID')
AZURE_SP_CLIENT_SECRET = os.getenv('AZURE_SP_CLIENT_SECRET')
PROJECT_ID=os.getenv("PROJECT_ID")

# Databricks
DATABRICKS_SERVER_HOSTNAME = os.getenv('DATABRICKS_SERVER_HOSTNAME')
DATABRICKS_HTTP_PATH = os.getenv('DATABRICKS_HTTP_PATH')
DATABRICKS_ACCESS_TOKEN = os.getenv('DATABRICKS_ACCESS_TOKEN')

# JWT
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')

# Azure Table Storage for caching
AZURE_STORAGE_CONNECTION_STRING = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
CACHE_TABLE_NAME = 'querycache'
RATE_LIMIT_TABLE_NAME = 'ratelimits'
AZURE_TABLES_CONNECTION_STRING = os.getenv("AZURE_TABLES_CONNECTION_STRING")
AZURE_TABLE_SESSIONS_TABLE = os.getenv("AZURE_TABLE_SESSIONS_TABLE", "agentsessions")
AZURE_TABLE_MESSAGES_TABLE = os.getenv("AZURE_TABLE_MESSAGES_TABLE", "agentmessages")

tables_enabled = False
table_service = None
sessions_table = None
messages_table = None

# Azure AD Configuration (for user authentication)
AZURE_AD_TENANT_ID = os.getenv('AZURE_AD_TENANT_ID')
AZURE_AD_CLIENT_ID = os.getenv('AZURE_AD_CLIENT_ID')
AZURE_AD_CLIENT_SECRET = os.getenv('AZURE_AD_CLIENT_SECRET')
AZURE_AD_REDIRECT_URI = os.getenv('AZURE_AD_REDIRECT_URI', f'{BASE_API_URL}/api/auth/callback')
AZURE_AD_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_AD_TENANT_ID}"

# Azure AD Group to Role Mapping
AD_GROUP_ROLE_MAPPING = {
    os.getenv('AD_GROUP_ADMIN_ID'): 'admin',
    os.getenv('AD_GROUP_ANALYST_ID'): 'analyst',
    os.getenv('AD_GROUP_VIEWER_ID'): 'viewer',
}

# Role-based permissions
ROLE_PERMISSIONS = {
    'admin': {
        'can_clear_cache': True,
        'can_view_all_data': True,
        'can_modify_agents': True,
        'can_export_data': True,
        'max_queries_per_day': 1000
    },
    'analyst': {
        'can_clear_cache': False,
        'can_view_all_data': True,
        'can_modify_agents': True,
        'can_export_data': True,
        'max_queries_per_day': 500
    },
    'viewer': {
        'can_clear_cache': False,
        'can_view_all_data': False,
        'can_modify_agents': False,
        'can_export_data': False,
        'max_queries_per_day': 100
    }
}

# Initialize Azure Table Storage for caching

cache_table = None
rate_limit_table = None
CACHE_ENABLED = False

try:
    if AZURE_TABLES_CONNECTION_STRING:
        table_service = TableServiceClient.from_connection_string(
            AZURE_TABLES_CONNECTION_STRING
        )

        for name in [AZURE_TABLE_SESSIONS_TABLE, AZURE_TABLE_MESSAGES_TABLE]:
            try:
                table_service.create_table(name)
            except ResourceExistsError:
                pass

        sessions_table = table_service.get_table_client(AZURE_TABLE_SESSIONS_TABLE)
        messages_table = table_service.get_table_client(AZURE_TABLE_MESSAGES_TABLE)

        tables_enabled = True
        print("Azure Tables connected (sessions + messages)")
    else:
        print("Azure Tables disabled (no connection string)")
except Exception as e:
    print(f"Azure Tables init failed: {e}")
    tables_enabled = False
# Rate limiting - using in-memory for simplicity
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["20000 per day", "50 per hour"],
    storage_uri="memory://"
)

def get_databricks_connection():
    if DEMO_MODE:
        return None
    return sql.connect(
        server_hostname=os.getenv("DATABRICKS_SERVER_HOSTNAME"),
        http_path=os.getenv("DATABRICKS_HTTP_PATH"),
        access_token=os.getenv("DATABRICKS_ACCESS_TOKEN"),
    )

# =========================
# UHG OAuth2 Token Manager
# =========================
class UHGTokenManager:
    """Auto-refreshing token manager for UHG OAuth2 endpoint"""

    def __init__(self):
        self.auth_url = "https://api.uhg.com/oauth2/token"
        # self.auth_url = "https://api-stg.uhg.com/oauth2/token"  # Non-prod
        self.scope = "https://api.uhg.com/.default"
        self.client_id = AZURE_SP_CLIENT_ID
        self.client_secret = AZURE_SP_CLIENT_SECRET

        self._token = None
        self._expires_at = 0
        self._lock = threading.Lock()

    def get_token(self):
        """Return valid token (refresh if <2min remaining)"""
        with self._lock:
            if time.time() > self._expires_at - 120:
                self._refresh_token()
            return self._token

    def _refresh_token(self):
        """Fetch new OAuth2 token"""
        with httpx.Client() as client:
            resp = client.post(
                self.auth_url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "client_credentials",
                    "scope": self.scope,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()

            self._token = data["access_token"]
            expires_in = data.get("expires_in", 3000)  # fallback ~50min
            self._expires_at = time.time() + expires_in

            print(f"UHG token refreshed, expires in {expires_in}s")


# =========================
# Azure OpenAI Client
# =========================
def get_azure_openai_client():
    """Create Azure OpenAI client using UHG OAuth OR API key"""

    if AZURE_OPENAI_USE_AAD:
        print("Using UHG OAuth2 Service Principal authentication")

        token_manager = UHGTokenManager()

        client = AzureOpenAI(
            azure_endpoint=AZURE_OPENAI_ENDPOINT,
            azure_ad_token_provider=token_manager.get_token,
            api_version=AZURE_OPENAI_API_VERSION,
            default_headers = { "projectID" : PROJECT_ID }
        )

    else:
        print("Using API Key authentication for OpenAI")

        client =  AzureOpenAI(
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        api_key=AZURE_OPENAI_API_KEY,
        api_version=AZURE_OPENAI_API_VERSION,
        default_headers={"projectID": PROJECT_ID}
    )

    return client

# Initialize client at startup
try:
    client = get_azure_openai_client()
    print(f"Azure OpenAI client initialized successfully")
    print(f"Endpoint: {AZURE_OPENAI_ENDPOINT}")
    print(f"Deployment: {AZURE_OPENAI_DEPLOYMENT}")
    print(f"API Version: {AZURE_OPENAI_API_VERSION}")
except Exception as e:
    print(f"Failed to initialize Azure OpenAI client: {e}")
    client = None

# MSAL Confidential Client for user authentication
def get_msal_app():
    """Create MSAL confidential client application for user auth"""
    return msal.ConfidentialClientApplication(
        AZURE_AD_CLIENT_ID,
        authority=AZURE_AD_AUTHORITY,
        client_credential=AZURE_AD_CLIENT_SECRET,
    )


  
def get_user_groups(access_token):  
    """Get all Azure AD group memberships (direct + via nested groups) for the signed-in user."""  
    url = ("https://graph.microsoft.com/v1.0/"  
           "me/transitiveMemberOf/microsoft.graph.group"  
           "?$select=id,displayName&$top=999")  
    headers = {"Authorization": f"Bearer {access_token}"}  
  
    groups = []  
    seen = set()  
  
    try:  
        while url:  
            resp = requests.get(url, headers=headers, timeout=30)  
            if resp.status_code != 200:  
                print(f"Failed to get groups: {resp.status_code} {resp.text}")  
                return groups  
  
            data = resp.json()  
            for g in data.get("value", []):  
                name = g.get("displayName")  
                if name and name not in seen:  
                    seen.add(name)  
                    groups.append(name)  
  
            url = data.get("@odata.nextLink")  # follow pagination  
    except Exception as e:  
        print(f"Error getting user groups: {e}")  
  
    return groups

def determine_user_role(group_ids):
    """Determine user role based on AD group membership"""
    for group_id in group_ids:
        if group_id in AD_GROUP_ROLE_MAPPING:
            role = AD_GROUP_ROLE_MAPPING[group_id]
            if role == 'admin':
                return 'admin'
    
    for group_id in group_ids:
        if group_id in AD_GROUP_ROLE_MAPPING:
            role = AD_GROUP_ROLE_MAPPING[group_id]
            if role == 'analyst':
                return 'analyst'
    
    for group_id in group_ids:
        if group_id in AD_GROUP_ROLE_MAPPING:
            return AD_GROUP_ROLE_MAPPING[group_id]
    
    return 'viewer'

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
            g.current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

def permission_required(permission):
    """Decorator to check if user has specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            user_role = g.current_user.get('role', 'viewer')
            permissions = ROLE_PERMISSIONS.get(user_role, {})
            
            if not permissions.get(permission, False):
                return jsonify({'error': f'Permission denied. Required: {permission}'}), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# Database schema
DATABASE_SCHEMA = """
Available Tables in dev_orx_hb.enriched schema:

1. d_order_header (Main order information)
   - OrderHeaderSK (BIGINT): Primary key
   - OrderNumber (BIGINT): Natural key, order identifier
   - VersionNumber (INT): Natural key
   - HeaderId (BIGINT): Header identifier
   - OrganisationId (INT): Organization
   - TransactionTypeSK (BIGINT): FK to d_transaction_types
   - OrderSourceSK (BIGINT): FK to d_order_sources
   - SalesRepSK (BIGINT): FK to d_salesrep
   - OrderedDate (TIMESTAMP): When order was placed
   - RequestedDate (TIMESTAMP): Requested delivery date
   - OrderStatus (STRING): Order status
   - ActiveFlag (BOOLEAN)

2. d_order_lines (Order line items)
   - OrderLinesSK (BIGINT): Primary key
   - OrderHeaderSK (BIGINT): FK to d_order_header
   - DrugSK (BIGINT): FK to d_drug
   - MemberSK (BIGINT): FK to d_member
   - ShippingSK (BIGINT): FK to d_shipping
   - Status (STRING): Line status
   - OrderedQuantity (DOUBLE)
   - ActualShipmentDate (TIMESTAMP)
   - BusinessUnit (STRING): Fulfillment site
   - FulFilledFlag (BOOLEAN)
   - CreatedTimestamp (TIMESTAMP)

3. d_drug (Drug/medication information)
   - DrugSK (BIGINT): Primary key
   - IRISDrugName (STRING): IRIS drug name
   - NDC (STRING): National Drug Code
   - GPI (STRING): Generic Product Identifier
   - TherapyClass1-3 (STRING): Drug classifications
   - ActiveFlag (BOOLEAN)

4. d_member (Patient/member information)
   - MemberSK (INT): Primary key
   - PersonFirstName, PersonLastName (STRING)
   - PrimaryState (STRING)
   - ActiveFlag (BOOLEAN)

5. d_shipping (Shipping details)
   - ShippingSK (BIGINT): Primary key
   - BusinessUnit (STRING): Fulfillment site
   - ShipDate (DATE)
   - TrackingNumber (STRING)
   - IsCold (BOOLEAN)

6. d_carrier (Shipping carrier information)
7. d_prescriber (Prescriber/physician details)
8. d_med_comm (Medical communications)
9. d_hold (Order holds)
10. d_transaction_types (Transaction type lookup)
11. d_order_sources (Order source lookup)
12. d_salesrep (Sales representative data)
13. d_member_location (Member addresses)

Business Logic:
- Shipments = COUNT(d_order_lines WHERE ActualShipmentDate IS NOT NULL)
- Fulfillment Rate = COUNT(FulFilledFlag = true) / COUNT(*) * 100
- Sites available in d_shipping.BusinessUnit and d_order_lines.BusinessUnit
"""

SYSTEM_PROMPT = f"""You are a data analyst assistant with access to a Databricks warehouse containing prescription fulfillment data.

{DATABASE_SCHEMA}

When a user asks a question:
1. Generate the appropriate SQL query to answer their question
2. Call the execute_databricks_query function with your SQL
3. Analyze the results and provide a clear, conversational answer
4. If the data would benefit from visualization, format it appropriately

For visualizations, respond with JSON in this format after your text explanation:

For metrics:
```json
{{"type":"metrics","metrics":[{{"label":"Total Shipments","value":"1,247","icon":"database","change":12}}]}}
```

For line charts (time series):
```json
{{"type":"line","data":[{{"name":"Mon","value":85}}]}}
```

For bar charts (comparisons):
```json
{{"type":"bar","data":[{{"name":"Charlotte","value":15420}}]}}
```

Icons: database, chart, trend

Always validate queries are read-only (SELECT only). Never use DROP, DELETE, UPDATE, INSERT, or CREATE.
"""

def generate_cache_key(query: str, params: Dict = None) -> str:
    """Generate a unique cache key for a query"""
    key_data = f"{query}:{json.dumps(params or {}, sort_keys=True)}"
    # Table Storage row keys have length limit of 1024 characters
    # Use MD5 hash to ensure consistent length
    return hashlib.md5(key_data.encode()).hexdigest()
    """Create a connection to Databricks SQL warehouse"""
    try:
        connection = sql.connect(
            server_hostname=DATABRICKS_SERVER_HOSTNAME,
            http_path=DATABRICKS_HTTP_PATH,
            access_token=DATABRICKS_ACCESS_TOKEN
        )
        return connection
    except Exception as e:
        print(f"Error connecting to Databricks: {e}")
        raise

def get_from_cache(cache_key: str) -> Dict | None:
    """Retrieve data from Azure Table Storage cache"""
    if not CACHE_ENABLED:
        return None
    
    try:
        entity = cache_table.get_entity(
            partition_key='cache',
            row_key=cache_key
        )
        
        # Check expiration
        expires = datetime.fromisoformat(entity['expires'])
        if datetime.utcnow() > expires:
            # Delete expired entry
            try:
                cache_table.delete_entity(
                    partition_key='cache',
                    row_key=cache_key
                )
            except:
                pass
            return None
        
        return json.loads(entity['data'])
    except ResourceNotFoundError:
        return None
    except Exception as e:
        print(f"Cache retrieval error: {e}")
        return None

def set_in_cache(cache_key: str, data: Dict, ttl: int = 300):
    """Store data in Azure Table Storage cache with TTL"""
    if not CACHE_ENABLED:
        return
    
    try:
        entity = {
            'PartitionKey': 'cache',
            'RowKey': cache_key,
            'data': json.dumps(data),
            'expires': (datetime.utcnow() + timedelta(seconds=ttl)).isoformat(),
            'created': datetime.utcnow().isoformat()
        }
        cache_table.upsert_entity(entity)
    except Exception as e:
        print(f"Cache storage error: {e}")

def get_query_count(user_id: str, date_str: str) -> int:
    """Get query count for a user on a specific date"""
    if not CACHE_ENABLED:
        return 0
    
    try:
        entity = rate_limit_table.get_entity(
            partition_key=date_str,
            row_key=user_id
        )
        return int(entity.get('count', 0))
    except ResourceNotFoundError:
        return 0
    except Exception as e:
        print(f"Error getting query count: {e}")
        return 0

def increment_query_count(user_id: str, date_str: str) -> int:
    """Increment query count for a user"""
    if not CACHE_ENABLED:
        return 0
    
    try:
        # Try to get existing count
        try:
            entity = rate_limit_table.get_entity(
                partition_key=date_str,
                row_key=user_id
            )
            count = int(entity.get('count', 0)) + 1
        except ResourceNotFoundError:
            count = 1
        
        # Update entity
        entity = {
            'PartitionKey': date_str,
            'RowKey': user_id,
            'count': count,
            'last_updated': datetime.utcnow().isoformat()
        }
        rate_limit_table.upsert_entity(entity)
        return count
    except Exception as e:
        print(f"Error incrementing query count: {e}")
        return 0

def clear_cache_entries():
    """Clear all cache entries from Table Storage"""
    if not CACHE_ENABLED:
        return 0
    
    try:
        # Query all cache entries
        entities = cache_table.query_entities("PartitionKey eq 'cache'")
        count = 0
        
        for entity in entities:
            try:
                cache_table.delete_entity(
                    partition_key=entity['PartitionKey'],
                    row_key=entity['RowKey']
                )
                count += 1
            except Exception as e:
                print(f"Error deleting entity: {e}")
        
        return count
    except Exception as e:
        print(f"Error clearing cache: {e}")
        return 0

def cleanup_expired_cache():
    """Remove expired cache entries (can be called periodically)"""
    if not CACHE_ENABLED:
        return 0
    
    try:
        now = datetime.utcnow()
        entities = cache_table.query_entities("PartitionKey eq 'cache'")
        count = 0
        
        for entity in entities:
            try:
                expires = datetime.fromisoformat(entity['expires'])
                if now > expires:
                    cache_table.delete_entity(
                        partition_key=entity['PartitionKey'],
                        row_key=entity['RowKey']
                    )
                    count += 1
            except Exception as e:
                print(f"Error checking/deleting expired entity: {e}")
        
        return count
    except Exception as e:
        print(f"Error cleaning up cache: {e}")
        return 0

def execute_databricks_query(sql_query: str, max_rows: int = 1000, use_cache: bool = True) -> Dict[str, Any]:
    """Execute a SQL query against Databricks and return results"""
    
    sql_upper = sql_query.upper().strip()
    dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'CREATE', 'ALTER', 'TRUNCATE', 'GRANT', 'REVOKE']
    
    for keyword in dangerous_keywords:
        if keyword in sql_upper:
            return {
                "success": False,
                "error": f"Query contains forbidden keyword: {keyword}. Only SELECT queries are allowed."
            }
    
    if not sql_upper.startswith('SELECT') and not sql_upper.startswith('WITH'):
        return {
            "success": False,
            "error": "Only SELECT queries (or CTEs starting with WITH) are allowed."
        }
    
    if use_cache:
        cache_key = generate_cache_key(sql_query)
        cached_result = get_from_cache(cache_key)
        if cached_result:
            print("Cache hit!")
            cached_result['from_cache'] = True
            return cached_result
    
    try:
        connection = get_databricks_connection()
        cursor = connection.cursor()
        
        #if 'LIMIT' not in sql_upper:
        #    sql_query = f"{sql_query} LIMIT {max_rows}"
        
        cursor.execute(sql_query)
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            results.append(dict(zip(columns, row)))
        
        cursor.close()
        connection.close()
        
        result_data = {
            "success": True,
            "data": results,
            "columns": columns,
            "row_count": len(results),
            "from_cache": False
        }
        
        if use_cache:
            set_in_cache(cache_key, result_data, ttl=300)
        
        return result_data
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "from_cache": False
        }

def call_openai_with_tools(messages: List[Dict], agent_type: str = "analytics"):
    """Call Azure OpenAI API with function calling for Databricks queries"""
    
    if not client:
        raise Exception("Azure OpenAI client not initialized")
    
    tools = [
        {
            "type": "function",
            "function": {
                "name": "execute_databricks_query",
                "description": "Execute a SELECT query against the Databricks data warehouse",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql_query": {
                            "type": "string",
                            "description": "The SQL SELECT query to execute"
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Brief explanation of what this query will retrieve"
                        }
                    },
                    "required": ["sql_query", "reasoning"]
                }
            }
        }
    ]
    
    full_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages
    
    response = client.chat.completions.create(
        model=AZURE_OPENAI_DEPLOYMENT,
        messages=full_messages,
        tools=tools,
        tool_choice="auto",
        temperature=0.1
    )
    
    return response

@app.route('/api/auth/login', methods=['GET'])
def login():
    """Initiate Azure AD OAuth flow"""
    try:
        msal_app = get_msal_app()
        
        auth_url = msal_app.get_authorization_request_url(
            scopes=[
                "User.Read",
                "GroupMember.Read.All"
            ],
            redirect_uri=AZURE_AD_REDIRECT_URI
        )
        
        return jsonify({
            "auth_url": auth_url
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/callback', methods=['GET'])
def auth_callback():
    """Handle Azure AD OAuth callback"""
    try:
        code = request.args.get('code')
        
        if not code:
            return jsonify({"error": "No authorization code provided"}), 400
        
        msal_app = get_msal_app()
        
        result = msal_app.acquire_token_by_authorization_code(
            code,
            scopes=[
                "User.Read",
                "GroupMember.Read.All"
            ],
            redirect_uri=AZURE_AD_REDIRECT_URI
        )
        
        if "error" in result:
            return jsonify({"error": result.get("error_description")}), 400
        
        access_token = result.get('access_token')
        id_token_claims = result.get('id_token_claims', {})
        
        user_email = id_token_claims.get('preferred_username') or id_token_claims.get('email')
        user_name = id_token_claims.get('name')
        user_oid = id_token_claims.get('oid')
        
        group_ids = get_user_groups(access_token)
        user_role = determine_user_role(group_ids)
        
        app_token = jwt.encode(
            {
                'email': user_email,
                'name': user_name,
                'oid': user_oid,
                'role': user_role,
                'groups': group_ids,
                'exp': datetime.utcnow() + timedelta(hours=24)
            },
            JWT_SECRET_KEY,
            algorithm="HS256"
        )
        
        frontend_url = os.getenv('FRONTEND_URL', BASE_API_URL)
        return redirect(f"{frontend_url}/auth/callback?token={app_token}")
        
    except Exception as e:
        print(f"Auth callback error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/auth/callback")
def auth_callback_frontend():
    return send_from_directory("dist", "index.html")

@app.route('/api/auth/verify', methods=['GET'])
@token_required
def verify_token():
    """Verify JWT token and return user info"""
    return jsonify({
        "success": True,
        "user": g.current_user,
        "permissions": ROLE_PERMISSIONS.get(g.current_user.get('role', 'viewer'), {})
    })

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    """Logout user"""
    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })

@app.route('/api/chat', methods=['POST'])
@token_required
@limiter.limit("30 per minute")
def chat():
    try:
        if not tables_enabled:
            return jsonify({"error": "Azure Tables not enabled"}), 500

        data = request.json
        user_message = data.get("message")
        agent = data.get("agent", "analytics")
        session_id = data.get("session_id")

        if not user_message:
            return jsonify({"error": "Message is required"}), 400

        user_email = g.current_user["email"]

        # 🔹 Create session if needed
        if not session_id:
            session_id = str(uuid.uuid4())
            sessions_table.upsert_entity({
                "PartitionKey": user_email,
                "RowKey": session_id,
                "agent": agent,
                "created_at": datetime.utcnow().isoformat(),
                "last_active": datetime.utcnow().isoformat()
            })

        # 🔹 Load history from Azure Tables
        history = []
        for e in messages_table.query_entities(f"PartitionKey eq '{session_id}'"):
            history.append({
                "role": e["role"],
                "content": e["content"]
            })

        history = history[-20:]
        messages = history + [{"role": "user", "content": user_message}]

        # 🔹 Call OpenAI
        response = client.chat.completions.create(
            model=AZURE_OPENAI_DEPLOYMENT,
            messages=messages,
            temperature=0.1
        )

        answer = response.choices[0].message.content
        now = datetime.utcnow().isoformat()

        # 🔹 Persist messages
        messages_table.create_entity({
            "PartitionKey": session_id,
            "RowKey": f"{time.time()}_{uuid.uuid4().hex}",
            "role": "user",
            "content": user_message,
            "agent": agent,
            "timestamp": now
        })

        messages_table.create_entity({
            "PartitionKey": session_id,
            "RowKey": f"{time.time()}_{uuid.uuid4().hex}",
            "role": "assistant",
            "content": answer,
            "agent": agent,
            "timestamp": now
        })

        return jsonify({
            "success": True,
            "response": answer,
            "session_id": session_id,
            "timestamp": now
        })

    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

def parse_visualization_from_text(text: str) -> Dict | None:
    """Extract JSON visualization data from markdown code blocks"""
    try:
        pattern = r'```json\s*(\{.*?\})\s*```'
        match = re.search(pattern, text, re.DOTALL)
        
        if match:
            json_str = match.group(1)
            viz_data = json.loads(json_str)
            return viz_data
        
        return None
    except Exception as e:
        print(f"Error parsing visualization: {e}")
        return None

@app.route('/api/cache/clear', methods=['POST'])
@token_required
@permission_required('can_clear_cache')
@limiter.limit("5 per minute")
def clear_cache():
    """Clear query cache (admin only)"""
    if not CACHE_ENABLED:
        return jsonify({"error": "Cache is not enabled"}), 400
    
    try:
        count = clear_cache_entries()
        
        return jsonify({
            "success": True,
            "message": f"Cleared {count} cached queries"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cache/stats', methods=['GET'])
@token_required
def cache_stats():
    """Get cache statistics"""
    if not CACHE_ENABLED:
        return jsonify({"enabled": False})
    
    try:
        # Count cache entries
        cache_entities = list(cache_table.query_entities("PartitionKey eq 'cache'"))
        total_cached = len(cache_entities)
        
        # Count expired entries
        now = datetime.utcnow()
        expired_count = 0
        for entity in cache_entities:
            try:
                expires = datetime.fromisoformat(entity['expires'])
                if now > expires:
                    expired_count += 1
            except:
                pass
        
        return jsonify({
            "enabled": True,
            "total_cached_queries": total_cached,
            "expired_queries": expired_count,
            "active_queries": total_cached - expired_count,
            "storage_type": "Azure Table Storage"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cache/cleanup', methods=['POST'])
@token_required
@permission_required('can_clear_cache')
@limiter.limit("5 per minute")
def cache_cleanup():
    """Cleanup expired cache entries (admin only)"""
    if not CACHE_ENABLED:
        return jsonify({"error": "Cache is not enabled"}), 400
    
    try:
        count = cleanup_expired_cache()
        
        return jsonify({
            "success": True,
            "message": f"Cleaned up {count} expired cache entries"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/api/test-connection', methods=['GET'])
@token_required
def test_connection():
    """Test endpoint to verify Databricks connection"""
    try:
        connection = get_databricks_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT 1 as test")
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        
        return jsonify({
            "success": True,
            "message": "Successfully connected to Databricks",
            "test_result": result[0],
            "user": g.current_user['email']
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "cache_enabled": CACHE_ENABLED,
        "rate_limiting_enabled": True,
        "auth_provider": "Azure AD",
        "openai_provider": "Azure OpenAI",
        "openai_endpoint": AZURE_OPENAI_ENDPOINT,
        "openai_deployment": AZURE_OPENAI_DEPLOYMENT,
        "openai_auth": "AAD Service Principal" if AZURE_OPENAI_USE_AAD else "API Key"
    }
    
    return jsonify(health_status)

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors"""
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(e.description)
    }), 429

@app.route("/")
@app.route("/<path:path>")
def serve_frontend(path=""):
    if path != "" and os.path.exists(os.path.join("dist", path)):
        return send_from_directory("dist", path)
    return send_from_directory("dist", "index.html")

if __name__ == '__main__':
    required_vars = [
        'AZURE_OPENAI_ENDPOINT',
        'DATABRICKS_SERVER_HOSTNAME',
        'DATABRICKS_HTTP_PATH',
        'DATABRICKS_ACCESS_TOKEN',
        'AZURE_AD_TENANT_ID',
        'AZURE_AD_CLIENT_ID',
        'AZURE_AD_CLIENT_SECRET'
    ]
    
    # Check if using AAD or API Key for OpenAI
    if AZURE_OPENAI_USE_AAD:
        required_vars.extend([
            #'AZURE_SP_TENANT_ID',
            'AZURE_SP_CLIENT_ID',
            'AZURE_SP_CLIENT_SECRET'
        ])
    else:
        required_vars.append('AZURE_OPENAI_API_KEY')
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"WARNING: Missing environment variables: {', '.join(missing_vars)}")
        print("App will run but some features may not work properly")
    
    print("Starting Flask server with Azure OpenAI...")
    print(f"Azure OpenAI Endpoint: {AZURE_OPENAI_ENDPOINT}")
    print(f"Azure OpenAI Deployment: {AZURE_OPENAI_DEPLOYMENT}")
    print(f"Authentication Method: {'Service Principal' if AZURE_OPENAI_USE_AAD else 'API Key'}")
    print(f"Databricks host: {DATABRICKS_SERVER_HOSTNAME}")
    print(f"Cache enabled: {CACHE_ENABLED}")
    print(f"Azure AD Tenant: {AZURE_AD_TENANT_ID}")
    #app.run(debug=True, host='0.0.0.0', port=8000)
    


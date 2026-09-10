#!/usr/bin/env python3
"""
LDAP MCP Server - Model Context Protocol server for LDAP/Active Directory operations.

Provides tools for:
- Searching users and groups in AD
- Checking group memberships
- Testing LDAP connections
- Validating credentials

Usage (via Claude Code):
    MCP server configured in .mcp.json or settings.json
"""

import os
import sys
import json
import logging
from typing import Any, Optional
from ldap3 import Server, Connection, ALL, SUBTREE

# Configure logging to stderr (MCP servers use stderr for logs)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    'LDAP_SERVER': os.getenv('LDAP_SERVER', 'ldap.example.local'),
    'LDAP_PORT': int(os.getenv('LDAP_PORT', '636')),
    'LDAP_USE_SSL': os.getenv('LDAP_USE_SSL', 'true').lower() == 'true',
    'LDAP_DOMAIN': os.getenv('LDAP_DOMAIN', 'example.local'),
    'LDAP_BASE_DN': os.getenv('LDAP_BASE_DN', 'DC=example,DC=local'),
    'LDAP_SEARCH_BASE': os.getenv('LDAP_SEARCH_BASE', 'OU=Users,DC=example,DC=local'),
    'LDAP_GROUPS_BASE': os.getenv('LDAP_GROUPS_BASE', 'OU=Groups,DC=example,DC=local'),
    'LDAP_SERVICE_USER': os.getenv('LDAP_SERVICE_USER', 'svc-mcp-reader'),
    'LDAP_SERVICE_PASSWORD': os.getenv('LDAP_SERVICE_PASSWORD', ''),
    'LDAP_TIMEOUT': int(os.getenv('LDAP_TIMEOUT', '10')),
}

class LDAPMCPServer:
    """LDAP MCP Server implementation."""

    def __init__(self, config: dict = None):
        self.config = config or DEFAULT_CONFIG
        self._connection: Optional[Connection] = None

    def _get_server_url(self) -> str:
        scheme = 'ldaps' if self.config['LDAP_USE_SSL'] else 'ldap'
        return f"{scheme}://{self.config['LDAP_SERVER']}:{self.config['LDAP_PORT']}"

    def _get_service_user_dn(self) -> str:
        return f"{self.config['LDAP_SERVICE_USER']}@{self.config['LDAP_DOMAIN']}"

    def connect(self, username: str = None, password: str = None) -> Connection:
        try:
            server = Server(
                self._get_server_url(),
                get_info=ALL,
                connect_timeout=self.config['LDAP_TIMEOUT']
            )

            if username and password:
                user_dn = f"{username}@{self.config['LDAP_DOMAIN']}" if '@' not in username else username
                conn = Connection(server, user_dn, password, auto_bind=True)
            else:
                user_dn = self._get_service_user_dn()
                password = password or self.config['LDAP_SERVICE_PASSWORD']
                conn = Connection(server, user_dn, password, auto_bind=True)

            self._connection = conn
            return conn

        except Exception as e:
            raise Exception(f"Failed to connect to LDAP: {e}")

    def disconnect(self):
        if self._connection:
            try:
                self._connection.unbind()
            except Exception:
                pass
            finally:
                self._connection = None

    def search_users(self, filter: str, attributes: list = None) -> list:
        if not self._connection:
            self.connect()

        base = self.config['LDAP_SEARCH_BASE']
        attrs = attributes or ['cn', 'sAMAccountName', 'mail', 'distinguishedName', 'userAccountControl']
        self._connection.search(base, filter, SUBTREE, attributes=attrs)

        results = []
        for entry in self._connection.entries:
            user = {}
            for attr in attrs:
                if entry[attr].value:
                    user[attr] = str(entry[attr].value)
            results.append(user)

        return results

    def search_groups(self, filter: str, base: str = None) -> list:
        if not self._connection:
            self.connect()

        search_base = base or self.config['LDAP_GROUPS_BASE']
        attrs = ['cn', 'distinguishedName', 'description']
        self._connection.search(search_base, filter, SUBTREE, attributes=attrs)

        results = []
        for entry in self._connection.entries:
            group = {
                'cn': str(entry.cn.value) if entry.cn.value else '',
                'distinguishedName': str(entry.distinguishedName.value) if entry.distinguishedName.value else '',
            }
            if entry.description.value:
                group['description'] = str(entry.description.value)
            results.append(group)

        return results

    def get_user_groups(self, username: str) -> list:
        if not self._connection:
            self.connect()

        user_filter = f"(sAMAccountName={username})"
        self._connection.search(
            self.config['LDAP_SEARCH_BASE'],
            user_filter,
            SUBTREE,
            attributes=['distinguishedName', 'memberOf']
        )

        if not self._connection.entries:
            return []

        user = self._connection.entries[0]
        if user.memberOf.value:
            return [self._extract_cn(dn) for dn in user.memberOf.value]
        return []

    def _extract_cn(self, dn: str) -> str:
        for part in dn.split(','):
            if part.upper().startswith('CN='):
                return part[3:]
        return dn


# JSON-RPC MCP Server
def send_response(result: Any = None, error: dict = None, id: Any = None):
    response = {
        "jsonrpc": "2.0",
        "result": result,
        "error": error,
        "id": id
    }
    # Remove None values
    if response["result"] is None:
        del response["result"]
    if response["error"] is None:
        del response["error"]
    if response["id"] is None:
        del response["id"]
    print(json.dumps(response), flush=True)

def main():
    logger.info("Starting LDAP MCP Server...")

    # Load config
    config = DEFAULT_CONFIG.copy()
    config_file = os.path.expanduser('~/.claude/plugins/ldap-mcp-server/config.json')
    if os.path.exists(config_file):
        with open(config_file) as f:
            config.update(json.load(f))

    ldap_server = LDAPMCPServer(config)

    # Tools available
    tools = [
        {
            "name": "ldap_search_users",
            "description": "Search for users in Active Directory",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "LDAP search filter, e.g., '(sAMAccountName=jdoe)' or '(cn=John*)'"
                    },
                    "attributes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional list of attributes to retrieve",
                        "default": ["cn", "sAMAccountName", "mail", "distinguishedName"]
                    }
                },
                "required": ["filter"]
            }
        },
        {
            "name": "ldap_search_groups",
            "description": "Search for groups in Active Directory",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "filter": {
                        "type": "string",
                        "description": "LDAP search filter, e.g., '(cn=ERP*)' or '(objectClass=group)'"
                    },
                    "base": {
                        "type": "string",
                        "description": "Optional custom search base, defaults to OU=Groups,DC=example,DC=local"
                    }
                },
                "required": ["filter"]
            }
        },
        {
            "name": "ldap_get_user_groups",
            "description": "Get list of groups for a user by username",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "sAMAccountName of the user"
                    }
                },
                "required": ["username"]
            }
        },
        {
            "name": "ldap_test",
            "description": "Test LDAP connection and return server info"
        }
    ]

    # Handle JSON-RPC requests
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            method = request.get("method")
            params = request.get("params", {})
            req_id = request.get("id")

            if method == "initialize":
                send_response({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "ldap-mcp-server",
                        "version": "1.0.0"
                    }
                }, id=req_id)

            elif method == "tools/list":
                send_response({"tools": tools}, id=req_id)

            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                try:
                    if tool_name == "ldap_search_users":
                        result = ldap_server.search_users(
                            filter=arguments.get("filter"),
                            attributes=arguments.get("attributes")
                        )
                        send_response({
                            "content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]
                        }, id=req_id)

                    elif tool_name == "ldap_search_groups":
                        result = ldap_server.search_groups(
                            filter=arguments.get("filter"),
                            base=arguments.get("base")
                        )
                        send_response({
                            "content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]
                        }, id=req_id)

                    elif tool_name == "ldap_get_user_groups":
                        result = ldap_server.get_user_groups(arguments.get("username"))
                        send_response({
                            "content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]
                        }, id=req_id)

                    elif tool_name == "ldap_test":
                        try:
                            conn = ldap_server.connect()
                            result = {
                                "status": "connected",
                                "server": ldap_server._get_server_url(),
                                "domain": ldap_server.config['LDAP_DOMAIN'],
                                "search_base": ldap_server.config['LDAP_SEARCH_BASE'],
                                "groups_base": ldap_server.config['LDAP_GROUPS_BASE']
                            }
                            ldap_server.disconnect()
                            send_response({
                                "content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}]
                            }, id=req_id)
                        except Exception as e:
                            send_response({
                                "content": [{"type": "text", "text": f"Connection failed: {e}"}]
                            }, id=req_id)

                    else:
                        send_response(error={"code": -32601, "message": f"Unknown tool: {tool_name}"}, id=req_id)

                except Exception as e:
                    send_response(error={"code": -32603, "message": str(e)}, id=req_id)

            else:
                send_response(error={"code": -32601, "message": f"Unknown method: {method}"}, id=req_id)

        except json.JSONDecodeError:
            logger.error(f"Invalid JSON: {line}")
        except Exception as e:
            logger.error(f"Error processing request: {e}")

if __name__ == '__main__':
    main()

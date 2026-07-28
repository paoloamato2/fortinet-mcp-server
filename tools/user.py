"""User management tools.

Covers /api/v2/cmdb/user/… and /api/v2/monitor/user/…
"""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP, Context
from pydantic import Field

from fortios_client import FortiOSError
from instances import FortiOSAPI
from resources import UserResource
from tool_annotations import CREATES, DESTRUCTIVE, READ_ONLY
from tool_params import InstanceParam, VdomParam
from tools._read import read_resource, resource_table_doc


def register(mcp: FastMCP) -> None:
    """Register all user management tools."""

    async def user_read(
        ctx: Context,
        resource: Annotated[
            UserResource, Field(description="Which user resource to read.")
        ],
        name: Annotated[
            str | None,
            Field(
                default=None,
                description=(
                    "Object key to fetch. Omit to list every object. "
                    "Rejected for singletons and monitor endpoints."
                ),
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Placeholder replaced below with the generated resource table."""
        return await read_resource(ctx, "user", resource, name, instance, vdom)

    user_read.__doc__ = (
        "Read user, group and authentication-server configuration.\n\n"
        "Omit `name` to list a resource, or pass it to fetch one object by "
        "key.\n\n" + resource_table_doc("user")
    )
    mcp.tool(annotations=READ_ONLY)(user_read)

    # ==================================================================
    # LOCAL USERS
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def user_local_create(
        ctx: Context,
        name: Annotated[str, Field(description="Username (must be unique).")],
        password: Annotated[str, Field(description="User password.")],
        status: Annotated[
            str,
            Field(default="enable", description="Account status: enable or disable."),
        ] = "enable",
        auth_type: Annotated[
            str,
            Field(
                default="password",
                description="Authentication type: password, radius, ldap, tacacs+.",
            ),
        ] = "password",
        email_to: Annotated[
            str | None,
            Field(default=None, description="Email address for token delivery."),
        ] = None,
        sms_phone: Annotated[
            str | None, Field(default=None, description="SMS phone number.")
        ] = None,
        two_factor: Annotated[
            str,
            Field(
                default="disable",
                description="Two-factor auth: disable, fortitoken, email, sms.",
            ),
        ] = "disable",
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new local user account."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {
            "name": name,
            "passwd": password,
            "status": status,
            "type": auth_type,
            "two-factor": two_factor,
        }
        if email_to:
            body["email-to"] = email_to
        if sms_phone:
            body["sms-phone"] = sms_phone
        try:
            return await client.cmdb_post("user/local", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def user_local_update(
        ctx: Context,
        name: Annotated[str, Field(description="Username to update.")],
        password: Annotated[
            str | None, Field(default=None, description="New password.")
        ] = None,
        status: Annotated[
            str | None,
            Field(default=None, description="New status: enable or disable."),
        ] = None,
        email_to: Annotated[
            str | None, Field(default=None, description="New email address.")
        ] = None,
        two_factor: Annotated[
            str | None, Field(default=None, description="New two-factor method.")
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Update a local user account."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {}
        if password is not None:
            body["passwd"] = password
        if status is not None:
            body["status"] = status
        if email_to is not None:
            body["email-to"] = email_to
        if two_factor is not None:
            body["two-factor"] = two_factor
        if not body:
            return {"error": "No fields to update were specified."}
        try:
            return await client.cmdb_put(f"user/local/{name}", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def user_local_delete(
        ctx: Context,
        name: Annotated[str, Field(description="Username to delete.")],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Delete a local user account."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_delete(f"user/local/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # USER GROUPS
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def user_group_create(
        ctx: Context,
        name: Annotated[str, Field(description="Group name.")],
        group_type: Annotated[
            str,
            Field(
                default="firewall",
                description="Group type: firewall, fsso-service, rsso, guest.",
            ),
        ] = "firewall",
        members: Annotated[
            list[str] | None,
            Field(default=None, description="List of user names to add as members."),
        ] = None,
        auth_concurrent: Annotated[
            str,
            Field(
                default="enable",
                description="Allow concurrent logins: enable or disable.",
            ),
        ] = "enable",
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new user group."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {
            "name": name,
            "group-type": group_type,
            "auth-concurrent-override": auth_concurrent,
        }
        if members:
            body["member"] = [{"name": m} for m in members]
        try:
            return await client.cmdb_post("user/group", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def user_group_delete(
        ctx: Context,
        name: Annotated[str, Field(description="User group name to delete.")],
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Delete a user group."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        try:
            return await client.cmdb_delete(f"user/group/{name}", vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # RADIUS SERVERS
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def user_radius_create(
        ctx: Context,
        name: Annotated[str, Field(description="RADIUS server name.")],
        server: Annotated[str, Field(description="RADIUS server IP or hostname.")],
        secret: Annotated[str, Field(description="RADIUS shared secret.")],
        auth_type: Annotated[
            str,
            Field(
                default="auto",
                description="Authentication protocol: auto, ms_chap_v2, ms_chap, chap, pap.",
            ),
        ] = "auto",
        port: Annotated[
            int, Field(default=1812, description="RADIUS authentication port.")
        ] = 1812,
        acct_port: Annotated[
            int, Field(default=1813, description="RADIUS accounting port.")
        ] = 1813,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new RADIUS server configuration."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {
            "name": name,
            "server": server,
            "secret": secret,
            "auth-type": auth_type,
            "radius-port": port,
            "acct-port": acct_port,
        }
        try:
            return await client.cmdb_post("user/radius", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # LDAP SERVERS
    # ==================================================================

    @mcp.tool(annotations=CREATES)
    async def user_ldap_create(
        ctx: Context,
        name: Annotated[str, Field(description="LDAP server name.")],
        server: Annotated[str, Field(description="LDAP server IP or hostname.")],
        dn: Annotated[
            str,
            Field(
                description="Distinguished Name base for user searches (e.g. 'dc=example,dc=com')."
            ),
        ],
        username: Annotated[
            str | None,
            Field(
                default=None,
                description="Bind account DN for querying LDAP (leave empty for anonymous bind).",
            ),
        ] = None,
        password: Annotated[
            str | None, Field(default=None, description="Bind account password.")
        ] = None,
        port: Annotated[
            int,
            Field(default=389, description="LDAP port (389 for LDAP, 636 for LDAPS)."),
        ] = 389,
        secure: Annotated[
            str,
            Field(
                default="disable", description="Use TLS: disable, starttls, or ldaps."
            ),
        ] = "disable",
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Create a new LDAP server configuration."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {
            "name": name,
            "server": server,
            "dn": dn,
            "port": port,
            "secure": secure,
        }
        if username:
            body["username"] = username
        if password:
            body["password"] = password
        try:
            return await client.cmdb_post("user/ldap", body, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    # ==================================================================
    # MONITOR: User Sessions
    # ==================================================================

    @mcp.tool(annotations=READ_ONLY)
    async def monitor_user_firewall(
        ctx: Context,
        ip_address: Annotated[
            str | None, Field(default=None, description="Filter by user IP address.")
        ] = None,
        username: Annotated[
            str | None, Field(default=None, description="Filter by username.")
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """List authenticated firewall users and their session information."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        params: dict[str, Any] = {}
        if ip_address:
            params["ipv4"] = ip_address
        if username:
            params["username"] = username
        try:
            return await client.monitor_get("user/firewall", params or None, vdom=vdom)
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

    @mcp.tool(annotations=DESTRUCTIVE)
    async def monitor_user_disconnect(
        ctx: Context,
        id_type: Annotated[
            str,
            Field(description="Disconnect by 'username', 'ip', or 'all'."),
        ],
        id_value: Annotated[
            str | None,
            Field(
                default=None,
                description="Username or IP address (required for username/ip type).",
            ),
        ] = None,
        instance: InstanceParam = None,
        vdom: VdomParam = None,
    ) -> dict[str, Any]:
        """Disconnect an authenticated firewall user session."""
        client: FortiOSAPI = ctx.request_context.lifespan_context["registry"].resolve(
            instance
        )
        body: dict[str, Any] = {"type": id_type}
        if id_value:
            body["id"] = id_value
        try:
            return await client.monitor_post(
                "user/firewall/deauthenticate", body, vdom=vdom
            )
        except FortiOSError as exc:
            return {"error": str(exc), "status_code": exc.status_code}

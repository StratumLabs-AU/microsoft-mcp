import base64
import datetime as dt
import os
import pathlib as pl
import re
from typing import Any
from fastmcp import FastMCP
from . import graph, auth

mcp = FastMCP("microsoft-mcp")

# SECURITY (C2): confine attachment file reads to an allow-listed directory so a caller
# cannot exfiltrate arbitrary host files (the OAuth token cache, other services' .env
# files, /etc/shadow) by passing them as an email attachment path. Defaults to the
# service's private /tmp (PrivateTmp=true isolates it); override with
# MICROSOFT_MCP_ATTACHMENT_DIRS (colon-separated).
_ALLOWED_ATTACHMENT_DIRS = [
    pl.Path(p).expanduser().resolve()
    for p in os.environ.get("MICROSOFT_MCP_ATTACHMENT_DIRS", "/tmp").split(":")
    if p
]


def _safe_attachment_path(file_path: str) -> pl.Path:
    path = pl.Path(file_path).expanduser().resolve()
    for base in _ALLOWED_ATTACHMENT_DIRS:
        try:
            path.relative_to(base)
            return path
        except ValueError:
            continue
    raise ValueError(
        f"Attachment path {path} is outside the allowed attachment directories "
        f"({', '.join(str(b) for b in _ALLOWED_ATTACHMENT_DIRS)}). Set "
        "MICROSOFT_MCP_ATTACHMENT_DIRS to permit additional directories."
    )


# Matches an opening/closing/self-closing/declaration HTML tag, e.g. <p>, </p>,
# <br/>, <div class="x">, <!DOCTYPE html>. Used to auto-detect HTML email bodies so
# the Graph payload sets contentType correctly (otherwise HTML renders as literal
# tags in Outlook).
_HTML_TAG_RE = re.compile(r"<[a-zA-Z!/][^>]*>")


def _detect_body_type(body: str) -> str:
    """Return "HTML" if the body contains an HTML tag, else "Text"."""
    return "HTML" if _HTML_TAG_RE.search(body or "") else "Text"


def _build_body(body: str, body_type: str | None = None) -> dict[str, str]:
    """Build a Graph message body object, choosing the content type.

    body_type, when provided, overrides auto-detection and must be "HTML" or
    "Text" (case-insensitive). When omitted, the type is auto-detected: "HTML" if
    the body contains an HTML tag, otherwise "Text".
    """
    if body_type:
        normalized = body_type.strip().casefold()
        if normalized == "html":
            content_type = "HTML"
        elif normalized == "text":
            content_type = "Text"
        else:
            raise ValueError(
                f"body_type must be 'HTML' or 'Text', got {body_type!r}"
            )
    else:
        content_type = _detect_body_type(body)
    return {"contentType": content_type, "content": body}


FOLDERS = {
    k.casefold(): v
    for k, v in {
        "inbox": "inbox",
        "sent": "sentitems",
        "drafts": "drafts",
        "deleted": "deleteditems",
        "junk": "junkemail",
        "archive": "archive",
    }.items()
}


@mcp.tool
def list_accounts() -> list[dict[str, str]]:
    """List all signed-in Microsoft accounts"""
    return [
        {"username": acc.username, "account_id": acc.account_id}
        for acc in auth.list_accounts()
    ]


@mcp.tool
def authenticate_account() -> dict[str, str]:
    """Authenticate a new Microsoft account using device flow authentication

    Returns authentication instructions and device code for the user to complete authentication.
    The user must visit the URL and enter the code to authenticate their Microsoft account.
    """
    app = auth.get_app()
    flow = app.initiate_device_flow(scopes=auth.SCOPES)

    if "user_code" not in flow:
        error_msg = flow.get("error_description", "Unknown error")
        raise Exception(f"Failed to get device code: {error_msg}")

    verification_url = flow.get(
        "verification_uri",
        flow.get("verification_url", "https://microsoft.com/devicelogin"),
    )

    return {
        "status": "authentication_required",
        "instructions": "To authenticate a new Microsoft account:",
        "step1": f"Visit: {verification_url}",
        "step2": f"Enter code: {flow['user_code']}",
        "step3": "Sign in with the Microsoft account you want to add",
        "step4": "After authenticating, use the 'complete_authentication' tool to finish the process",
        "device_code": flow["user_code"],
        "verification_url": verification_url,
        "expires_in": str(flow.get("expires_in", 900)),
        "_flow_cache": str(flow),
    }


@mcp.tool
def complete_authentication(flow_cache: str) -> dict[str, str]:
    """Complete the authentication process after the user has entered the device code

    Args:
        flow_cache: The flow data returned from authenticate_account (the _flow_cache field)

    Returns:
        Account information if authentication was successful
    """
    import ast

    try:
        flow = ast.literal_eval(flow_cache)
    except (ValueError, SyntaxError):
        raise ValueError("Invalid flow cache data")

    app = auth.get_app()
    result = app.acquire_token_by_device_flow(flow)

    if "error" in result:
        error_msg = result.get("error_description", result["error"])
        if "authorization_pending" in error_msg:
            return {
                "status": "pending",
                "message": "Authentication is still pending. The user needs to complete the authentication process.",
                "instructions": "Please ensure you've visited the URL and entered the code, then try again.",
            }
        raise Exception(f"Authentication failed: {error_msg}")

    # Save the token cache
    cache = app.token_cache
    if isinstance(cache, auth.msal.SerializableTokenCache) and cache.has_state_changed:
        auth._write_cache(cache.serialize())

    # Get the newly added account
    accounts = app.get_accounts()
    if accounts:
        # Find the account that matches the token we just got
        for account in accounts:
            if (
                account.get("username", "").lower()
                == result.get("id_token_claims", {})
                .get("preferred_username", "")
                .lower()
            ):
                return {
                    "status": "success",
                    "username": account["username"],
                    "account_id": account["home_account_id"],
                    "message": f"Successfully authenticated {account['username']}",
                }
        # If exact match not found, return the last account
        account = accounts[-1]
        return {
            "status": "success",
            "username": account["username"],
            "account_id": account["home_account_id"],
            "message": f"Successfully authenticated {account['username']}",
        }

    return {
        "status": "error",
        "message": "Authentication succeeded but no account was found",
    }


@mcp.tool
def list_emails(
    account_id: str,
    folder: str = "inbox",
    limit: int = 10,
    include_body: bool = True,
) -> list[dict[str, Any]]:
    """List emails from specified folder"""
    folder_path = FOLDERS.get(folder.casefold(), folder)

    if include_body:
        select_fields = "id,subject,from,toRecipients,ccRecipients,receivedDateTime,hasAttachments,body,conversationId,isRead"
    else:
        select_fields = "id,subject,from,toRecipients,receivedDateTime,hasAttachments,conversationId,isRead"

    params = {
        "$top": min(limit, 100),
        "$select": select_fields,
        "$orderby": "receivedDateTime desc",
    }

    emails = list(
        graph.request_paginated(
            f"/me/mailFolders/{folder_path}/messages",
            account_id,
            params=params,
            limit=limit,
        )
    )

    return emails


@mcp.tool
def get_email(
    email_id: str,
    account_id: str,
    include_body: bool = True,
    body_max_length: int = 50000,
    include_attachments: bool = True,
) -> dict[str, Any]:
    """Get email details with size limits

    Args:
        email_id: The email ID
        account_id: The account ID
        include_body: Whether to include the email body (default: True)
        body_max_length: Maximum characters for body content (default: 50000)
        include_attachments: Whether to include attachment metadata (default: True)
    """
    params = {}
    if include_attachments:
        params["$expand"] = "attachments($select=id,name,size,contentType)"

    result = graph.request("GET", f"/me/messages/{email_id}", account_id, params=params)
    if not result:
        raise ValueError(f"Email with ID {email_id} not found")

    # Truncate body if needed
    if include_body and "body" in result and "content" in result["body"]:
        content = result["body"]["content"]
        if len(content) > body_max_length:
            result["body"]["content"] = (
                content[:body_max_length]
                + f"\n\n[Content truncated - {len(content)} total characters]"
            )
            result["body"]["truncated"] = True
            result["body"]["total_length"] = len(content)
    elif not include_body and "body" in result:
        del result["body"]

    # Remove attachment content bytes to reduce size
    if "attachments" in result and result["attachments"]:
        for attachment in result["attachments"]:
            if "contentBytes" in attachment:
                del attachment["contentBytes"]

    return result


@mcp.tool
def create_email_draft(
    account_id: str,
    to: str | list[str],
    subject: str,
    body: str,
    cc: str | list[str] | None = None,
    attachments: str | list[str] | None = None,
    body_type: str | None = None,
) -> dict[str, Any]:
    """Create an email draft with file path(s) as attachments

    body_type: optional "HTML" or "Text" to force the body content type. When
    omitted, the type is auto-detected (HTML if the body contains an HTML tag).
    """
    to_list = [to] if isinstance(to, str) else to

    message = {
        "subject": subject,
        "body": _build_body(body, body_type),
        "toRecipients": [{"emailAddress": {"address": addr}} for addr in to_list],
    }

    if cc:
        cc_list = [cc] if isinstance(cc, str) else cc
        message["ccRecipients"] = [
            {"emailAddress": {"address": addr}} for addr in cc_list
        ]

    small_attachments = []
    large_attachments = []

    if attachments:
        # Convert single path to list
        attachment_paths = (
            [attachments] if isinstance(attachments, str) else attachments
        )
        for file_path in attachment_paths:
            path = _safe_attachment_path(file_path)
            content_bytes = path.read_bytes()
            att_size = len(content_bytes)
            att_name = path.name

            if att_size < 3 * 1024 * 1024:
                small_attachments.append(
                    {
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": att_name,
                        "contentBytes": base64.b64encode(content_bytes).decode("utf-8"),
                    }
                )
            else:
                large_attachments.append(
                    {
                        "name": att_name,
                        "content_bytes": content_bytes,
                        "content_type": "application/octet-stream",
                    }
                )

    if small_attachments:
        message["attachments"] = small_attachments

    result = graph.request("POST", "/me/messages", account_id, json=message)
    if not result:
        raise ValueError("Failed to create email draft")

    message_id = result["id"]

    for att in large_attachments:
        graph.upload_large_mail_attachment(
            message_id,
            att["name"],
            att["content_bytes"],
            account_id,
            att.get("content_type", "application/octet-stream"),
        )

    return result


@mcp.tool
def send_email(
    account_id: str,
    to: str | list[str],
    subject: str,
    body: str,
    cc: str | list[str] | None = None,
    attachments: str | list[str] | None = None,
    body_type: str | None = None,
) -> dict[str, str]:
    """Send an email immediately with file path(s) as attachments

    body_type: optional "HTML" or "Text" to force the body content type. When
    omitted, the type is auto-detected (HTML if the body contains an HTML tag).
    """
    to_list = [to] if isinstance(to, str) else to

    message = {
        "subject": subject,
        "body": _build_body(body, body_type),
        "toRecipients": [{"emailAddress": {"address": addr}} for addr in to_list],
    }

    if cc:
        cc_list = [cc] if isinstance(cc, str) else cc
        message["ccRecipients"] = [
            {"emailAddress": {"address": addr}} for addr in cc_list
        ]

    # Check if we have large attachments
    has_large_attachments = False
    processed_attachments = []

    if attachments:
        # Convert single path to list
        attachment_paths = (
            [attachments] if isinstance(attachments, str) else attachments
        )
        for file_path in attachment_paths:
            path = _safe_attachment_path(file_path)
            content_bytes = path.read_bytes()
            att_size = len(content_bytes)
            att_name = path.name

            processed_attachments.append(
                {
                    "name": att_name,
                    "content_bytes": content_bytes,
                    "content_type": "application/octet-stream",
                    "size": att_size,
                }
            )

            if att_size >= 3 * 1024 * 1024:
                has_large_attachments = True

    if not has_large_attachments and processed_attachments:
        message["attachments"] = [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": att["name"],
                "contentBytes": base64.b64encode(att["content_bytes"]).decode("utf-8"),
            }
            for att in processed_attachments
        ]
        graph.request("POST", "/me/sendMail", account_id, json={"message": message})
        return {"status": "sent"}
    elif has_large_attachments:
        # Create draft first, then add large attachments, then send
        # We need to handle large attachments manually here
        to_list = [to] if isinstance(to, str) else to
        message = {
            "subject": subject,
            "body": _build_body(body, body_type),
            "toRecipients": [{"emailAddress": {"address": addr}} for addr in to_list],
        }
        if cc:
            cc_list = [cc] if isinstance(cc, str) else cc
            message["ccRecipients"] = [
                {"emailAddress": {"address": addr}} for addr in cc_list
            ]

        result = graph.request("POST", "/me/messages", account_id, json=message)
        if not result:
            raise ValueError("Failed to create email draft")

        message_id = result["id"]

        for att in processed_attachments:
            if att["size"] >= 3 * 1024 * 1024:
                graph.upload_large_mail_attachment(
                    message_id,
                    att["name"],
                    att["content_bytes"],
                    account_id,
                    att.get("content_type", "application/octet-stream"),
                )
            else:
                small_att = {
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "name": att["name"],
                    "contentBytes": base64.b64encode(att["content_bytes"]).decode(
                        "utf-8"
                    ),
                }
                graph.request(
                    "POST",
                    f"/me/messages/{message_id}/attachments",
                    account_id,
                    json=small_att,
                )

        graph.request("POST", f"/me/messages/{message_id}/send", account_id)
        return {"status": "sent"}
    else:
        graph.request("POST", "/me/sendMail", account_id, json={"message": message})
        return {"status": "sent"}


@mcp.tool
def update_email(
    email_id: str, updates: dict[str, Any], account_id: str
) -> dict[str, Any]:
    """Update email properties (isRead, categories, flag, etc.)"""
    result = graph.request(
        "PATCH", f"/me/messages/{email_id}", account_id, json=updates
    )
    if not result:
        raise ValueError(f"Failed to update email {email_id} - no response")
    return result


@mcp.tool
def delete_email(email_id: str, account_id: str) -> dict[str, str]:
    """Delete an email"""
    graph.request("DELETE", f"/me/messages/{email_id}", account_id)
    return {"status": "deleted"}


@mcp.tool
def move_email(
    email_id: str, destination_folder: str, account_id: str
) -> dict[str, Any]:
    """Move email to another folder"""
    folder_path = FOLDERS.get(destination_folder.casefold(), destination_folder)

    folders = graph.request("GET", "/me/mailFolders", account_id)
    folder_id = None

    if not folders:
        raise ValueError("Failed to retrieve mail folders")
    if "value" not in folders:
        raise ValueError(f"Unexpected folder response structure: {folders}")

    for folder in folders["value"]:
        if folder["displayName"].lower() == folder_path.lower():
            folder_id = folder["id"]
            break

    if not folder_id:
        raise ValueError(f"Folder '{destination_folder}' not found")

    payload = {"destinationId": folder_id}
    result = graph.request(
        "POST", f"/me/messages/{email_id}/move", account_id, json=payload
    )
    if not result:
        raise ValueError("Failed to move email - no response from server")
    if "id" not in result:
        raise ValueError(f"Failed to move email - unexpected response: {result}")
    return {"status": "moved", "new_id": result["id"]}


@mcp.tool
def reply_to_email(
    account_id: str, email_id: str, body: str, body_type: str | None = None
) -> dict[str, str]:
    """Reply to an email (sender only)

    body_type: optional "HTML" or "Text" to force the body content type. When
    omitted, the type is auto-detected (HTML if the body contains an HTML tag).
    """
    endpoint = f"/me/messages/{email_id}/reply"
    payload = {"message": {"body": _build_body(body, body_type)}}
    graph.request("POST", endpoint, account_id, json=payload)
    return {"status": "sent"}


@mcp.tool
def reply_all_email(
    account_id: str, email_id: str, body: str, body_type: str | None = None
) -> dict[str, str]:
    """Reply to all recipients of an email

    body_type: optional "HTML" or "Text" to force the body content type. When
    omitted, the type is auto-detected (HTML if the body contains an HTML tag).
    """
    endpoint = f"/me/messages/{email_id}/replyAll"
    payload = {"message": {"body": _build_body(body, body_type)}}
    graph.request("POST", endpoint, account_id, json=payload)
    return {"status": "sent"}


@mcp.tool
def list_events(
    account_id: str,
    days_ahead: int = 7,
    days_back: int = 0,
    include_details: bool = True,
) -> list[dict[str, Any]]:
    """List calendar events within specified date range, including recurring event instances"""
    now = dt.datetime.now(dt.timezone.utc)
    start = (now - dt.timedelta(days=days_back)).isoformat()
    end = (now + dt.timedelta(days=days_ahead)).isoformat()

    params = {
        "startDateTime": start,
        "endDateTime": end,
        "$orderby": "start/dateTime",
        "$top": 100,
    }

    if include_details:
        params["$select"] = (
            "id,subject,start,end,location,body,attendees,organizer,isAllDay,recurrence,onlineMeeting,seriesMasterId"
        )
    else:
        params["$select"] = "id,subject,start,end,location,organizer,seriesMasterId"

    # Use calendarView to get recurring event instances
    events = list(
        graph.request_paginated("/me/calendarView", account_id, params=params)
    )

    return events


@mcp.tool
def get_event(event_id: str, account_id: str) -> dict[str, Any]:
    """Get full event details"""
    result = graph.request("GET", f"/me/events/{event_id}", account_id)
    if not result:
        raise ValueError(f"Event with ID {event_id} not found")
    return result


@mcp.tool
def create_event(
    account_id: str,
    subject: str,
    start: str,
    end: str,
    location: str | None = None,
    body: str | None = None,
    attendees: str | list[str] | None = None,
    timezone: str = "UTC",
) -> dict[str, Any]:
    """Create a calendar event"""
    event = {
        "subject": subject,
        "start": {"dateTime": start, "timeZone": timezone},
        "end": {"dateTime": end, "timeZone": timezone},
    }

    if location:
        event["location"] = {"displayName": location}

    if body:
        event["body"] = {"contentType": "Text", "content": body}

    if attendees:
        attendees_list = [attendees] if isinstance(attendees, str) else attendees
        event["attendees"] = [
            {"emailAddress": {"address": a}, "type": "required"} for a in attendees_list
        ]

    result = graph.request("POST", "/me/events", account_id, json=event)
    if not result:
        raise ValueError("Failed to create event")
    return result


@mcp.tool
def update_event(
    event_id: str, updates: dict[str, Any], account_id: str
) -> dict[str, Any]:
    """Update event properties"""
    formatted_updates = {}

    if "subject" in updates:
        formatted_updates["subject"] = updates["subject"]
    if "start" in updates:
        formatted_updates["start"] = {
            "dateTime": updates["start"],
            "timeZone": updates.get("timezone", "UTC"),
        }
    if "end" in updates:
        formatted_updates["end"] = {
            "dateTime": updates["end"],
            "timeZone": updates.get("timezone", "UTC"),
        }
    if "location" in updates:
        formatted_updates["location"] = {"displayName": updates["location"]}
    if "body" in updates:
        formatted_updates["body"] = {"contentType": "Text", "content": updates["body"]}

    result = graph.request(
        "PATCH", f"/me/events/{event_id}", account_id, json=formatted_updates
    )
    return result or {"status": "updated"}


@mcp.tool
def delete_event(
    account_id: str, event_id: str, send_cancellation: bool = True
) -> dict[str, str]:
    """Delete or cancel a calendar event"""
    if send_cancellation:
        graph.request("POST", f"/me/events/{event_id}/cancel", account_id, json={})
    else:
        graph.request("DELETE", f"/me/events/{event_id}", account_id)
    return {"status": "deleted"}


@mcp.tool
def respond_event(
    account_id: str,
    event_id: str,
    response: str = "accept",
    message: str | None = None,
) -> dict[str, str]:
    """Respond to event invitation (accept, decline, tentativelyAccept)"""
    payload: dict[str, Any] = {"sendResponse": True}
    if message:
        payload["comment"] = message

    graph.request("POST", f"/me/events/{event_id}/{response}", account_id, json=payload)
    return {"status": response}


@mcp.tool
def check_availability(
    account_id: str,
    start: str,
    end: str,
    attendees: str | list[str] | None = None,
) -> dict[str, Any]:
    """Check calendar availability for scheduling"""
    me_info = graph.request("GET", "/me", account_id)
    if not me_info or "mail" not in me_info:
        raise ValueError("Failed to get user email address")
    schedules = [me_info["mail"]]
    if attendees:
        attendees_list = [attendees] if isinstance(attendees, str) else attendees
        schedules.extend(attendees_list)

    payload = {
        "schedules": schedules,
        "startTime": {"dateTime": start, "timeZone": "UTC"},
        "endTime": {"dateTime": end, "timeZone": "UTC"},
        "availabilityViewInterval": 30,
    }

    result = graph.request("POST", "/me/calendar/getSchedule", account_id, json=payload)
    if not result:
        raise ValueError("Failed to check availability")
    return result


@mcp.tool
def list_contacts(account_id: str, limit: int = 50) -> list[dict[str, Any]]:
    """List contacts"""
    params = {"$top": min(limit, 100)}

    contacts = list(
        graph.request_paginated("/me/contacts", account_id, params=params, limit=limit)
    )

    return contacts


@mcp.tool
def get_contact(contact_id: str, account_id: str) -> dict[str, Any]:
    """Get contact details"""
    result = graph.request("GET", f"/me/contacts/{contact_id}", account_id)
    if not result:
        raise ValueError(f"Contact with ID {contact_id} not found")
    return result


@mcp.tool
def create_contact(
    account_id: str,
    given_name: str,
    surname: str | None = None,
    email_addresses: str | list[str] | None = None,
    phone_numbers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create a new contact"""
    contact: dict[str, Any] = {"givenName": given_name}

    if surname:
        contact["surname"] = surname

    if email_addresses:
        email_list = (
            [email_addresses] if isinstance(email_addresses, str) else email_addresses
        )
        contact["emailAddresses"] = [
            {"address": email, "name": f"{given_name} {surname or ''}".strip()}
            for email in email_list
        ]

    if phone_numbers:
        if "business" in phone_numbers:
            contact["businessPhones"] = [phone_numbers["business"]]
        if "home" in phone_numbers:
            contact["homePhones"] = [phone_numbers["home"]]
        if "mobile" in phone_numbers:
            contact["mobilePhone"] = phone_numbers["mobile"]

    result = graph.request("POST", "/me/contacts", account_id, json=contact)
    if not result:
        raise ValueError("Failed to create contact")
    return result


@mcp.tool
def update_contact(
    contact_id: str, updates: dict[str, Any], account_id: str
) -> dict[str, Any]:
    """Update contact information"""
    result = graph.request(
        "PATCH", f"/me/contacts/{contact_id}", account_id, json=updates
    )
    return result or {"status": "updated"}


@mcp.tool
def delete_contact(contact_id: str, account_id: str) -> dict[str, str]:
    """Delete a contact"""
    graph.request("DELETE", f"/me/contacts/{contact_id}", account_id)
    return {"status": "deleted"}


@mcp.tool
def list_files(
    account_id: str, path: str = "/", limit: int = 50
) -> list[dict[str, Any]]:
    """List files and folders in OneDrive"""
    endpoint = (
        "/me/drive/root/children"
        if path == "/"
        else f"/me/drive/root:/{path}:/children"
    )
    params = {
        "$top": min(limit, 100),
        "$select": "id,name,size,lastModifiedDateTime,folder,file,@microsoft.graph.downloadUrl",
    }

    items = list(
        graph.request_paginated(endpoint, account_id, params=params, limit=limit)
    )

    return [
        {
            "id": item["id"],
            "name": item["name"],
            "type": "folder" if "folder" in item else "file",
            "size": item.get("size", 0),
            "modified": item.get("lastModifiedDateTime"),
            "download_url": item.get("@microsoft.graph.downloadUrl"),
        }
        for item in items
    ]


@mcp.tool
def get_file(file_id: str, account_id: str, download_path: str) -> dict[str, Any]:
    """Download a file from OneDrive to local path"""
    import subprocess

    metadata = graph.request("GET", f"/me/drive/items/{file_id}", account_id)
    if not metadata:
        raise ValueError(f"File with ID {file_id} not found")

    download_url = metadata.get("@microsoft.graph.downloadUrl")
    if not download_url:
        raise ValueError("No download URL available for this file")

    try:
        subprocess.run(
            ["curl", "-L", "-o", download_path, download_url],
            check=True,
            capture_output=True,
        )

        return {
            "path": download_path,
            "name": metadata.get("name", "unknown"),
            "size_mb": round(metadata.get("size", 0) / (1024 * 1024), 2),
            "mime_type": metadata.get("file", {}).get("mimeType") if metadata else None,
        }
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to download file: {e.stderr.decode()}")


@mcp.tool
def create_file(
    onedrive_path: str, local_file_path: str, account_id: str
) -> dict[str, Any]:
    """Upload a local file to OneDrive"""
    path = pl.Path(local_file_path).expanduser().resolve()
    data = path.read_bytes()
    result = graph.upload_large_file(
        f"/me/drive/root:/{onedrive_path}:", data, account_id
    )
    if not result:
        raise ValueError(f"Failed to create file at path: {onedrive_path}")
    return result


@mcp.tool
def update_file(file_id: str, local_file_path: str, account_id: str) -> dict[str, Any]:
    """Update OneDrive file content from a local file"""
    path = pl.Path(local_file_path).expanduser().resolve()
    data = path.read_bytes()
    result = graph.upload_large_file(f"/me/drive/items/{file_id}", data, account_id)
    if not result:
        raise ValueError(f"Failed to update file with ID: {file_id}")
    return result


@mcp.tool
def delete_file(file_id: str, account_id: str) -> dict[str, str]:
    """Delete a file or folder"""
    graph.request("DELETE", f"/me/drive/items/{file_id}", account_id)
    return {"status": "deleted"}


@mcp.tool
def get_attachment(
    email_id: str, attachment_id: str, save_path: str, account_id: str
) -> dict[str, Any]:
    """Download email attachment to a specified file path"""
    result = graph.request(
        "GET", f"/me/messages/{email_id}/attachments/{attachment_id}", account_id
    )

    if not result:
        raise ValueError("Attachment not found")

    if "contentBytes" not in result:
        raise ValueError("Attachment content not available")

    # Save attachment to file
    path = pl.Path(save_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    content_bytes = base64.b64decode(result["contentBytes"])
    path.write_bytes(content_bytes)

    return {
        "name": result.get("name", "unknown"),
        "content_type": result.get("contentType", "application/octet-stream"),
        "size": result.get("size", 0),
        "saved_to": str(path),
    }


@mcp.tool
def search_files(
    query: str,
    account_id: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search for files in OneDrive using the modern search API."""
    items = list(graph.search_query(query, ["driveItem"], account_id, limit))

    return [
        {
            "id": item["id"],
            "name": item["name"],
            "type": "folder" if "folder" in item else "file",
            "size": item.get("size", 0),
            "modified": item.get("lastModifiedDateTime"),
            "download_url": item.get("@microsoft.graph.downloadUrl"),
        }
        for item in items
    ]


@mcp.tool
def search_emails(
    query: str,
    account_id: str,
    limit: int = 50,
    folder: str | None = None,
) -> list[dict[str, Any]]:
    """Search emails using the modern search API."""
    if folder:
        # For folder-specific search, use the traditional endpoint
        folder_path = FOLDERS.get(folder.casefold(), folder)
        endpoint = f"/me/mailFolders/{folder_path}/messages"

        params = {
            "$search": f'"{query}"',
            "$top": min(limit, 100),
            "$select": "id,subject,from,toRecipients,receivedDateTime,hasAttachments,body,conversationId,isRead",
        }

        return list(
            graph.request_paginated(endpoint, account_id, params=params, limit=limit)
        )

    return list(graph.search_query(query, ["message"], account_id, limit))


@mcp.tool
def search_events(
    query: str,
    account_id: str,
    days_ahead: int = 365,
    days_back: int = 365,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search calendar events using the modern search API."""
    events = list(graph.search_query(query, ["event"], account_id, limit))

    # Filter by date range if needed
    if days_ahead != 365 or days_back != 365:
        now = dt.datetime.now(dt.timezone.utc)
        start = now - dt.timedelta(days=days_back)
        end = now + dt.timedelta(days=days_ahead)

        filtered_events = []
        for event in events:
            event_start = dt.datetime.fromisoformat(
                event.get("start", {}).get("dateTime", "").replace("Z", "+00:00")
            )
            event_end = dt.datetime.fromisoformat(
                event.get("end", {}).get("dateTime", "").replace("Z", "+00:00")
            )

            if event_start <= end and event_end >= start:
                filtered_events.append(event)

        return filtered_events

    return events


@mcp.tool
def search_contacts(
    query: str,
    account_id: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search contacts. Uses traditional search since unified_search doesn't support contacts."""
    params = {
        "$search": f'"{query}"',
        "$top": min(limit, 100),
    }

    contacts = list(
        graph.request_paginated("/me/contacts", account_id, params=params, limit=limit)
    )

    return contacts


@mcp.tool
def unified_search(
    query: str,
    account_id: str,
    entity_types: list[str] | None = None,
    limit: int = 50,
) -> dict[str, list[dict[str, Any]]]:
    """Search across multiple Microsoft 365 resources using the modern search API

    entity_types can include: 'message', 'event', 'drive', 'driveItem', 'list', 'listItem', 'site'
    If not specified, searches across all available types.
    """
    if not entity_types:
        entity_types = ["message", "event", "driveItem"]

    results = {entity_type: [] for entity_type in entity_types}

    items = list(graph.search_query(query, entity_types, account_id, limit))

    for item in items:
        resource_type = item.get("@odata.type", "").split(".")[-1]

        if resource_type == "message":
            results.setdefault("message", []).append(item)
        elif resource_type == "event":
            results.setdefault("event", []).append(item)
        elif resource_type in ["driveItem", "file", "folder"]:
            results.setdefault("driveItem", []).append(item)
        else:
            results.setdefault("other", []).append(item)

    return {k: v for k, v in results.items() if v}


# --- SharePoint sites & lists -------------------------------------------------

_COLUMN_TYPES = (
    "text",
    "choice",
    "number",
    "currency",
    "dateTime",
    "boolean",
    "personOrGroup",
    "lookup",
    "hyperlinkOrPicture",
    "calculated",
    "term",
    "geolocation",
    "thumbnail",
)

_SYSTEM_FIELDS = {
    "ContentType",
    "Edit",
    "LinkTitle",
    "LinkTitleNoMenu",
    "DocIcon",
    "ItemChildCount",
    "FolderChildCount",
    "AppAuthorLookupId",
    "AppEditorLookupId",
    "Attachments",
}


def _encode_share_url(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return f"u!{encoded}"


def _clean_fields(fields: dict[str, Any]) -> dict[str, Any]:
    return {
        k: v
        for k, v in fields.items()
        if not k.startswith(("@", "_")) and k not in _SYSTEM_FIELDS
    }


def _format_list(lst: dict[str, Any]) -> dict[str, Any]:
    return {
        "site_id": lst.get("parentReference", {}).get("siteId"),
        "list_id": lst["id"],
        "name": lst.get("displayName") or lst.get("name"),
        "description": lst.get("description"),
        "template": lst.get("list", {}).get("template"),
        "web_url": lst.get("webUrl"),
        "modified": lst.get("lastModifiedDateTime"),
    }


def _format_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item["id"],
        "web_url": item.get("webUrl"),
        "created": item.get("createdDateTime"),
        "modified": item.get("lastModifiedDateTime"),
        "fields": _clean_fields(item.get("fields", {})),
    }


@mcp.tool
def resolve_sharepoint_url(url: str, account_id: str) -> dict[str, Any]:
    """Resolve a SharePoint URL to site_id (and list_id when it points at a list).

    Accepts a sharing link (e.g. https://tenant.sharepoint.com/:l:/s/site/...),
    a site URL (https://tenant.sharepoint.com/sites/site) or a list URL
    (https://tenant.sharepoint.com/sites/site/Lists/MyList/AllItems.aspx).
    """
    parsed = url.split("?")[0]
    host_and_path = parsed.split("://", 1)[-1]
    host, _, path = host_and_path.partition("/")

    if re.match(r"^:[a-z]:/", path):
        lst = graph.request("GET", f"/shares/{_encode_share_url(url)}/list", account_id)
        if not lst:
            raise ValueError(f"Sharing link did not resolve to a list: {url}")
        return _format_list(lst)

    match = re.match(r"^((?:sites|teams)/[^/]+)(?:/Lists/([^/]+))?", path)
    site_path = f":/{match.group(1)}" if match else ""
    site = graph.request("GET", f"/sites/{host}{site_path}", account_id)
    if not site:
        raise ValueError(f"Could not resolve site: {url}")

    result = {"site_id": site["id"], "site_name": site.get("displayName")}
    if match and match.group(2):
        list_name = match.group(2)
        lists = graph.request_paginated(
            f"/sites/{site['id']}/lists",
            account_id,
            params={"$select": "id,name,displayName,webUrl"},
        )
        for lst in lists:
            if lst.get("webUrl", "").rstrip("/").endswith(f"/Lists/{list_name}"):
                result.update(list_id=lst["id"], name=lst.get("displayName"))
                break
    return result


@mcp.tool
def list_sharepoint_lists(
    site_id: str, account_id: str, include_hidden: bool = False
) -> list[dict[str, Any]]:
    """List the lists (and document libraries) in a SharePoint site"""
    params = {"$select": "id,name,displayName,description,webUrl,lastModifiedDateTime,list,parentReference"}
    lists = graph.request_paginated(f"/sites/{site_id}/lists", account_id, params=params)
    return [
        _format_list(lst)
        for lst in lists
        if include_hidden or not lst.get("list", {}).get("hidden")
    ]


@mcp.tool
def get_sharepoint_list_columns(
    site_id: str, list_id: str, account_id: str, include_system: bool = False
) -> list[dict[str, Any]]:
    """Get a SharePoint list's columns: internal name (use this in fields/filters),
    display name, type, and choices for choice columns"""
    columns = graph.request_paginated(
        f"/sites/{site_id}/lists/{list_id}/columns", account_id
    )
    result = []
    for col in columns:
        if not include_system and (
            col.get("hidden")
            or col["name"] in _SYSTEM_FIELDS
            or (col.get("readOnly") and col["name"] != "Title")
        ):
            continue
        col_type = next((t for t in _COLUMN_TYPES if t in col), "unknown")
        entry = {
            "name": col["name"],
            "display_name": col.get("displayName"),
            "type": col_type,
            "required": col.get("required", False),
            "read_only": col.get("readOnly", False),
            "description": col.get("description") or None,
        }
        if col_type == "choice":
            entry["choices"] = col["choice"].get("choices", [])
            entry["multi_select"] = col["choice"].get("displayAs") == "checkBoxes"
        elif col_type == "lookup":
            entry["lookup_list_id"] = col["lookup"].get("listId")
        result.append(entry)
    return result


@mcp.tool
def list_sharepoint_list_items(
    site_id: str,
    list_id: str,
    account_id: str,
    filter: str | None = None,
    fields: list[str] | None = None,
    order_by: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """List items in a SharePoint list with their field values.

    filter: OData filter on internal column names, e.g. "fields/Status eq 'Active'"
    fields: internal column names to return (default: all)
    order_by: e.g. "fields/Title desc"
    """
    expand = f"fields($select={','.join(fields)})" if fields else "fields"
    params: dict[str, Any] = {"$expand": expand, "$top": min(limit, 200)}
    if filter:
        params["$filter"] = filter
    if order_by:
        params["$orderby"] = order_by

    items = graph.request_paginated(
        f"/sites/{site_id}/lists/{list_id}/items",
        account_id,
        params=params,
        limit=limit,
        extra_headers={"Prefer": "HonorNonIndexedQueriesWarningMayFailRandomly"},
    )
    return [_format_item(item) for item in items]


@mcp.tool
def get_sharepoint_list_item(
    site_id: str, list_id: str, item_id: str, account_id: str
) -> dict[str, Any]:
    """Get a single SharePoint list item with all field values"""
    item = graph.request(
        "GET",
        f"/sites/{site_id}/lists/{list_id}/items/{item_id}",
        account_id,
        params={"$expand": "fields"},
    )
    if not item:
        raise ValueError(f"List item {item_id} not found")
    return _format_item(item)


@mcp.tool
def create_sharepoint_list_item(
    site_id: str, list_id: str, fields: dict[str, Any], account_id: str
) -> dict[str, Any]:
    """Create a SharePoint list item. fields maps internal column names to values,
    e.g. {"Title": "Project A", "Status": "Active"}"""
    item = graph.request(
        "POST",
        f"/sites/{site_id}/lists/{list_id}/items",
        account_id,
        json={"fields": fields},
    )
    if not item:
        raise ValueError("Failed to create list item")
    return _format_item(item)


@mcp.tool
def update_sharepoint_list_item(
    site_id: str,
    list_id: str,
    item_id: str,
    fields: dict[str, Any],
    account_id: str,
) -> dict[str, Any]:
    """Update fields on a SharePoint list item (only the fields given are changed)"""
    result = graph.request(
        "PATCH",
        f"/sites/{site_id}/lists/{list_id}/items/{item_id}/fields",
        account_id,
        json=fields,
    )
    return {"id": item_id, "fields": _clean_fields(result or {})}


@mcp.tool
def delete_sharepoint_list_item(
    site_id: str, list_id: str, item_id: str, account_id: str
) -> dict[str, str]:
    """Delete a SharePoint list item"""
    graph.request(
        "DELETE", f"/sites/{site_id}/lists/{list_id}/items/{item_id}", account_id
    )
    return {"status": "deleted"}


# --- SharePoint list schema (needs Sites.Manage.All) ---------------------------

_COLUMN_KINDS = (
    "text", "multiline", "choice", "number", "currency", "date", "datetime",
    "boolean", "person", "lookup",
)


def _internal_name(display_name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9]", "", display_name)
    if not name:
        raise ValueError(f"Column name {display_name!r} needs at least one letter or digit")
    return name if not name[0].isdigit() else f"C{name}"


def _column_definition(
    display_name: str,
    kind: str,
    *,
    choices: list[str] | None = None,
    multi_select: bool = False,
    required: bool = False,
    description: str | None = None,
    lookup_list_id: str | None = None,
    lookup_column: str = "Title",
    default: str | None = None,
) -> dict[str, Any]:
    kind = kind.lower()
    if kind in ("image", "thumbnail", "picture"):
        raise ValueError("Image columns can't be created through Graph; add them in the SharePoint UI")
    if kind in ("hyperlink", "url", "link"):
        raise ValueError("Hyperlink columns can't be created through Graph; use a multiline text column for links, or add one in the SharePoint UI")
    if kind not in _COLUMN_KINDS:
        raise ValueError(f"type must be one of {', '.join(_COLUMN_KINDS)}")
    col: dict[str, Any] = {
        "name": _internal_name(display_name),
        "displayName": display_name,
        "required": required,
    }
    if description:
        col["description"] = description
    if default is not None:
        col["defaultValue"] = {"value": str(default)}
    if kind == "text":
        col["text"] = {}
    elif kind == "multiline":
        col["text"] = {"allowMultipleLines": True, "linesForEditing": 6}
    elif kind == "choice":
        if not choices:
            raise ValueError("choice columns need a list of choices")
        col["choice"] = {
            "choices": list(dict.fromkeys(choices)),
            "displayAs": "checkBoxes" if multi_select else "dropDownMenu",
        }
    elif kind == "number":
        col["number"] = {}
    elif kind == "currency":
        col["currency"] = {"locale": "en-AU"}
    elif kind == "date":
        col["dateTime"] = {"format": "dateOnly"}
    elif kind == "datetime":
        col["dateTime"] = {"format": "dateTime"}
    elif kind == "boolean":
        col["boolean"] = {}
    elif kind == "person":
        col["personOrGroup"] = {"allowMultipleSelection": multi_select, "chooseFromType": "peopleOnly"}
    elif kind == "lookup":
        if not lookup_list_id:
            raise ValueError("lookup columns need lookup_list_id")
        col["lookup"] = {"listId": lookup_list_id, "columnName": lookup_column, "allowMultipleValues": multi_select}
    return col


def _resolve_column(site_id: str, list_id: str, column: str, account_id: str) -> dict[str, Any]:
    cols = graph.request("GET", f"/sites/{site_id}/lists/{list_id}/columns", account_id) or {}
    for c in cols.get("value", []):
        if column in (c.get("id"), c.get("name"), c.get("displayName")):
            return c
    raise ValueError(f"No column {column!r} in list {list_id}")


@mcp.tool
def create_sharepoint_list(
    site_id: str,
    display_name: str,
    account_id: str,
    description: str | None = None,
    columns: list[dict[str, Any]] | None = None,
    document_library: bool = False,
) -> dict[str, Any]:
    """Create a SharePoint list (or document library) with optional columns.

    columns: [{"name": "Client", "type": "text"},
              {"name": "Stage", "type": "choice", "choices": ["Briefing", "Building"]},
              {"name": "Sectors", "type": "choice", "choices": [...], "multi_select": true},
              {"name": "Fee", "type": "currency", "required": true},
              {"name": "Person", "type": "lookup", "lookup_list_id": "<list id>"}]
    type: text, multiline, choice, number, currency, date, datetime, boolean,
    person, lookup. Every list already has a Title column.
    Returns the new list plus any columns that failed.
    """
    lst = graph.request(
        "POST",
        f"/sites/{site_id}/lists",
        account_id,
        json={
            "displayName": display_name,
            "description": description or "",
            "list": {"template": "documentLibrary" if document_library else "genericList"},
        },
    )
    if not lst:
        raise ValueError("Failed to create list")
    created, failed = [], []
    for spec in columns or []:
        spec = dict(spec)
        name = spec.pop("name", None) or spec.pop("display_name", None)
        kind = spec.pop("type", "text")
        try:
            body = _column_definition(name, kind, **spec)
            graph.request("POST", f"/sites/{site_id}/lists/{lst['id']}/columns", account_id, json=body)
            created.append(name)
        except Exception as e:  # keep going; report per-column failures
            failed.append({"column": name, "error": str(e)[:200]})
    out = _format_list(lst)
    out["site_id"] = out.get("site_id") or site_id
    out.update(columns_created=created, columns_failed=failed)
    return out


@mcp.tool
def update_sharepoint_list(
    site_id: str,
    list_id: str,
    account_id: str,
    display_name: str | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """Rename a SharePoint list or change its description"""
    body = {k: v for k, v in (("displayName", display_name), ("description", description)) if v is not None}
    if not body:
        raise ValueError("Nothing to update")
    lst = graph.request("PATCH", f"/sites/{site_id}/lists/{list_id}", account_id, json=body)
    return _format_list(lst or {"id": list_id})


@mcp.tool
def add_list_column(
    site_id: str,
    list_id: str,
    name: str,
    account_id: str,
    type: str = "text",
    choices: list[str] | None = None,
    multi_select: bool = False,
    required: bool = False,
    description: str | None = None,
    lookup_list_id: str | None = None,
    lookup_column: str = "Title",
    default: str | None = None,
) -> dict[str, Any]:
    """Add a column to a SharePoint list.

    type: text, multiline, choice, number, currency, date, datetime, boolean,
    person, lookup. Image and hyperlink columns can't be created through Graph.
    multi_select applies to choice, person and lookup columns.
    """
    body = _column_definition(
        name, type, choices=choices, multi_select=multi_select, required=required,
        description=description, lookup_list_id=lookup_list_id, lookup_column=lookup_column, default=default,
    )
    col = graph.request("POST", f"/sites/{site_id}/lists/{list_id}/columns", account_id, json=body)
    return {"id": (col or {}).get("id"), "name": body["name"], "display_name": name, "type": type}


@mcp.tool
def update_list_column(
    site_id: str,
    list_id: str,
    column: str,
    account_id: str,
    display_name: str | None = None,
    description: str | None = None,
    required: bool | None = None,
    choices: list[str] | None = None,
    hidden: bool | None = None,
) -> dict[str, Any]:
    """Change a column: rename it, change its description or required flag,
    replace its choices (choice columns), or hide it. column: id, internal name
    or display name. A column's type can't be changed; add a new column instead."""
    col = _resolve_column(site_id, list_id, column, account_id)
    body: dict[str, Any] = {}
    if display_name is not None:
        body["displayName"] = display_name
    if description is not None:
        body["description"] = description
    if required is not None:
        body["required"] = required
    if hidden is not None:
        body["hidden"] = hidden
    if choices is not None:
        if "choice" not in col:
            raise ValueError(f"{col.get('displayName')} is not a choice column")
        body["choice"] = {**col["choice"], "choices": list(dict.fromkeys(choices))}
    if not body:
        raise ValueError("Nothing to update")
    graph.request("PATCH", f"/sites/{site_id}/lists/{list_id}/columns/{col['id']}", account_id, json=body)
    return {"id": col["id"], "name": col.get("name"), "updated": sorted(body)}


@mcp.tool
def delete_list_column(
    site_id: str, list_id: str, column: str, account_id: str
) -> dict[str, str]:
    """Delete a column and all its data from a SharePoint list. Confirm with the
    user first. column: id, internal name or display name."""
    col = _resolve_column(site_id, list_id, column, account_id)
    if col.get("readOnly") or col.get("name") == "Title":
        raise ValueError(f"{col.get('displayName')} is a built-in column and can't be deleted")
    graph.request("DELETE", f"/sites/{site_id}/lists/{list_id}/columns/{col['id']}", account_id)
    return {"status": "deleted", "column": col.get("displayName") or col.get("name")}

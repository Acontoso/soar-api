import requests
from application.services.servicesaws import CognitoServices
from azure.identity import ClientAssertionCredential
from flask import current_app
from typing import Optional
import os
import json

TENANT_ID = os.getenv("TENANT_ID")
REGION = "ap-southeast-2"
APPROVED_LIST_NAMES = ["SOAR-API-Locations"]
APPROVED_LIST_IDS = [
    "0b7f8da0-a271-4bf8-9c85-01c7514766c9",
    "043e37d2-8214-41db-9b4f-b4291ddd6382",
]
WESHEALTH_GRAPH_AZ_CLIENT_ID = "12f71dfd-10c2-4bb9-a1de-347f270acc1a"
WESHEALTH_MA_GRAPH_AZ_CLIENT_ID = "aa9c2c20-b0f9-4e75-a9bf-19fff70641d0"


class Azure:
    @classmethod
    def az_ad_list_upload(
        cls, ioc: str, list_id: str, list_name: str, tenant_id: str
    ) -> bool:
        if not all([ioc, list_id, list_name]):
            current_app.logger.error("One or more required parameters are empty.")
            return False
        if list_name not in APPROVED_LIST_NAMES or list_id not in APPROVED_LIST_IDS:
            current_app.logger.error(
                f"List name {list_name} or list ID {list_id} is not approved."
            )
            return False
        match list_id:
            case "0b7f8da0-a271-4bf8-9c85-01c7514766c9":
                client_id = WESHEALTH_GRAPH_AZ_CLIENT_ID
            case "043e37d2-8214-41db-9b4f-b4291ddd6382":
                client_id = WESHEALTH_MA_GRAPH_AZ_CLIENT_ID
            case _:
                current_app.logger.error(f"Unknown list_id: {list_id}")
                return False
        endpoint = f"https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/{list_id}"
        payload = {
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "displayName": list_name,
            "isTrusted": False,
            "ipRanges": [],
        }
        token = cls.access_token_graph_api(client_id, tenant_id)
        if token:
            header = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            data = {"@odata.type": "#microsoft.graph.iPv4CidrRange", "cidrAddress": ioc}
            payload["ipRanges"].append(data)
            original_list_response = requests.get(url=endpoint, headers=header)
            if original_list_response.status_code == 200:
                current_app.logger.info(
                    f"[+] Successfully pulled the original IP's from the to Azure AD list {list_name}"
                )
                ip_ranges = original_list_response.json().get("ipRanges")
                payload["ipRanges"].extend(ip_ranges)
            else:
                return False
            response = requests.patch(
                url=endpoint, headers=header, data=json.dumps(payload)
            )
            if response.status_code == 204:
                current_app.logger.info(
                    f"[+] Successfully added IP {ioc} to Azure AD list {list_name}"
                )
                return True
            else:
                current_app.logger.error(
                    f"[+] Failed to add IP {ioc} to Azure AD list {list_name}"
                )
                current_app.logger.error(
                    f"[-] Status code: {response.status_code}, Response: {response.text}"
                )
                return False
        else:
            return False

    @classmethod
    def access_token_graph_api(cls, client_id: str, tenant_id: str) -> Optional[str]:
        """Get OAuth access token to send data to MS Graph API"""
        current_app.logger.info("[+] Requesting API key for Graph API")
        scope = "https://graph.microsoft.com/.default"
        token = ClientAssertionCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            func=CognitoServices.get_token,
        )
        if token:
            try:
                access_token = token.get_token(scope).token
                current_app.logger.info("[+] Successfully received token from Azure AD")
                return access_token
            except Exception as error:
                current_app.logger.error(
                    f"[-] Failed to get access token from Azure AD: {error}"
                )
                return None
        else:
            current_app.logger.error("[-] Failed to get token from Cognito")
            return None

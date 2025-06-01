import requests
from application.services.servicesaws import SSMServices
from flask import current_app
from typing import Optional
import os
import json

TENANT_ID = os.getenv("TENANT_ID")
REGION = "ap-southeast-2"


class Azure:
    @classmethod
    def az_ad_list_upload(cls, ioc: str, list_id: str, list_name: str) -> bool:
        if not all([ioc, list_id, list_name]):
            current_app.logger.error("One or more required parameters are empty.")
            return False
        endpoint = f"https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations/{list_id}"
        payload = {
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "displayName": list_name,
            "isTrusted": False,
            "ipRanges": [],
        }
        token = cls.access_token_graph_api()
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
    def generate_access_token_payload(
        cls, client_id: str, client_secret: str, scope: str
    ) -> str:
        """Generate payload for access token for client credential flow"""
        payload = (
            "client_id="
            + client_id
            + "&scope="
            + scope
            + "&client_secret="
            + client_secret
            + "&grant_type=client_credentials"
        )
        return payload

    @classmethod
    def access_token_graph_api(cls) -> Optional[str]:
        """Get OAuth access token to send data to MS Graph API"""
        ssm = SSMServices(REGION)
        current_app.logger.info("[+] Requesting API key for Graph API")
        client_id = ssm.get_param(param="graph_client_id")
        client_secret = ssm.get_param(param="graph_client_secret")
        scope = "https://graph.microsoft.com/.default"
        max_retries = 3
        retry_count = 0
        payload = cls.generate_access_token_payload(client_id, client_secret, scope)
        endpoint = (
            "https://login.microsoftonline.com/" + TENANT_ID + "/oauth2/v2.0/token"
        )
        headers = {"content-type": "application/x-www-form-urlencoded"}
        while retry_count < max_retries:
            try:
                response = requests.post(
                    url=endpoint, headers=headers, data=payload, timeout=20
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError as error:
                current_app.logger.error(
                    f"[-] Upstream returned a status code of {response.status_code}, retrying..."
                )
                current_app.logger.error(f"{error}")
                retry_count += 1
                continue
            token = response.json().get("access_token")
            if token:
                current_app.logger.info(
                    "[+] Successfully recieved token from Azure AD re DATP"
                )
                return token
            else:
                current_app.logger.error(
                    "[-] Failed to get access token from Azure AD, retrying..."
                )
                retry_count += 1
                continue
        current_app.logger.error(
            "[-] Failed to get access token from Azure AD after multiple retries"
        )
        return None

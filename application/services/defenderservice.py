import uuid
from datetime import datetime, timedelta, timezone
import requests
from typing import Optional
from application.services.servicesaws import SSMServices
from flask import current_app
import json
import os

TENANT_ID = os.getenv("TENANT_ID")
REGION = "ap-southeast-2"


def generate_short_uuid():
    return str(uuid.uuid4())[:8]

class Defender:
    @classmethod
    def upload(cls, ioc: str, type: str, action: str, incident_id: str) -> bool:
        if not all([ioc, type, action, incident_id]):
            current_app.logger.error("One or more required parameters are empty.")
            return False
        token = cls.access_token_ms_sec_api()
        if token:
            result = cls.check_indicator(ioc, token)
            if not result:
                payload = cls.construct_payload_defender(ioc, incident_id, action, type)
                result = cls.block_indicator(token, payload)
                return result
            else:
                True
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
    def access_token_ms_sec_api(cls) -> Optional[str]:
        """Get OAuth access token to send data to Microsoft Defender 365"""
        ssm = SSMServices(REGION)
        current_app.logger.info("[+] Requesting API key for DATP Check")
        client_id = ssm.get_param(param="datp_client_id")
        client_secret = ssm.get_param(param="datp_client_secret")
        security_centre_scope = "https://api.securitycenter.windows.com/.default"
        max_retries = 3
        retry_count = 0
        payload = cls.generate_access_token_payload(
            client_id, client_secret, security_centre_scope
        )
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


    @classmethod
    def check_indicator(cls, indicator: str, token: str) -> bool:
        """Check to see if indicator already exists in Defender for Endpoint"""
        endpoint = f"https://api.securitycenter.microsoft.com/api/indicators?$filter=indicatorValue+eq+'{indicator}'"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url=endpoint, headers=headers, timeout=20)
            response.raise_for_status()
            data = response.json()
            if len(data.get("value")) > 0:
                current_app.logger.info(f"[+] Indicator exists: {indicator}")
                return True
            else:
                current_app.logger.info(f"[+] Indicator does not exists: {indicator}")
                return False
        except requests.exceptions.HTTPError as error:
            current_app.logger.error(
                f"[-] Upstream returned a status code of {response.status_code}, assuming indicator is not in DATP"
            )
            current_app.logger.error(f"{error}")
            return False

    @classmethod
    def construct_payload_defender(
        cls, ioc: str, incident_id: str, action: str, ioc_type: str
    ) -> dict:
        """Create unique payload for DATP upload"""
        time_delta = (
            (datetime.now(timezone.utc) + timedelta(weeks=52))
            .isoformat("T", "seconds")
            .replace("+00:00", "Z")
        )
        identifier = generate_short_uuid()
        ti_payload = {}
        ti_payload["indicatorValue"] = ioc
        ti_payload["title"] = f"SentinelSOAR-{identifier}-{incident_id}"
        ti_payload["description"] = f"SOAR API Automated Response - {incident_id}"
        ti_payload["action"] = action
        ti_payload["severity"] = "High"
        ti_payload["indicatorType"] = ioc_type
        ti_payload["generateAlert"] = True
        ti_payload["expirationTime"] = time_delta
        return ti_payload

    @classmethod
    def block_indicator(cls, token: str, payload: dict) -> bool:
        """Block indicators MS XDR"""
        max_retries = 3
        retry_count = 0
        endpoint = "https://api.securitycenter.microsoft.com/api/indicators"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        while retry_count < max_retries:
            try:
                response = requests.post(
                    url=endpoint, headers=headers, data=json.dumps(payload), timeout=20
                )
                response.raise_for_status()
                current_app.logger.info("[+] Successfully blocked indicator in DATP")
                return True
            except requests.exceptions.HTTPError as error:
                current_app.logger.error(
                    f"[-] Upstream returned a status code of {response.status_code}, retrying..."
                )
                current_app.logger.error(f"{error}")
                retry_count += 1
                continue
        if retry_count == max_retries:
            current_app.logger.error(
                "[-] Failed to get upsteam to response, returning empty response"
            )
            return False

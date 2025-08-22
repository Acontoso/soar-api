import uuid
from datetime import datetime, timedelta, timezone
import requests
from typing import Optional
from application.services.servicesaws import CognitoServices
from azure.identity import ClientAssertionCredential
from flask import current_app
import json
import os
import re

TENANT_ID = os.getenv("TENANT_ID")
REGION = "ap-southeast-2"
WESHEALTH_SECURITY_AZ_CLIENT_ID = "3b340f00-9bad-4559-86da-df76e9c3af4b"


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
        current_app.logger.info("[+] Requesting API key for DATP Check")
        scope = "https://api.securitycenter.windows.com/.default"
        token = ClientAssertionCredential(
            tenant_id=TENANT_ID,
            client_id=WESHEALTH_SECURITY_AZ_CLIENT_ID,
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

    @classmethod
    def check_indicator(cls, indicator: str, token: str) -> bool:
        """Check to see if indicator already exists in Defender for Endpoint"""
        verify_indicator = cls.ioc_type_finder(ioc=indicator)
        if not verify_indicator:
            current_app.logger.error(
                f"[-] Invalid indicator type for, cannot check in DATP"
            )
            return False
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

    @classmethod
    def ioc_type_finder(ioc: str) -> Optional[str]:
        """Extract IOC from str"""
        indicator = str(ioc)
        if re.match(r"[A-Fa-f0-9]{64}$", indicator):
            return "FileSha256"
        if re.match(r"[A-Fa-f0-9]{32}$", indicator):
            return "FileMd5"
        if re.match(r"[A-Fa-f0-9]{40}$", indicator):
            return "FileSha1"
        # match ipv4
        if re.match(
            r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            indicator,
        ):
            return "IpAddress"
        # match domain names
        if re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", indicator):
            return "DomainName"
        return ""

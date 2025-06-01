import requests
from requests.auth import HTTPBasicAuth
from application.services.servicesaws import SSMServices
from flask import current_app
import json
import os

TENANT_ID = os.getenv("TENANT_ID")
REGION = "ap-southeast-2"
UMBRELLA_DEST_LIST_IDS = ("17699844", "17699845")


class Umbrella:
    @classmethod
    def upload(cls, ioc: str, incident_id: str) -> bool:
        access_token = cls.get_cisco_token()
        pl = []
        if access_token:
            payload = {
                "destination": ioc,
                "comment": f"SOAR API Response on Incident {incident_id}",
            }
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }
            pl.append(payload)
            for lst in UMBRELLA_DEST_LIST_IDS:
                endpoint = f"https://api.umbrella.com/policies/v2/destinationlists/{lst}/destinations"
                response = requests.post(
                    url=endpoint, data=json.dumps(pl), headers=headers
                )
                if response.status_code == 200:
                    current_app.logger.info(
                        f"[+] Successfully imported domain IOC's into Umbrella {lst} destination list"
                    )
                else:
                    current_app.logger.error(
                        f"[-] Failed imported domain IOC's into Umbrella {lst} destination list"
                    )
                    current_app.logger.error(
                        f"{response.status_code} - {response.text}"
                    )
                    return False
            return True

    @classmethod
    def get_cisco_token(self) -> str:
        """Generate JWT token via Client Credential flow"""
        try:
            client_id = SSMServices.get_param(param="umbrella_client_id")
            client_secret = SSMServices.get_param(param="umbrella_client_secret")
            header = {"Content-Type": "application/x-www-form-urlencoded"}
            token_endpoint = "https://api.umbrella.com/auth/v2/token"
            data = "grant_type=client_credentials"
            auth = HTTPBasicAuth(client_id, client_secret)
            response = requests.post(
                url=token_endpoint, data=data, headers=header, auth=auth
            )
            response.raise_for_status()
            token = response.json().get("access_token")
            current_app.logger.error("[+] Umbrella access token returned")
            return token
        except Exception as error:
            current_app.logger.error(
                "[-] Failed to return access token from Umbrella API"
            )
            return ""

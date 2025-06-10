import requests
from application.services.servicesaws import SSMServices
from typing import Optional
from flask import current_app
import json
import os
import time

TENANT_ID = os.getenv("TENANT_ID")
REGION = "ap-southeast-2"

                         
def obfuscateApiKey(api_key: str) -> Optional[list]:
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for i in range(0, len(str(n)), 1):
        key += api_key[int(str(n)[i])]
    for j in range(0, len(str(r)), 1):
        key += api_key[int(str(r)[j])+2]
    return key, now


class SSEServices:
    @classmethod
    def sandbox_file(cls, file: bytes, api_key: str) -> Optional[dict]:
        """Submit file to SSE Sandbox"""
        api_url = f"https://api.sse.net/zscsb/submit?apiKey={api_key}"
        try:
            current_app.logger.info("[+] Submitting file to SSE Sandbox")
            headers = {"Content-Type": "application/octet-stream"}
            response = requests.post(
                url=api_url, data=file, headers=headers, timeout=10
            )
            response.raise_for_status()
            current_app.logger.info("[+] File submitted successfully to SSE Sandbox")
            return response.json()
        except requests.RequestException as error:
            current_app.logger.error(
                f"[-] Failed to submit file to SSE Sandbox: {error}"
            )
            return None
        
    @classmethod
    def lookup_url_category(cls, ioc: str) -> Optional[dict]:
        """Submit file to SSE Sandbox"""
        payload = {
            "urls": [ioc]
        }
        cookies = {'JSESSIONID': cls.get_jsession()}
        api_url = "https://api.sse.net/api/v1/urlLookup"
        try:
            current_app.logger.info("[+] Submitting URL to SSE for category lookup")
            headers = {"Content-Type": "application/json"}
            response = requests.post(
                url=api_url, data=json.dumps(payload), headers=headers, cookies=cookies, timeout=10
            )
            response.raise_for_status()
            current_app.logger.info("[+] URL category lookup successful")
            return response.json()
        except requests.RequestException as error:
            current_app.logger.error(
                f"[-] Failed to submit URL to SSE for category lookup: {error}"
            )
            return None

    @classmethod
    def get_jsession(self) -> str:
        """Generate Jsession ID"""
        try:
            api_key = SSMServices.get_param(param="new_sse_api_key")
            username = SSMServices.get_param(param="new_sse_username")
            password = SSMServices.get_param(param="new_sse_password")
            header = {"Content-Type": "application/json"}
            obfuscated_key, now = obfuscateApiKey(api_key)
            token_endpoint = "https://api.sse.net/api/v1/authenticatedSession"
            data = {
                "apiKey": obfuscated_key,
                "username": username,
                "password": password,
                "timestamp": now,
            }
            response = requests.post(
                url=token_endpoint, data=data, headers=header, timeout=10
            )
            response.raise_for_status()
            jsession_id = response.headers.get("JSESSIONID")
            current_app.logger.error("[+] SSE jsession ID token returned")
            return jsession_id
        except Exception as error:
            current_app.logger.error(
                f"[-] Failed to return access token from SSE API: {error}"
            )
            return ""

    @classmethod
    def sandbox_api_key(self) -> Optional[str]:
        """Pull Sandbox API Key from SSM Parameter Store"""
        api_key = SSMServices.get_param(param="new_sse_sandbox_api_key")
        return api_key if api_key else ""

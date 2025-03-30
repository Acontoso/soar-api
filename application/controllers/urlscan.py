import os
from services.servicesaws import SSMServices, DynamoDBService
from flask import current_app
from datetime import datetime
import ioc_fanger
import requests
import json
import time

REGION = "ap-southeast-2"
ACTION_TABLE = os.getenv("ACTION_TABLE")
ACTION_PARTITION_KEY = os.getenv("ACTION_PARTITION_KEY")
ACTION_SORT_KEY = os.getenv("ACTION_SORT_KEY")

class URLScan:
    @classmethod
    def scan(cls, ioc: str, incident_id: str) -> dict:
        db_lookup = cls.lookup_record_to_db(str(ioc), "URLScan")
        if db_lookup:
            current_app.logger.info(f"[+] Record for IOC (link) action found {ioc_fanger.defang(ioc)}, returning")
            link = db_lookup.get("Link")
            data = {"Scan": True, "IOC": ioc_fanger.defang(ioc), "Link": link}
            return data
        else:
            scan_result, link = cls.scan_link(ioc)
            data = {
                "Scan": scan_result,
                "IOC": ioc_fanger.defang(ioc),
                "Link": link
            }
        if scan_result:
            cls.add_record_to_db(ioc_fanger.defang(ioc), link, incident_id)
        return data

    @classmethod
    def add_record_to_db(cls, ioc: str, link: str, incident_id: str) -> None:
        dynamo = DynamoDBService(REGION)
        current_date = datetime.now().strftime("%d-%m-%Y")
        current_app.logger.info(f"[+] Attempting to write to DB, IOC: {ioc}")
        item = {
            "IOC": {"S": ioc},
            "Integration": {"S": "URLScan"},
            "IOCType": {"S": "URL"},
            "Action": {"S": "Scan"},
            "IncidentId": {"S": incident_id},
            "Date": {"S": current_date},
            "Link": {"S": link},
        }
        dynamo.put_item(ACTION_TABLE, item)

    @classmethod
    def lookup_record_to_db(cls, hash_key_value: str, sort_key_value: str) -> dict:
        dynamo = DynamoDBService(REGION)
        current_app.logger.info(
            f"[+] Looking to see if record exists for table {ACTION_TABLE} where IOC primary key {hash_key_value}"
        )
        return dynamo.get_item(
            ACTION_TABLE,
            ACTION_PARTITION_KEY,
            hash_key_value,
            ACTION_SORT_KEY,
            sort_key_value,
        )
    
    @staticmethod
    def get_ssm_api_key() -> str:
        ssm = SSMServices(REGION)
        current_app.logger.info("[+] Requesting API key for URLScan")
        url_scan_api_key = ssm.get_param(param="urlscan")
        if url_scan_api_key:
            return url_scan_api_key
        return None

    @classmethod
    def scan_link(cls, ioc: str) -> tuple:
        max_retries = 3
        retry_count = 0
        endpoint = "https://urlscan.io/api/v1/scan/"
        payload_data = {"url": ioc, "visibility": "public", "country": "au"}
        key = cls.get_ssm_api_key()
        header = {"Content-Type": "application/json", "API-Key": key}
        if key:
            while retry_count < max_retries:
                try:
                    response = requests.post(url=endpoint, headers=header, data=json.dumps(payload_data), timeout=20)
                    response.raise_for_status()
                    break
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
                return False, ""
            data_init = response.json()
            current_app.logger.info(
                "[+] Scan has been initiating, await for return......"
            )
            api_endpoint = data_init.get("api")
            finished = False
            try:
                while not finished:
                    poll_response = requests.get(url=api_endpoint, timeout=20)
                    if poll_response.status_code == 200:
                        finished = True
                    current_app.logger.info("[+] Polling......")
                    time.sleep(5)
                data = poll_response.json()
                task = data.get("task").get("reportURL")
                return True, task
            except Exception as error:
                current_app.logger.error(
                    f"[-] Failed to get URLScan link, returning False & None"
                )
                return False, ""
        else:
            current_app.logger.error(
                f"[-] Failed to get URLScan API Key, returning False & None"
            )
            return False, ""

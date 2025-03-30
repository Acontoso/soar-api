import os
from services.servicesaws import SSMServices, DynamoDBService
from services.azuread import Azure
from flask import current_app
from datetime import datetime
import ipaddress

REGION = "ap-southeast-2"
ACTION_TABLE = os.getenv("ACTION_TABLE")
ACTION_PARTITION_KEY = os.getenv("ACTION_PARTITION_KEY")
ACTION_SORT_KEY = os.getenv("ACTION_SORT_KEY")

class AzureAD:
    @classmethod
    def ip_upload(cls, ioc: str, list_id: str, list_name: str, incident_id: str) -> dict:
        ip_result = cls.is_cidr(ioc)
        if ip_result is None:
            current_app.logger.error(f"[-] Invalid IP address {ioc}")
            return {"Action": False, "IOC": ioc, "ListName": list_name}
        else:
            if ip_result is False:
                ioc = f"{ioc}/32"
        db_lookup = cls.lookup_record_to_db(str(ioc), "AzureAD")
        if db_lookup:
            current_app.logger.info(f"[+] Record for IOC action found {ioc}, returning")
            list_name = db_lookup.get("ListName")
            data = {"Action": True, "IOC": ioc, "ListName": list_name}
            return data
        else:
            result = cls.add_to_list(ioc, list_id, list_name)
            if result:
                cls.add_record_to_db(ioc, list_id, list_name, incident_id)
                data = {
                    "Action": True,
                    "IOC": ioc,
                    "ListName": list_name
                }
            else:
                data = {
                    "Action": False,
                    "IOC": ioc,
                    "ListName": list_name
                }
        return data

    @classmethod
    def add_record_to_db(cls, ioc: str, list_id: str, list_name: str, incident_id: str) -> None:
        dynamo = DynamoDBService(REGION)
        current_date = datetime.now().strftime("%d-%m-%Y")
        current_app.logger.info(f"[+] Attempting to write to DB, IOC: {ioc}")
        item = {
            "IOC": {"S": ioc},
            "Integration": {"S": "AzureAD"},
            "IOCType": {"S": "IPv4"},
            "Action": {"S": "AzureADBlock"},
            "IncidentId": {"S": incident_id},
            "Date": {"S": current_date},
            "ListName": {"S": list_name},
            "ListID": {"S": list_id}
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
    def add_to_list(cls, ioc: str, list_id: str, list_name: str) -> bool:
        return Azure.az_ad_list_upload(ioc, list_id, list_name)
 
    @staticmethod
    def is_cidr(ip_str):
        try:
            if '/' in ip_str:
                ipaddress.ip_network(ip_str, strict=False)
                return True
            else:
                ipaddress.ip_address(ip_str)
                return False
        except ValueError:
            return None 

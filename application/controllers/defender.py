import os
from typing import Optional
from application.services.servicesaws import DynamoDBService
from application.services.defenderservice import Defender
from application.services.ioccheck import ioc_type_finder, tenant_friendly_name
from flask import current_app
from datetime import datetime
import re

REGION = "ap-southeast-2"
ACTION_TABLE = os.getenv("ACTION_TABLE")
ACTION_PARTITION_KEY = os.getenv("ACTION_PARTITION_KEY")
ACTION_SORT_KEY = os.getenv("ACTION_SORT_KEY")


class DATP:
    @classmethod
    def ioc_upload(
        cls, ioc: str, action: str, incident_id: str, tenant_id: str
    ) -> dict:
        db_lookup = cls.lookup_record_to_db(str(ioc), "DATPIndicator")
        if db_lookup:
            current_app.logger.info(f"[+] Record for IOC action found {ioc}, returning")
            platform = db_lookup.get("Platform")
            action = db_lookup.get("Action")
            data = {"Added": True, "IOC": ioc, "Platform": platform, "Action": action}
            return data
        else:
            ioc_type = ioc_type_finder(ioc)
            defender_ioc_type = DATP.convert_ioc_type(ioc_type)
            if defender_ioc_type in ("IpAddress", "DomainName"):
                data = {
                    "Added": False,
                    "IOC": ioc,
                    "Platform": "DATP",
                    "Action": "None",
                }
                return data
            else:
                result = Defender.upload(ioc, defender_ioc_type, action, incident_id)
                cls.add_record_to_db(ioc, ioc_type, action, incident_id, tenant_id)
                if result:
                    data = {
                        "Added": True,
                        "IOC": ioc,
                        "Platform": "DATP",
                        "Action": action,
                    }
                else:
                    data = {
                        "Added": False,
                        "IOC": ioc,
                        "Platform": "DATP",
                        "Action": "None",
                    }
                return data

    @staticmethod
    def convert_ioc_type(type: str) -> Optional[str]:
        """Extract IOC from str"""
        match type:
            case "SHA256":
                return "FileSha256"
            case "MD5":
                return "FileMd5"
            case "SHA1":
                return "FileSha1"
            case "IPv4":
                return "IpAddress"
            case "Domain":
                return "DomainName"
            case _:
                return None

    @classmethod
    def add_record_to_db(
        cls, ioc: str, ioc_type: str, action: str, incident_id: str, tenant_id: str
    ) -> None:
        dynamo = DynamoDBService(REGION)
        current_date = datetime.now().strftime("%d-%m-%Y")
        current_app.logger.info(f"[+] Attempting to write to DB, IOC: {ioc}")
        item = {
            "IOC": {"S": ioc},
            "Integration": {"S": "DATP"},
            "IOCType": {"S": ioc_type},
            "Action": {"S": action},
            "IncidentId": {"S": incident_id},
            "Date": {"S": current_date},
            "TenantId": {"S": tenant_id},
            "TenantFriendlyName": {"S": tenant_friendly_name(tenant_id)},
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

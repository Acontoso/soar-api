import os
from services.servicesaws import DynamoDBService
from services.defenderservice import Defender
from flask import current_app
from datetime import datetime
import re

REGION = "ap-southeast-2"
ACTION_TABLE = os.getenv("ACTION_TABLE")
ACTION_PARTITION_KEY = os.getenv("ACTION_PARTITION_KEY")
ACTION_SORT_KEY = os.getenv("ACTION_SORT_KEY")

class DATP:
    @classmethod
    def ioc_upload(cls, ioc: str, action: str, incident_id: str) -> dict:
        db_lookup = cls.lookup_record_to_db(str(ioc), "DATPIndicator")
        if db_lookup:
            current_app.logger.info(f"[+] Record for IOC action found {ioc}, returning")
            platform = db_lookup.get("Platform")
            action = db_lookup.get("Action")
            data = {"Added": True, "IOC": ioc, "Platform": platform, "Action": action}
            return data
        else:
            ioc_type = cls.ioc_type_finder(ioc)
            if ioc_type in ("IpAddress", "DomainName"):
                data = {
                    "Added": False,
                    "IOC": ioc,
                    "Platform": "DATP",
                    "Action": "None",
                }
                return data
            else:
                result = Defender.upload(ioc, ioc_type, action, incident_id)
                cls.add_record_to_db(ioc, ioc_type, action, incident_id)
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
    def ioc_type_finder(ioc: str) -> str:
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
        return "DomainName"

    @classmethod
    def add_record_to_db(cls, ioc: str, ioc_type: str, action: str, incident_id: str) -> None:
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

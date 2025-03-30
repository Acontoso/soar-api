import os
import requests
from services.servicesaws import DynamoDBService
from services.umbrella import Umbrella
from flask import current_app
from datetime import datetime
import re
import ipaddress

REGION = "ap-southeast-2"
ACTION_TABLE = os.getenv("ACTION_TABLE")
ACTION_PARTITION_KEY = os.getenv("ACTION_PARTITION_KEY")
ACTION_SORT_KEY = os.getenv("ACTION_SORT_KEY")

class SASE:
    @classmethod
    def block(cls, ioc: str, incident_id: str) -> dict:
        db_lookup = cls.lookup_record_to_db(str(ioc), "SASE")
        if db_lookup:
            current_app.logger.info(f"[+] Record for IOC found {ioc}, returning")
            platform = db_lookup.get("Platform")
            action = db_lookup.get("Action")
            data = {"Added": True, "IOC": ioc, "Platform": platform, "Action": action}
            return data
        else:
            ioc_type = cls.ioc_type_finder(ioc)
            if ioc_type == "IPv4":
                ip_obj = ipaddress.ip_address(ioc)
                if ip_obj.is_private:
                    return {"Added": False, "IOC": ioc, "Platform": "SASE", "Action": "Block"}
            operation = Umbrella.upload(ioc, incident_id)
            if operation:
                cls.add_record_to_db(ioc, ioc_type)
                return {"Added": True, "IOC": ioc, "Platform": "SASE", "Action": "Block"}
            else:
                return {"Added": False, "IOC": ioc, "Platform": "SASE", "Action": "Block"}

    @staticmethod
    def ioc_type_finder(ioc: str) -> str:
        """Extract IOC from str"""
        indicator = str(ioc)
        if re.match(r"[A-Fa-f0-9]{64}$", indicator):
            return "SHA256"
        if re.match(r"[A-Fa-f0-9]{32}$", indicator):
            return "MD5"
        if re.match(r"[A-Fa-f0-9]{40}$", indicator):
            return "SHA1"
        # match ipv4
        if re.match(
            r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            indicator,
        ):
            return "IPv4"
        # match domain names
        if re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", indicator):
            return "Domain"
        return "Domain"

    @classmethod
    def add_record_to_db(cls, ioc: str, ioc_type: str, incident_id: str) -> None:
        dynamo = DynamoDBService(REGION)
        current_date = datetime.now().strftime("%d-%m-%Y")
        current_app.logger.info(f"[+] Attempting to write to DB, IOC: {ioc}")
        item = {
            "IOC": {"S": ioc},
            "Integration": {"S": "SASE"},
            "IOCType": {"S": ioc_type},
            "Action": {"S": "Block"},
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
            ACTION_TABLE, ACTION_PARTITION_KEY, hash_key_value, ACTION_SORT_KEY, sort_key_value
        )

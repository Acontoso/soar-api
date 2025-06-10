import os
from application.services.servicesaws import DynamoDBService
from application.services.umbrella import Umbrella
from application.services.newsse import SSEServices
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
            return {
                "Added": True,
                "IOC": ioc,
                "Integration": db_lookup.get("Integration"),
                "Action": db_lookup.get("Action"),
            }
        ioc_type = cls.ioc_type_finder(ioc)
        if ioc_type == "IPv4" and ipaddress.ip_address(ioc).is_private:
            return {"Added": False, "IOC": ioc, "Integration": "SASE", "Action": "Block"}
        operation = Umbrella.upload(ioc, incident_id)
        if operation:
            cls.add_record_to_db_action(ioc, ioc_type, incident_id)
            return {"Added": True, "IOC": ioc, "Integration": "SASE", "Action": "Block"}
        return {"Added": False, "IOC": ioc, "Integration": "SASE", "Action": "Block"}

    @classmethod
    def submit_file(cls, file: bytes) -> dict:
        sandbox_api_key = SSEServices.sandbox_api_key()
        if not sandbox_api_key:
            current_app.logger.error("[-] Failed to get JSESSIONID for SSE")
            return {"Sandbox": False, "Message": "Failed to get JSESSIONID"}
        response = SSEServices.sandbox_file(file, sandbox_api_key)
        if response:
            current_app.logger.info(f"[+] File submitted to SSE for analysis")
            return {
                "MD5": response.get("md5"),
                "Status": response.get("sandboxSubmission"),
                "VirusName": response.get("virusName"),
                "VirusType": response.get("virusType"),
                "Sandbox": True,
                "StatusCode": response.get("code"),
            }
        current_app.logger.error("[-] Failed to submit file to SSE")
        return {"Sandbox": False, "Message": "Failed to submit file"}

    @classmethod
    def url_category_lookup(cls, ioc: str) -> dict:
        db_lookup = cls.lookup_record_to_db(str(ioc), "SASE")
        if db_lookup:
            return cls._handle_db_lookup(db_lookup, ioc)
        return cls._fresh_url_category_lookup(ioc)

    @classmethod
    def _handle_db_lookup(cls, db_lookup, ioc):
        current_app.logger.info(f"[+] Record for IOC found {ioc}, returning")
        date_added_str = db_lookup.get("Date")
        try:
            date_added = datetime.strptime(date_added_str, "%d-%m-%Y")
            if (datetime.now() - date_added).days > 365:
                current_app.logger.info(
                    "[+] Record is older than 1 year, doing fresh lookup"
                )
                data = cls._fresh_url_category_lookup(ioc)
                if data:
                    ioc_type = cls.ioc_type_finder(ioc)
                    categories = data.get("Categories", [])
                    cls.add_record_to_db_enrich(ioc, ioc_type, "SASE", "Lookup", categories)
                    response_data = {
                        "IOC": ioc,
                        "Categories": categories,
                        "Action": "Lookup",
                        "Integration": "SASE"
                    }
            current_app.logger.info(
                f"[+] Record is less than a year old, returning DB record for ioc {ioc}"
            )
            return {
                "IOC": ioc,
                "Categories": db_lookup.get("Categories", []),
                "Action": "Lookup",
                "Integration": "SASE"
            }
        except Exception as error:
            current_app.logger.error(
                f"[-] Failed to do time comparison, returning DB found data"
            )
            data = cls._fresh_url_category_lookup(ioc)
            if data:
                ioc_type = cls.ioc_type_finder(ioc)
                categories = data.get("Categories", [])
                cls.add_record_to_db_enrich(ioc, ioc_type, "SASE", "Lookup", categories)
                response_data = {
                    "IOC": ioc,
                    "Categories": categories,
                    "Action": "Lookup",
                    "Integration": "SASE"
                }
                return response_data

    @classmethod
    def _fresh_url_category_lookup(cls, ioc):
        data = SSEServices.lookup_url_category(ioc)
        if data:
            ioc_type = cls.ioc_type_finder(ioc)
            categories = data.get("Categories", [])
            cls.add_record_to_db_enrich(ioc, ioc_type, "SASE", "Lookup", categories)
            response_data = {
                "IOC": ioc,
                "Categories": categories,
                "Action": "Lookup",
                "Integration": "SASE"
            }
        else:
            current_app.logger.error(f"[-] Failed to lookup URL category for {ioc}")
        return response_data

    @staticmethod
    def ioc_type_finder(ioc: str) -> str:
        indicator = str(ioc)
        if re.match(r"[A-Fa-f0-9]{64}$", indicator):
            return "SHA256"
        if re.match(r"[A-Fa-f0-9]{32}$", indicator):
            return "MD5"
        if re.match(r"[A-Fa-f0-9]{40}$", indicator):
            return "SHA1"
        if re.match(
            r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            indicator,
        ):
            return "IPv4"
        if re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", indicator):
            return "Domain"
        return "Domain"

    @classmethod
    def add_record_to_db_enrich(
        cls, ioc: str, ioc_type: str, categories: list = None
    ) -> None:
        dynamo = DynamoDBService(REGION)
        current_date = datetime.now().strftime("%d-%m-%Y")
        current_app.logger.info(f"[+] Attempting to write to DB, IOC: {ioc}")
        item = {
            "IOC": {"S": ioc},
            "Integration": {"S": "SASE"},
            "IOCType": {"S": ioc_type},
            "Action": {"S": "Lookup"},
            "Date": {"S": current_date},
            "Categories": {"L": categories if categories else []},
        }
        dynamo.put_item(ACTION_TABLE, item)

    @classmethod
    def add_record_to_db_action(
        cls, ioc: str, ioc_type: str, incident_id: str) -> None:
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

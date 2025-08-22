import os
from application.services.servicesaws import DynamoDBService
from application.services.ioccheck import ioc_type_finder, tenant_friendly_name
from flask import current_app
from datetime import datetime
import ipaddress

REGION = "ap-southeast-2"
ACTION_TABLE = os.getenv("ACTION_TABLE")
ACTION_PARTITION_KEY = os.getenv("ACTION_PARTITION_KEY")
ACTION_SORT_KEY = os.getenv("ACTION_SORT_KEY")


class Manual:
    @classmethod
    def write_db(
        cls, ioc: str, integration: str, action: str, incident_id: str, tenant_id: str
    ) -> dict:
        db_lookup = cls.lookup_record_to_db(str(ioc), integration)
        if db_lookup:
            current_app.logger.info(
                f"[+] IOC SOAR action already done for ioc {ioc}, returning"
            )
            return {"Added": True}
        ioc_type = ioc_type_finder(ioc)
        if ioc_type == "IPv4" and ipaddress.ip_address(ioc).is_private:
            current_app.logger.info(
                f"[-] Private IP address {ioc} cannot be added actioned"
            )
            return {"Added": False}
        cls.add_record_to_db_action(
            ioc, integration, ioc_type, action, incident_id, tenant_id
        )
        return {"Added": True}

    @classmethod
    def add_record_to_db_action(
        cls,
        ioc: str,
        integration: str,
        ioc_type: str,
        action: str,
        incident_id: str,
        tenant_id: str,
    ) -> None:
        dynamo = DynamoDBService(REGION)
        current_date = datetime.now().strftime("%d-%m-%Y")
        current_app.logger.info(f"[+] Attempting to write to DB, IOC: {ioc}")
        item = {
            "IOC": {"S": ioc},
            "Integration": {"S": integration},
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

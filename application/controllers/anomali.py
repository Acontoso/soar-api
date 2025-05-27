import os
import requests
from application.services.servicesaws import SSMServices, DynamoDBService
from flask import current_app
from datetime import datetime
import re
import ipaddress

REGION = "ap-southeast-2"
TABLE = os.getenv("TABLE")
PARTITION_KEY = os.getenv("PARTITION_KEY")
SORT_KEY = os.getenv("SORT_KEY")

class Anomali:
    @classmethod
    def ioc_lookup(cls, ioc: str) -> dict:
        db_lookup = cls.lookup_record_to_db(str(ioc), "Anomali")
        if db_lookup:
            current_app.logger.info(f"[+] Record for IOC found {ioc}, returning")
            date_added_str = db_lookup.get("Date")
            try:
                date_added = datetime.strptime(date_added_str, "%d-%m-%Y")
                current_date = datetime.now()
                difference = current_date - date_added
                if difference.days > 365:
                    current_app.logger.info(
                        f"[+] Record returned from DB is greater than 1 year old, doing fresh lookup"
                    )
                    data = cls.anomali_api_call(ioc)
                    return data
                else:
                    current_app.logger.info(
                        f"[+] Record returned from DB is less than a year old, returning DB record for ioc {ioc}"
                    )
                    grade_confidence = cls.grade_confidence(db_lookup.get("Confidence"))
                    db_lookup["Grade"] = grade_confidence
                    db_lookup.pop("Date")
                    return db_lookup
            except Exception as error:
                current_app.logger.error(
                    f"[-] Failed to do time comparison, returning DB found data"
                )
                data = cls.anomali_api_call(ioc)
                return data
        else:
            data = cls.anomali_api_call(ioc)
            return data

    @staticmethod
    def generate_headers() -> dict:
        ssm = SSMServices(REGION)
        current_app.logger.info("[+] Requesting API key for Anoamli ThreatStream")
        anomali_user = ssm.get_param(param="anomali_user")
        anomali_key = ssm.get_param(param="anomali_api")
        if anomali_key and anomali_user:
            return {
                "Authorization": f"apikey {anomali_user}:{anomali_key}",
            }
        else:
            return {}

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
    def add_record_to_db(cls, confidence: int, ioc_type: str, ioc: str) -> None:
        dynamo = DynamoDBService(REGION)
        current_date = datetime.now().strftime("%d-%m-%Y")
        current_app.logger.info(f"[+] Attempting to write to DB, IOC: {ioc}")
        item = {
            "IOC": {"S": ioc},
            "Source": {"S": "Anomali"},
            "Confidence": {"N": str(confidence)},
            "IOCType": {"S": ioc_type},
            "Date": {"S": current_date},
        }
        dynamo.put_item(TABLE, item=item)

    @staticmethod
    def grade_confidence(confidence: int) -> str:
        """Grade the confidence score on a Low, Medium & High scale"""
        match confidence:
            case _ if confidence < 30:
                return "Low"
            case _ if 30 <= confidence < 70:
                return "Medium"
            case _ if confidence >= 70:
                return "High"

    @classmethod
    def lookup_record_to_db(cls, hash_key_value: str, sort_key_value: str) -> dict:
        dynamo = DynamoDBService(REGION)
        current_app.logger.info(
            f"[+] Looking to see if record exists for table {TABLE} where IOC primary key {hash_key_value}"
        )
        return dynamo.get_item(
            TABLE, PARTITION_KEY, hash_key_value, SORT_KEY, sort_key_value
        )

    @classmethod
    def anomali_api_call(cls, ioc: str) -> dict:
        max_retries = 3
        retry_count = 0
        endpoint = f"https://api.threatstream.com/api/v1/inteldetails/confidence_trend/?type=confidence&value={ioc}"
        ioc_type = Anomali.ioc_type_finder(ioc)
        if ioc_type == "IPv4":
            if Anomali.is_private_ip(ioc):
                return {"confidence": 0, "ioc_type": ioc_type, "ioc": ioc}
        current_app.logger.info(f"[+] IOC type for {ioc} is {ioc_type}")
        header = Anomali.generate_headers()
        if header:
            while retry_count < max_retries:
                try:
                    response = requests.get(url=endpoint, headers=header, timeout=20)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as error:
                    current_app.logger.error(
                        f"[-] Upstream returned a status code of {response.status_code}, retrying..."
                    )
                    current_app.logger.error(f"{error}")
                    retry_count += 1
                    continue
                average_confidence = response.json().get("average_confidence")
                grade_confidence = cls.grade_confidence(average_confidence)
                cls.add_record_to_db(average_confidence, ioc_type, ioc)
                return {
                    "Confidence": average_confidence,
                    "IOCType": ioc_type,
                    "IOC": ioc,
                    "Grade": grade_confidence
                }
            if retry_count == max_retries:
                current_app.logger.error(
                    "[-] Failed to get upsteam to response, returning empty response"
                )
                return {}

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private

    @staticmethod
    def grade_confidence(confidence: int) -> str:
        """Grade the confidence score on a Low, Medium & High scale"""
        match confidence:
            case _ if confidence < 30:
                return "Low"
            case _ if 30 <= confidence < 70:
                return "Medium"
            case _ if confidence >= 70:
                return "High"

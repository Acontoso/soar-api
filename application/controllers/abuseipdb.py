import os
import requests
from application.services.servicesaws import SSMServices, DynamoDBService
from flask import current_app
from datetime import datetime
import ipaddress

ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
REGION = "ap-southeast-2"
TABLE = os.getenv("TABLE")
PARTITION_KEY = os.getenv("PARTITION_KEY")
SORT_KEY = os.getenv("SORT_KEY")


class IPAbuseDB:
    @classmethod
    def ip_lookup(cls, ip: str) -> dict:
        db_lookup = cls.lookup_record_to_db(str(ip), "IPAbuseDB")
        if db_lookup:
            current_app.logger.info(f"[+] Record for IOC found {ip}, returning")
            date_added_str = db_lookup.get("Date")
            try:
                date_added = datetime.strptime(date_added_str, "%d-%m-%Y")
                current_date = datetime.now()
                difference = current_date - date_added
                if difference.days > 365:
                    if IPAbuseDB.is_private_ip(ip):
                        return {
                            "Confidence": 0,
                            "Country": "Unknown",
                            "ReportCount": 0,
                            "Tor": False,
                            "Ioc": ip,
                            "Private": True,
                        }
                    else:
                        current_app.logger.info(
                            f"[+] Record returned from DB is greater than 1 year old, doing fresh lookup"
                        )
                        data = cls.ipabuse_api_call(ip)
                        return data
                else:
                    current_app.logger.info(
                        f"[+] Record returned from DB is less than a year old, returning DB record for ioc {ip}"
                    )
                    db_lookup.pop("Date")
                    return db_lookup
            except Exception as error:
                current_app.logger.error(
                    f"[-] Failed to do time comparison, returning DB found data"
                )
                data = cls.ipabuse_api_call(ip)
                return data
        else:
            data = cls.ipabuse_api_call(ip)
            return data

    @staticmethod
    def generate_headers() -> dict:
        ssm = SSMServices(REGION)
        current_app.logger.info("[+] Requesting API key for AbuseIPDB")
        data = ssm.get_param(param="ipabuse_db")
        if data:
            return {"Accept": "application/json", "Key": data}
        else:
            return {}

    @classmethod
    def add_record_to_db(
        cls, confidence: int, country: str, report_count: int, tor: bool, ioc: str
    ) -> None:
        dynamo = DynamoDBService(REGION)
        current_date = datetime.now().strftime("%d-%m-%Y")
        current_app.logger.info(f"[+] Attempting to write to DB, IOC: {ioc}")
        item = {
            "IOC": {"S": ioc},
            "Source": {"S": "IPAbuseDB"},
            "Confidence": {"N": str(confidence)},
            "Country": {"S": country},
            "ReportCount": {"N": str(report_count)},
            "Tor": {"BOOL": tor},
            "Date": {"S": current_date},
        }
        dynamo.put_item(TABLE, item=item)

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
    def ipabuse_api_call(cls, ioc: str) -> dict:
        max_retries = 3
        retry_count = 0
        header = IPAbuseDB.generate_headers()
        if header:
            params = {"ipAddress": ioc}
            while retry_count < max_retries:
                try:
                    response = requests.get(url=ENDPOINT, headers=header, params=params)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as error:
                    current_app.logger.error(
                        f"[-] Upstream returned a status code of {response.status_code}, retrying..."
                    )
                    current_app.logger.error(f"{error}")
                    retry_count += 1
                    continue
                data = response.json()
                payload = data.get("data")
                # need a better way to unpack
                confidence = int(payload.get("abuseConfidenceScore"))
                country = payload.get("countryName", "Unknown")
                report_count = int(payload.get("totalReports"))
                tor = payload.get("isTor")
                cls.add_record_to_db(confidence, country, report_count, tor, ioc)
                return {
                    "Confidence": confidence,
                    "Country": country,
                    "ReportCount": report_count,
                    "Tor": tor,
                    "IOC": ioc,
                    "Private": False,
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

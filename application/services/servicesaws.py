import boto3
import base64
from typing import Optional
from flask import current_app
from boto3.dynamodb.types import TypeDeserializer


# boto3.setup_default_session(profile_name='sec-log')
class CustomTypeDeserializer(TypeDeserializer):
    def deserialize(self, value):
        # If it's a number, convert it to an integer or float - similar to .Net virtual methods that is overidden by derived class
        if "N" in value:
            num_value = value["N"]
            return int(num_value) if num_value.isdigit() else float(num_value)
        # Call the original instance method
        return super().deserialize(value)


class DynamoDBService:
    def __init__(self, region: str):
        self.dynamodb_client = boto3.client("dynamodb", region_name=region)

    def get_item(
        self,
        table: str,
        hash_key: str,
        hash_key_value: str,
        sort_key: str,
        sort_key_value: str,
    ) -> Optional[dict]:
        """Get item from DynamoDB table"""
        if not all([table, table, hash_key, hash_key_value, sort_key, sort_key_value]):
            current_app.logger.error(
                "One or more required parameters are empty when calling put_item."
            )
            return None
        response = self.dynamodb_client.get_item(
            TableName=table,
            Key={hash_key: {"S": hash_key_value}, sort_key: {"S": sort_key_value}},
        )
        if "Item" in response:
            deserializer = CustomTypeDeserializer()
            parsed_item = {
                key: deserializer.deserialize(value)
                for key, value in response["Item"].items()
            }
            return parsed_item
        else:
            return {}

    def put_item(self, table: str, item: dict) -> Optional[bool]:
        """Put item into DynamoDB table"""
        try:
            if not all([table, item]):
                current_app.logger.error(
                    "One or more required parameters are empty when calling put_item."
                )
                return
            self.dynamodb_client.put_item(TableName=table, Item=item)
            current_app.logger.info(f"[+] Successful Database write on {table}")
            return True
        except Exception as error:
            current_app.logger.error("[-] Failed to add record in database, no stress")
            current_app.logger.error(f"{error}")
            return False


class SSMServices:
    def __init__(self, region: str):
        self.client = boto3.client("ssm", region_name=region)
        self.kms = KMSServices(region)

    def get_param(self, param: str) -> str:
        try:
            data = (
                self.client.get_parameter(
                    Name=f"/soar-api/{param}", WithDecryption=True
                )
                .get("Parameter")
                .get("Value")
            )
            raw_bytes = base64.b64decode(data)
            return_data = self.kms.client.decrypt(CiphertextBlob=raw_bytes)
            unencrypted_string = return_data.get("Plaintext").decode("utf-8")
            current_app.logger.info(
                "[+] Successfully retrieved the requested SSM parameter"
            )
        except Exception as error:
            current_app.logger.error(
                "[-] Failed to retrieve the parameter from SSM, returning null"
            )
            current_app.logger.error(error)
            return None
        return unencrypted_string


class KMSServices:
    def __init__(self, region: str):
        self.client = boto3.client("kms", region_name=region)

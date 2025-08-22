# routes.py
from flask import Flask, jsonify, request, g
from application.controllers.abuseipdb import IPAbuseDB
from application.controllers.anomali import Anomali
from application.controllers.defender import DATP
from application.controllers.azad import AzureAD
from application.controllers.sase import SASE
from application.middleware.authen import verify_scopes
from application.controllers.manual import Manual

DATP_VALID_ACTIONS = [
    "Block",
    "Audit",
    "BlockAndRemediate",
]


def init_routes(app: Flask):
    @app.route("/health")
    def home():
        return jsonify({"message": "API is healthy!"})

    @app.errorhandler(500)
    def internal_error(error):
        return {"error": "Internal Server Error", "message": str(error)}, 500

    @app.errorhandler(404)
    def not_found_error(error):
        return {
            "error": "Not Found",
            "message": "The requested resource was not found.",
        }, 404

    @app.route("/ipabusedb", methods=["GET"])
    def ipabuse_path():
        required_scopes = ["soar-api/admin.readwrite.all"]
        if verify_scopes(g.token, required_scopes):
            if len(request.args) == 0:
                response = jsonify(
                    {"error": "Missing ip uri param, please pass a IP address"}
                )
                response.status_code = 400
                return response
            elif len(request.args) == 1:
                param = request.args.to_dict()
                ip = param.get("ip", None)
                if ip:
                    data = IPAbuseDB.ip_lookup(ip=ip)
                    if data:
                        return jsonify(data)
                    else:
                        response = jsonify(
                            {"error": "Upstream API issue, returning 500 error"}
                        )
                        response.status_code = 500
                        return response
                else:
                    response = jsonify(
                        {"error": "Missing ip uri param, please pass a IP address"}
                    )
                    response.status_code = 400
                    return response
            else:
                response = jsonify(
                    {
                        "error": "More than one argument sent, please only send the ip param"
                    }
                )
                response.status_code = 400
                return response
        else:
            response = jsonify(
                {"error": "Missing required scopes in access token in API call"}
            )
            response.status_code = 401
            return response

    @app.route("/anomali", methods=["GET"])
    def anomali_path():
        required_scopes = ["soar-api/admin.readwrite.all"]
        if verify_scopes(g.token, required_scopes):
            # Accepting only single IOC here per API call
            if len(request.args) == 1:
                param = request.args.to_dict()
                ioc = param.get("ioc", None)
                if ioc:
                    data = Anomali.ioc_lookup(ioc=ioc)
                    if data:
                        return jsonify(data)
                    else:
                        response = jsonify(
                            {"error": "Upstream API issue, returning 500 error"}
                        )
                        response.status_code = 500
                        return response
                else:
                    response = jsonify(
                        {"error": "Missing ip uri param, please pass a IP address"}
                    )
                    response.status_code = 400
                    return response
            else:
                response = jsonify(
                    {
                        "error": "More than one argument sent, please only send the ioc param"
                    }
                )
                response.status_code = 400
                return response
        else:
            response = jsonify(
                {"error": "Missing required scopes in access token in API call"}
            )
            response.status_code = 401
            return response

    @app.route("/manual", methods=["POST"])
    def manual_soar():
        required_scopes = ["soar-api/admin.readwrite.all"]
        if verify_scopes(g.token, required_scopes):
            if request.is_json:
                data = request.get_json()
                try:
                    ioc, integration, action, incident_id, tenant_id = data.values()
                except Exception as error:
                    print(error)
                    response = jsonify(
                        {
                            "error": "Failed to unpack all POST arguments, please provide IOC, Action & Sentinel Incident ID"
                        }
                    )
                    response.status_code = 400
                    return response
                resp_data = Manual.write_db(
                    ioc, integration, action, incident_id, tenant_id
                )
                return jsonify(resp_data)
            else:
                response = jsonify({"error": "Request must be JSON"})
                response.status_code = 400
                return response
        else:
            response = jsonify(
                {"error": "Missing required scopes in access token in API call"}
            )
            response.status_code = 401
            return response

    @app.route("/datp/upload", methods=["POST"])
    def ioc_post_datp():
        required_scopes = ["soar-api/admin.readwrite.all"]
        if verify_scopes(g.token, required_scopes):
            if request.is_json:
                data = request.get_json()
                try:
                    ioc, action, incident_id, tenant_id = data.values()
                    if action not in DATP_VALID_ACTIONS:
                        response = jsonify(
                            {"error": "Action must be in list of supported actions"}
                        )
                        response.status_code = 400
                        return response
                except Exception as error:
                    print(error)
                    response = jsonify(
                        {
                            "error": "Failed to unpack all POST arguments, please provide IOC, Action & Sentinel Incident ID"
                        }
                    )
                    response.status_code = 400
                    return response
                resp_data = DATP.ioc_upload(ioc, action, incident_id, tenant_id)
                return jsonify(resp_data)
            else:
                response = jsonify({"error": "Request must be JSON"})
                response.status_code = 400
                return response
        else:
            response = jsonify(
                {"error": "Missing required scopes in access token in API call"}
            )
            response.status_code = 401
            return response

    @app.route("/azuread/blockip", methods=["POST"])
    def ioc_ip_azuread_block():
        required_scopes = ["soar-api/admin.readwrite.all"]
        if verify_scopes(g.token, required_scopes):
            if request.is_json:
                data = request.get_json()
                try:
                    ioc, list_id, list_name, incident_id, tenant_id = data.values()
                except Exception as error:
                    print(error)
                    response = jsonify(
                        {
                            "error": "Failed to unpack all POST arguments, please provide IOC, Azure AD List Name & Sentinel Incident ID"
                        }
                    )
                    response.status_code = 400
                    return response
                resp_data = AzureAD.ip_upload(
                    ioc, incident_id, list_id, list_name, tenant_id
                )
                return jsonify(resp_data)
            else:
                response = jsonify({"error": "Request must be JSON"})
                response.status_code = 400
                return response
        else:
            response = jsonify(
                {"error": "Missing required scopes in access token in API call"}
            )
            response.status_code = 401
            return response

    @app.route("/sase/block", methods=["POST"])
    def sase_block():
        required_scopes = ["soar-api/admin.readwrite.all"]
        if verify_scopes(g.token, required_scopes):
            if request.is_json:
                data = request.get_json()
                try:
                    ioc, incident_id = data.values()
                except Exception as error:
                    print(error)
                    response = jsonify(
                        {
                            "error": "Failed to unpack all POST arguments, please provide IOC & Sentinel Incident ID"
                        }
                    )
                    response.status_code = 400
                    return response
                resp_data = SASE.block(ioc, incident_id)
                return jsonify(resp_data)
            else:
                response = jsonify({"error": "Request must be JSON"})
                response.status_code = 400
                return response
        else:
            response = jsonify(
                {"error": "Missing required scopes in access token in API call"}
            )
            response.status_code = 401
            return response

    @app.route("/sase/submit", methods=["POST"])
    def sase_sandbox():
        required_scopes = ["soar-api/admin.readwrite.all"]
        if verify_scopes(g.token, required_scopes):
            if "file" in request.files:
                try:
                    uploaded_file = request.files["file"]
                    uploaded_file.seek(0, 2)  # Move to end of file
                    file_size = uploaded_file.tell()
                    uploaded_file.seek(0)  # Reset pointer to start
                    if file_size > 2 * 1024 * 1024:
                        response = jsonify({"error": "File size exceeds 2MB limit"})
                        response.status_code = 400
                        return response
                    file_bytes = uploaded_file.read()
                except Exception as error:
                    print(error)
                    response = jsonify(
                        {"error": "Failed to unpack & deserialize submitted file"}
                    )
                    response.status_code = 400
                    return response
                result = SASE.submit_file(file_bytes)
                if result.get("Sandbox") is False:
                    response = jsonify(
                        {
                            "error": "Failed to submit file to SASE sandbox, please check the file type and size"
                        }
                    )
                    response.status_code = 400
                    return response
                else:
                    return jsonify(result)
            else:
                response = jsonify({"error": "Request must be contain file"})
                response.status_code = 400
                return response
        else:
            response = jsonify(
                {"error": "Missing required scopes in access token in API call"}
            )
            response.status_code = 401
            return response

    @app.route("/sase/urlcategory", methods=["GET"])
    def sase_urlcategory():
        required_scopes = ["soar-api/admin.readwrite.all"]
        if verify_scopes(g.token, required_scopes):
            # Accepting only single IOC here per API call
            if len(request.args) == 1:
                param = request.args.to_dict()
                ioc = param.get("ioc", None)
                if ioc:
                    data = SASE.url_category_lookup(ioc)
                    if data:
                        return jsonify(data)
                    else:
                        response = jsonify(
                            {"error": "Upstream API issue, returning 500 error"}
                        )
                        response.status_code = 500
                        return response
                else:
                    response = jsonify(
                        {"error": "Missing ip uri param, please pass a IP address"}
                    )
                    response.status_code = 400
                    return response
            else:
                response = jsonify(
                    {
                        "error": "More than one argument sent, please only send the ioc param"
                    }
                )
                response.status_code = 400
                return response
        else:
            response = jsonify(
                {"error": "Missing required scopes in access token in API call"}
            )
            response.status_code = 401
            return response

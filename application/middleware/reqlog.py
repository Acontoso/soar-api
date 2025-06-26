from flask import request, g
import time
import urllib.parse
import uuid
from application.utils.logs import access_logger
from application.middleware.authen import verify_jwt


def before_request():
    # special global object that stores data during lifecycle of single request
    # Middleware function that executes before the request is processed
    g.start_time = time.time()
    g.request_ip = request.remote_addr
    g.user_agent = request.user_agent.string
    g.uri = request.url
    g.method = request.method
    g.args_size = len(urllib.parse.urlencode(request.args))
    g.request_id = str(uuid.uuid4())
    verify_jwt(request)


def after_request(response):
    bytes_in = len(request.get_data())
    bytes_out = len(response.get_data())
    extra = {
        "user_ip": g.request_ip,
        "user_agent": g.user_agent,
        "uri": g.uri,
        "method": g.method,
        "status_code": response.status_code,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "args_size_bytes": g.args_size,
        "client": g.client_id,
        "request_id": g.request_id,
    }
    access_logger.info("Request processed", extra=extra)
    return response

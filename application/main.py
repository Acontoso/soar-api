from flask import Flask
from utils.logs import setup_standard_logger
from routes.route import init_routes
from middleware.reqlog import before_request, after_request
import awsgi


def create_app():
    app = Flask(__name__)
    app.logger.handlers.clear()
    std_logger = setup_standard_logger()
    app.logger = std_logger
    app.before_request(before_request)
    app.after_request(after_request)
    init_routes(app)
    return app


def lambda_handler(event, context):
    app = create_app()
    response = awsgi.response(app, event, context)
    return response


# if __name__ == "__main__":
#     app = create_app()
#     app.run()

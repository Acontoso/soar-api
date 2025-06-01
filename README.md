# soar-api

Contoso SOAR API is a Security Orchestration, Automation, and Response (SOAR) platform built on AWS, designed to automate and orchestrate security operations workflows. It provides a set of RESTful APIs for integrating with various security tools and services, enabling automated incident response, enrichment, and remediation.

## Features
- **RESTful API**: Exposes endpoints for security automation, enrichment, and response actions.
- **AWS Native**: Integrates with AWS services such as DynamoDB, Lambda, SSM, and API Gateway.
- **Modular Controllers**: Supports integrations with Azure AD, Microsoft Defender, Cisco Umbrella, Anomali ThreatStream, AbuseIPDB, and more.
- **OpenAPI Spec**: API contract defined in `openapi.yaml` for easy integration and documentation.
- **Authentication**: Supports authentication middleware for secure access.
- **Extensible**: Easily add new integrations and automation workflows.

## Project Structure
```
application/
  controllers/   # API endpoint logic for each integration
  middleware/    # Authentication and request logging
  routes/        # API route definitions
  services/      # Service classes for external APIs and AWS
  utils/         # Utility functions and logging
  main.py        # Flask app entry point
openapi.yaml     # OpenAPI 3.0 specification
requirements.txt # Python dependencies
terraform/       # Infrastructure as Code for AWS resources
workflows/       # CI/CD pipeline definitions
```

## Testing
Run all unittests in the `tests` directory:
```bash
python -m unittest discover -s tests
```
To suppress warnings:
```bash
python -W ignore -m unittest discover -s tests
```

## API Documentation
- The OpenAPI specification is available in `openapi.yaml`.
- Import it into tools like Swagger UI or Postman for interactive documentation and testing.

## Infrastructure
- Infrastructure as Code is provided in the `terraform/` directory for AWS deployment.

---

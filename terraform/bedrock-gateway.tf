resource "aws_bedrockagentcore_gateway" "gateway" {
  name            = var.gateway_name
  description     = var.gateway_description
  role_arn        = aws_iam_role.gateway_role.arn
  authorizer_type = var.authorization_type
  protocol_type   = "MCP"
  region          = data.aws_region.current.name
  authorizer_configuration {
    custom_jwt_authorizer {
      discovery_url    = "https://login.microsoftonline.com/${var.tenant_id}/v2.0/.well-known/openid-configuration"
      allowed_audience = var.audience_values
    }
  }
  tags = local.tags
}

resource "aws_bedrockagentcore_gateway_target" "soar_api" {
  name               = "SOARAPIModern"
  gateway_identifier = aws_bedrockagentcore_gateway.gateway.gateway_id
  description        = "This gateway enables our existing SOAR API to be accessible via MCP"
  region             = data.aws_region.current.name

  credential_provider_configuration {
    oauth { #Provider needs to be created outside of terraform and has no data object
    # The client secret is stored in a secrets manager resource when creating from portal so need to add that.
      provider_arn = var.arn_oauth_outbound_provider
      grant_type   = "CLIENT_CREDENTIALS"
      scopes       = ["soar-api/admin.readwrite.all"]
    }
  }

  target_configuration {
    mcp {
      open_api_schema {
        inline_payload {
          payload = file("${path.module}/../openapi.yaml")
        }
      }
    }
  }
}

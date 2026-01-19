package routes

import (
	appcontainer "github.com/Acontoso/soar-api/code/app"
	"github.com/Acontoso/soar-api/code/middleware"
)

func SetupProtectedRoutes(app *appcontainer.App) {
	tokenGroup := app.Router.Group("/api/enrich")
	tokenGroup.Use(middleware.CognitoAuthMiddleware())
	tokenGroup.POST("/ipabusedb", app.IPLookup)
	tokenGroup.POST("/anomali", app.AnomaliLookup)
	tokenGroupSOAR := app.Router.Group("/api/soar")
	tokenGroupSOAR.Use(middleware.CognitoAuthMiddleware())
	tokenGroupSOAR.POST("/sse/zscaler", app.SSEBlock)
	tokenGroupSOAR.POST("/azuread/ca", app.CABlock)
	tokenGroupSOAR.POST("/datp/blockioc", app.DATPBlock)
	tokenGroupSOAR.POST("/waf/blockip", app.CloudflareBlock)
}


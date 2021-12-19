package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/robiokidenis/microservice-mvc-2/controller/auth"
	"github.com/robiokidenis/microservice-mvc-2/controller/ping"
	"github.com/robiokidenis/microservice-mvc-2/controller/users"
	"github.com/robiokidenis/microservice-mvc-5/jwtmiddleware"
)

func main() {
	r := gin.Default()

	signInKey := "secret"
	jwtmiddleware.InitJWTMiddlewareCustom([]byte(signInKey), jwt.SigningMethodHS512)

	r.Use(jwtmiddleware.CORSMiddleware())
	r.GET("ping", ping.PingController)

	{
		userRoute := r.Group("user")
		userRoute.Use(jwtmiddleware.MyAuth())

		userRoute.POST("", users.CreateController)
		userRoute.GET(":id", users.FindController)
		userRoute.GET("", users.FindByController)
	}

	{
		authRoute := r.Group("auth")
		authRoute.POST("", auth.LoginController)
	}

	r.Run(":9000")
}

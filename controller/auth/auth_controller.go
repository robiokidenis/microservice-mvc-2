package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/robiokidenis/microservice-mvc-2/conf"
	"github.com/robiokidenis/microservice-mvc-2/request/auth"
	"github.com/robiokidenis/microservice-mvc-2/services"
	"github.com/robiokidenis/microservice-mvc-5/httpresponse"
	"github.com/robiokidenis/microservice-mvc-5/jwtmiddleware"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

func LoginController(ctx *gin.Context) {
	var err error
	cfg := conf.NewConfig()

	db, err := conf.MysqlConnection(cfg)
	if err != nil {
		httpresponse.NewErrorException(ctx, http.StatusBadRequest, err)
		return
	}

	var req auth.LoginRequest
	if err = ctx.ShouldBind(&req); err != nil {
		httpresponse.NewErrorException(ctx, http.StatusBadRequest, err)
		return
	}

	userContract := services.NewUserServiceContract(db)
	user, err := userContract.FindOneBy(map[string]interface{}{
		"email": req.Email,
	})
	if err != nil {
		httpresponse.NewErrorException(ctx, http.StatusBadRequest, err)
		return
	}

	//	 compare password from db with request
	byteHash := []byte(user.Password) // password from db
	bytePlain := []byte(req.Password) // password from request

	if err := bcrypt.CompareHashAndPassword(byteHash, bytePlain); err != nil {
		httpresponse.NewErrorException(ctx, http.StatusForbidden, err)
		return
	}

	tokenStruct := new(jwtmiddleware.TokenRequestStructure)
	tokenStruct.Email = user.Email
	tokenStruct.UserID = user.ID

	signInKey := "secret"
	g := jwtmiddleware.NewCustomAuth([]byte(signInKey))
	token, err := g.GenerateToken(*tokenStruct)
	if err != nil {
		httpresponse.NewErrorException(ctx, http.StatusForbidden, err)
		return
	}

	httpresponse.NewSuccessResponse(ctx, token)
	return

}

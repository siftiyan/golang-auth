package middleware

import (
	"a21hc3NpZ25tZW50/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func Auth() gin.HandlerFunc {
	return gin.HandlerFunc(func(ctx *gin.Context) {

		token, err := ctx.Cookie("session_token")
		if err != nil {
			if ctx.Request.Header.Get("Content-Type") != "application/json" {
				ctx.JSON(303, gin.H{
					"error": "Invalid content type",
				})
				ctx.Abort()
				return
			}
			ctx.JSON(401, gin.H{
				"error": err.Error(),
			})
			ctx.Abort()
			return
		}

		claims := &model.Claims{}

		tokenString, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(model.JwtKey), nil
		})
		if err != nil {
			ctx.JSON(400, gin.H{
				"error": "Invalid token",
			})
			ctx.Abort()
			return
		}

		if !tokenString.Valid {
			ctx.JSON(401, gin.H{
				"error": "Unauthorized",
			})
			ctx.Abort()
			return
		}

		ctx.Set("id", claims.UserID)

		ctx.Next()
	})
}

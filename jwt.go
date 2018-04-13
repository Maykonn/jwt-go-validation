package jwt_go_validation

import (
	"github.com/dgrijalva/jwt-go"
	"fmt"
	"strconv"
)

func JwtParse(signatureString string, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// testing if is HMAC signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(signatureString), nil
	})
	return token, err
}

func JwtSignatureIsValid(signatureString string, tokenString string) (bool) {
	token, _ := JwtParse(signatureString, tokenString)
	return token.Valid
}

func JwtDecode(token *jwt.Token) (jwt.MapClaims) {
	return token.Claims.(jwt.MapClaims)
}

func JwtIdClaimIsValid(signatureString string, tokenString string, id string) (bool, error) {
	if token, _ := JwtParse(signatureString, tokenString); token != nil {
		// this cast is necessary how explained in this link(the JWT json parser, casting integer to float64):
		// https://github.com/dgrijalva/jwt-go/pull/162#issuecomment-317074607
		givenIdAsFloat64, err := strconv.ParseFloat(id, 64)
		if err != nil {
			return false, err
		}

		idClaim := JwtDecode(token)["id"]
		if idClaim == givenIdAsFloat64 {
			return true, nil
		}
	}

	return false, fmt.Errorf("given id do not matches jwt id")
}

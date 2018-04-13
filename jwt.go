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

func JwtDecode(token *jwt.Token) (map[string]interface{}, error) {
	if token.Valid {
		return token.Claims.(jwt.MapClaims), nil
	}
	return nil, fmt.Errorf("invalid token")
}

func JwtIdClaimIsValid(token *jwt.Token, id string) (bool, error) {
	// this cast is necessary how explained in this link(the JWT json parser, casting integer to float64):
	// https://github.com/dgrijalva/jwt-go/pull/162#issuecomment-317074607
	givenIdAsFloat64, err := strconv.ParseFloat(id, 64)
	if err != nil {
		return false, err
	}

	claims, _ := JwtDecode(token)
	if claims["id"] == givenIdAsFloat64 {
		return true, nil
	}

	return false, fmt.Errorf("given id do not matches jwt id")
}

func JwtSignatureIsValid(signatureString string, tokenString string) (bool) {
	token, _ := JwtParse(signatureString, tokenString)
	return token.Valid
}
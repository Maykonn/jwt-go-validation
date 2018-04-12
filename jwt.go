package jwt_go_validation

import (
	"github.com/dgrijalva/jwt-go"
	"fmt"
	"strconv"
)

func JwtSignatureIsValid(signatureString string, tokenString string) (bool) {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// testing if is HMAC signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(signatureString), nil
	})
	return token.Valid
}

func JwtValidateSignatureAndReturnParsed(signatureString string, tokenString string) (*jwt.Token) {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// testing if is HMAC signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(signatureString), nil
	})
	return token
}

func JwtIdClaimIsValid(signatureString string, tokenString string, id string) (bool, error) {
	token := JwtValidateSignatureAndReturnParsed(signatureString, tokenString)
	if idClaim, ok := token.Claims.(jwt.MapClaims)["id"]; ok && token.Valid {
		// this cast is necessary how explained in this link(the JWT json parser, casting integer to float64):
		// https://github.com/dgrijalva/jwt-go/pull/162#issuecomment-317074607
		givenIdAsFloat64, err := strconv.ParseFloat(id, 64)
		if err != nil {
			return false, err
		}
		if idClaim == givenIdAsFloat64 {
			return true, err
		}
	}
	return false, fmt.Errorf("given ID don't match the JWT id claim")
}

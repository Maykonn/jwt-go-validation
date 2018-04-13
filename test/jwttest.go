package main

import (
	"fmt"
	"maykonn/jwt-go-validation"
)

func main() {
	testValidSignature()
	testInValidSignature()
	testDecode()
	testIdClaim()
}

func testValidSignature() {
	signatureString := "fd6e28d3186f799458595dd466c8c957daa0a7ba"
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTE0NjUwLCJuYW1lIjoiTWF5a29ubiBXZWxpbmd0b24gQ2FuZGlkbyIsImlhdCI6MTUyMzQ2ODQwMiwiZXhwIjoxNTI2MDYwNDAyLCJpc3MiOiIxNzcuMjAuMjI1LjE2MiIsInN1YiI6IjExNDY1MCJ9.VIqAzk7_eilxxgOFVu_ygCoc2FfyafltyFoMqo2Be7A"
	ret := jwt_go_validation.JwtSignatureIsValid(signatureString, tokenString)
	fmt.Println("Test a valid signature:")
	fmt.Println(ret)
}

func testInValidSignature() {
	signatureString := "12324"
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTE0NjUwLCJuYW1lIjoiTWF5a29ubiBXZWxpbmd0b24gQ2FuZGlkbyIsImlhdCI6MTUyMzQ2ODQwMiwiZXhwIjoxNTI2MDYwNDAyLCJpc3MiOiIxNzcuMjAuMjI1LjE2MiIsInN1YiI6IjExNDY1MCJ9.VIqAzk7_eilxxgOFVu_ygCoc2FfyafltyFoMqo2Be7A"
	ret := jwt_go_validation.JwtSignatureIsValid(signatureString, tokenString)

	// signature must be invalid in this test
	test := true
	if ret {
		test = false
	}

	fmt.Println("Test an invalid signature:")
	fmt.Println(test)
}

func testDecode() {
	signatureString := "fd6e28d3186f799458595dd466c8c957daa0a7ba"
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTE0NjUwLCJuYW1lIjoiTWF5a29ubiBXZWxpbmd0b24gQ2FuZGlkbyIsImlhdCI6MTUyMzQ2ODQwMiwiZXhwIjoxNTI2MDYwNDAyLCJpc3MiOiIxNzcuMjAuMjI1LjE2MiIsInN1YiI6IjExNDY1MCJ9.VIqAzk7_eilxxgOFVu_ygCoc2FfyafltyFoMqo2Be7A"
	claims := jwt_go_validation.JwtDecode(signatureString, tokenString)
	_, test := claims["id"]

	fmt.Println("Test Decode:")
	fmt.Println(test)
}

func testIdClaim() {
	signatureString := "fd6e28d3186f799458595dd466c8c957daa0a7ba"
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTE0NjUwLCJuYW1lIjoiTWF5a29ubiBXZWxpbmd0b24gQ2FuZGlkbyIsImlhdCI6MTUyMzQ2ODQwMiwiZXhwIjoxNTI2MDYwNDAyLCJpc3MiOiIxNzcuMjAuMjI1LjE2MiIsInN1YiI6IjExNDY1MCJ9.VIqAzk7_eilxxgOFVu_ygCoc2FfyafltyFoMqo2Be7A"
	id := "114650"
	ret, _ := jwt_go_validation.JwtIdClaimIsValid(signatureString, tokenString, id)

	fmt.Println("Test ID Claim:")
	fmt.Println(ret)
}
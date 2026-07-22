package tools

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/golang-jwt/jwt/v5"
)

const (
	/*
		Test Keys used for local development!
	*/

	privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA201RBnUjXZ3QJ3M4uDEp7bP0TtWTt/oIxHQ8vI2tS5yeR7tj
sp3Oyf7q0sPjbNqW4SVVBwu1UGZGKAXAhUfGUsRDsf4NKphf9Ssm5DT0CkJsDnCt
lzoXxaKFXry9u4MGYxPXwrVuNQUAeQOZlspXu+nnMe2LPmZ1qrnpAlvaFFjI5gFt
Hh/7idClIKc8nbmAxasg1xK7o8s0GEPGIyF4H+TH9TTK7ZQtDvx7fcc+B3JDbHH+
3n7mT7cG2Hoh58EmX/ydapO2XkeIXRgA73t4+tY5ao0sszpAFf1zDorhLFr+Qc72
GWvLkJIZGGi7uOWuQYxBVDcyW2n3N0a2Jxrb2QIDAQABAoIBAAKNnOLhXD8Lxk+f
RMrIL7/Ht5FvZR/gNlfrLoXXdGwL77/QC7IZqj2pzRwVEcHDrbwDTkEdvsen2StA
HeSvWDzAcjVRSt/zFDLrhLFleG3iJhXo8+xtzbcMVFctBVx4gwuGQJ3QtO7DFyVR
iGk8A9d5OqrXJCbe1IHfVjojzZ8s/+1bh6P92RrkSuA1/V4Y8aWVdWBgUBx6LHI/
1tJOXg0Mc1Ke3QsRBN+MMeytCmCmgB4A8//8BjI892NZnFGbBmtQl9XJSeHkCruo
dNbxkXRTxBJgWfGOWjaL9qBsC3pXuwKYdai6QjWyZxT3xARohYbIiqKMGA1xWrVE
kGGFBAECgYEA7jdSnn2vmz62WvL3I081l6Yvo3BKx6Ox7vpmXUiv3eHlZuuxKU95
DsSyiXKGSCyTrx5VW+wHwDVTFO56oTSf/KhlqtPFer/LYS6Qs0dNe0AYzeMFnj5e
2vCIL8lKFuCGNXModPQmd0FymMRW396CAPVIVL0LZT657BynxUThbIECgYEA66yE
Mm+f/LteJG585/TT2YMYhoQTR/NA4wDqIq5tdNwxlQTBJNQad67r15TT5jB3p0Ku
P/2Hh1CwkYOqZHGWlfmuuBTrMtXe6+VSdcjsbn+daXf0KCeWsQHVf4jNZ9wIq9fj
JdJs8QLBS4cenQ2K9FNJ0rnSBEraRJqyhNGmo1kCgYBnuxt0/JINbh+GNyq663EQ
2kMATpOhn3yJ7evJTy+V1RpJ2PRKYtr6PVjpVT94CkE9Dl5pKrytTAsjoD0yGXJZ
WRL8cj8aFo5/gQFtr+zjcKPcc7EsmUhA2mDTPjnPAHIwsDa7xt1BLPSz5TtXPNMr
i6O1kqR1r/zR/iBoXHg1AQKBgQDSfpDIl4i27Acm1QR9DOBXC09Rfg/WmL7gwgVd
mpuq36ztY4S7RzKoqTR+pbApjiqg2t7VyrVNN9Ws8oOzGP0d0Rer1QtJqVplKbrf
9uitvQ+0ju4lG07tpCyzr1V/KTkZe0anlm21SfepZPMD5X+xv95U96FMMisHUYCX
PsXuaQKBgGWglns91f/hnh99yzTAKUbUDqi8X2l/0Y8GtxkkBcZJuxZu4DmfTAxr
0oyMZPqfru1bn0Ata5wfAJu6t1MkOoye6V8uFdv8svXMrUg1cDK3BVeYq4c/U7/h
DkknjDZgpWFXzelSfcagjo8KXNSf6lc5HL/g3CDvG0vlxyCybeKG
-----END RSA PRIVATE KEY-----
`
	publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA201RBnUjXZ3QJ3M4uDEp
7bP0TtWTt/oIxHQ8vI2tS5yeR7tjsp3Oyf7q0sPjbNqW4SVVBwu1UGZGKAXAhUfG
UsRDsf4NKphf9Ssm5DT0CkJsDnCtlzoXxaKFXry9u4MGYxPXwrVuNQUAeQOZlspX
u+nnMe2LPmZ1qrnpAlvaFFjI5gFtHh/7idClIKc8nbmAxasg1xK7o8s0GEPGIyF4
H+TH9TTK7ZQtDvx7fcc+B3JDbHH+3n7mT7cG2Hoh58EmX/ydapO2XkeIXRgA73t4
+tY5ao0sszpAFf1zDorhLFr+Qc72GWvLkJIZGGi7uOWuQYxBVDcyW2n3N0a2Jxrb
2QIDAQAB
-----END PUBLIC KEY-----
`
)

//

func PrivateKey() *rsa.PrivateKey {
	key, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	return key
}

func PublicKey() *rsa.PublicKey {
	key, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	return key
}

func EncodePrivateKey() string {
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(PrivateKey()),
	})

	return string(privateKeyPEM)
}

func EncodePublicKey() string {
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(PublicKey())
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})

	return string(pubKeyPEM)
}

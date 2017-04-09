package utils

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/docker/notary/tuf/data"
	"github.com/stretchr/testify/require"
)

func TestConvertTUFKeyToPKCS8(t *testing.T) {
	testRSAKey, err := GenerateRSAKey(rand.Reader, 1024)
	require.NoError(t, err)

	testECKey, err := GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)

	testEDKey, err := GenerateED25519Key(rand.Reader)
	require.NoError(t, err)

	testConvertKeyToPKCS8(t, testRSAKey)
	testConvertKeyToPKCS8(t, testRSAKey, []byte("poonies"))
	testConvertKeyToPKCS8(t, testECKey)
	testConvertKeyToPKCS8(t, testECKey, []byte("poonies"))
	testConvertKeyToPKCS8(t, testEDKey)
	testConvertKeyToPKCS8(t, testEDKey, []byte("poonies"))
}

func testConvertKeyToPKCS8(t *testing.T, privKey data.PrivateKey, v ...[]byte) {
	var der []byte
	var err error

	if v != nil {
		der, err = ConvertTUFKeyToPKCS8(privKey, v[0])
		require.NoError(t, err, "could not convert private key to pkcs8")

		keyInfo, err := ParsePKCS8ToTufKey(der, v[0])
		require.NoError(t, err, "could not decrypt the newly created pkcs8 key")
		require.EqualValues(t, keyInfo.Private(), privKey.Private())
	} else {
		der, err = ConvertTUFKeyToPKCS8(privKey)
		require.NoError(t, err, "could not convert private key to pkcs8")

		var keyInfo privateKeyInfo
		_, err = asn1.Unmarshal(der, &keyInfo)
		require.NoError(t, err, "could not unmarshal pkcs8")

		require.EqualValues(t, keyInfo.PrivateKey, privKey.Private(), "private key did not match")
	}
}

func TestParsePKCS8ToTufKey(t *testing.T) {
	testRSAKeyParsing(t)
	testECKeyParsing(t)
	testEDKeyParsing(t)
}

func testRSAKeyParsing(t *testing.T) {
	testRSAPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQEEggSqMIIEpgIBAAKCAQEA3vRQI7s20MF0Zc3f
ywttsw72OkRXuTT0/JQrSuoilzOSaoLKp7sYprIeIu9OeXqvBbwAxe3i1GViGwWM
8cH9QqD05XhMz0Crr9vu2zHaZFEI9mgTXcQxMQGntZ4xYV/rL/fddzj7+n1oKNvo
vS800NvPEMUkkgApdp5ES605V1q51tBpLEYJ82xb5vT8cVseFYfA4G+gVqLNfQla
sa0QsQT4YlVEDbbwT3/wuMG/m+wTx2p8urhD+69oQbORkpqkNiEzMNidOrvtD7qy
ab+cUNamYU0CKOFn/KhWuoZV7EVYnc+oevm7naYsenDq43Q5hGyacEuTjGtLnUG3
2d8RewIDAQABAoIBAQDeLOBfewSY6u8vNAU7tVvP/6znS4uPiHJJ8O1jbgaiXkYd
1dBVbWCXXRAjCA5PiC45rKuokfJkbdNh0houIH5ck0D4GvWP4oY0bRqNXBShuw8P
XY9O9V9/0oJpvga/XnJkDsCnOiX/7FCLxvka7ZvYNfMWZx6WT4sCJZ0xPKHTpT09
SzbhDOCLOsM4nWbs5xkXuEGPkD289z+NOmENdcKDHz0mgYAr7hKJI3oAt2ogTjSy
iQBLmxgudBUP5oJ1qY6/kYUCTYE3cjssY/mqfNcKtylQpTIUaUCw8BhOf3yJFA0G
SI6C7hp96cjEk2dRQxAtYhSZJPA2uN+D1/UIUeSBAoGBAO9VnVaTvkvc55upY9kU
KnZcztJwG2Hf9FRrJrgC2RIaj3KNEImUQyPgIVBXRzvdrvtvNJ6Tdb0cg6CBLJu7
IeQjca2Lj4ACIzoSMF8ak6BP3cdB/fCc2eHchqBKPWgZ23dq3CrpedtR6TbWLcsw
MrYdpZzpZ2eFPeStYxVhTLExAoGBAO56tNX+Sp4N4cCeht6ttljLnGfAjeSBWv4z
+xIqRyEoXbhchoppNxfnX34CrKmQM8MHfEYHKo27u/SkhnMGyuDOtrd51+jhB0LX
COH3w6GI162HVTRJXND8nUtCPB9h/SpFspr8Nk1Y2FtcfwkqhVphzExFzKm7eOPu
eevlsKJrAoGBALuvhh1Y60iOycpWggjAObRsf3yjkbWlbPOuu8Rd52C9F3UbjrZ1
YFmH8FgSubgG1qwyvy8EMLbG36pE4niVvbQs337bDQOzqXBmxywtqUt0llUmOUAx
oOPwjlqxHYq/jE4PrOyx/2+wwpTQTUUkXQBYK4Hrv718zdbA6gzgKsZhAoGBAMsn
QufNMZmFL9xb737Assbf5QRJd1bCj1Zfx7FIzMFFVtlYENDWIrW9R47cDmSAUGgC
923cavbEh7A3e8V/ctKhpeuU40YidIIPFyUQYNo57amI0R+yo1vw5roW2YrOedFK
AIWg901asyzZFeskCufcyiHrkBbDeo+JNtmrGJazAoGBAMOxKBm9HpFXB0h90+FA
6aQgL6FfF578QTW+s5UsZUJjKunYuGmXnYOb3iF6Kvvc/qmKDB1TInVtho1N5TcD
pLTbO3/JPtJyolvYXjnBI7qXjpPxJeicDbA919iDaEVtW1tQOQ9g7WBG0VorWUSr
oQSGi2o00tBJXEiEPmsJK2HL
-----END PRIVATE KEY-----
`)

	testEncryptedRSAPEM := []byte(`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI9VYsMyTwKmwCAggA
MB0GCWCGSAFlAwQBKgQQ86aS7qx+tL8SXCyh9jU9PASCBNDsJuZlBaoUc41IwNwS
eRtEAnjWQI2Aw/wEbo9I9xk2o3G5sTlUitpYfg5r4OjetqAcOietML/fT1XG7Wiv
6s9WBUsMZ1Q+ekccH3WbC4gP/yqcrDsoxUnAjHSyrFHsPamM7snZahwYALBJHd7x
kihCuxUOfCoI+nxhwnves5RJMYnvEizzJ58RonY9nr8jmbDHZy9nObyQqHOT0Jt9
X2xaCp+giZfPzkf1zyywf+VCMfNCDkpMiqjz5IDuk9ZignCTbvG8Zdnk6VFYaiif
o+12KjcXxYpYPDunADNPzu1xM90MpF9gZTyR2ZCnpiR0yqwMOVAQIUmq79kX03uw
RWMcbiiwCP0ZMA5GGO1+M0LQf+XVFs7zQdhebDrTVcEmWVoFpH8Rgn671QDlc2tY
m7KYgQ103oi8HpvtMJeqSMY7HtMClwXMJyCxUn6DQMiDNVx0FnBRFJWwY3Ji/Fs4
xmfnGF/JD+Tx35JxUKdBgqAU/OPUDbrg/Vcivj5M7BzaLA+LpV+IbFBkVGmE8Zuc
jVsJaGHsEdiAUhsV60I47/LVUp+MC2SdxaEdlUI8MCi1gspU9mKvc0OdCdefLBm1
V4xQY2CmiQZ4q9lmUz/kkEY0itMZ7WeeQ6v63uSn+WmZgmkzlQ4Qf5HKmNTmWAKq
g9IkLwaRd9OnXvqKPOcZLOma4vRVyNq91+VWhS6g1zKGGWV52NI5RnCaOJIJs+as
gJCi9gFDR1yqt6W9odQyV5ttT9OCY3Cl/KXhQsWnJzFM3lys0N4gq0qQYIwnzBla
L4r+m7VUtD6pe2DCxiF9ShNaYcQvhatz7mRKQJGPWVubbTYoodtAZYBcHeMe922/
gtkhwZ6w6txIfBQ8ptc7hZuhTj74l3bh9ENwUEAobecwHA/aKsyAWxm6YdxO/WAu
RiufbuadaCUywrwPFuxsnV529clFIT4gc8XCqQ4VHtqJIc3XJ97WAvHDiSE8fxMM
P1z2t93ZkpxD+ivV+l2EhabJ8xpReWo4Tof78rnNhTC9W4qS1fvlv8peHvhhnrG9
w6PMHXzjlVXDBYh63trCcA1MqxwMfIcZHI3++uonP/jS27dmMZYSkfYDJH4nmdL7
ZMUR9ruO8sljtMIRzfK000/+qNcAx4vZSJ94QwjCSCpwEX5VgO+kp+2h66XPIHgb
zYX/Xw5l76fQYQHNtE5GQJg+APiu5I5uFibZi/dJqwQEdrIZX6b/gfEogkkns6Ug
cdU/IK3RG8lf0Rh3X0BIJEQVBKmPewzMq2GzG342CHOTO4kLw0RHwOJmqhK0nS8U
c0U7iBLFMPglQ2fQz9izvEIaezzJVX7usyMxfQBm5J0qsQYDCFmCsdP1wzMGLYce
U9bJpFzkiBfaQRucvtTJpQ7PEVLYCg40CGQGpHFrhzeYAO19TQGZolkv6xcYrYmg
PY+2QtRt4EfaacNpxSJcrCYFT81OP6UV0x8XSvdFtAGbf5PjChFDTsoAkbNSVrd2
NREZMhxFATh3Ek9y/2nxo8pDZ1N0Vid6sOg5dtryB7p9ZZgczleY7B8xaLsoCN4y
6T1wYok7Pg9inKoB4J3yun4Td85Xwo8aT0aulX/oN6XjZt3ZjjtK+RXoZMfARAJ1
u+rmy9/CMkLtFQM4Hlbb75WeFA==
-----END ENCRYPTED PRIVATE KEY-----
`)

	block, _ := pem.Decode(testRSAPEM)
	key, err := ParsePKCS8ToTufKey(block.Bytes)
	require.NoError(t, err, "could not parse pkcs8 to tuf key")

	block, _ = pem.Decode(testEncryptedRSAPEM)
	encryptedKey, err := ParsePKCS8ToTufKey(block.Bytes, []byte("poonies"))
	require.NoError(t, err, "could not parse encrypted pkcs8 to tuf key")

	require.Equal(t, "rsa", key.Algorithm())
	require.Equal(t, "rsa", encryptedKey.Algorithm())
	require.EqualValues(t, key.Private(), encryptedKey.Private())
}

func testECKeyParsing(t *testing.T) {
	testECPEM := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiwt5YfD/xQdVwJZ0
2TpiJDQQ8DRHYVeWzIscya52BvChRANCAAT58IHVQJwbo3/MS/dFjh+xM85gVydX
xY+wxYDkaougZDPIgvu3+bQZ4xYSAnCGX7UJIiLloKuuuvbmXQlnSGqw
-----END PRIVATE KEY-----
`)

	testEncryptedECPEM := []byte(`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAhau2ksQB01lgICCAAw
HQYJYIZIAWUDBAEqBBABQd7kN7aKsbD62UQ8QQl7BIGQO4cuxkugQZLMLUPV39Jl
24jAl0lFLdvAPWZoD9Z5jCa7Fbw/uFza/PVZkScHv6LC5BAah4+NmyydiJiIbP4D
9udZlQ/T4ui4/zrm/19LGP7TPB8LtxaNl6xyKSbDiJHqkz30h+qGr5naCu5xb1dd
P2RiPFJIOaO8pEegcJ5EL++ZJXDaX0UAi3X7E1tS27ye
-----END ENCRYPTED PRIVATE KEY-----
`)

	block, _ := pem.Decode(testECPEM)
	key, err := ParsePKCS8ToTufKey(block.Bytes)
	require.NoError(t, err, "could not parse pkcs8 to tuf key")

	block, _ = pem.Decode(testEncryptedECPEM)
	encryptedKey, err := ParsePKCS8ToTufKey(block.Bytes, []byte("poonies"))
	require.NoError(t, err, "could not parse encrypted pkcs8 to tuf key")

	require.Equal(t, "ecdsa", key.Algorithm())
	require.Equal(t, "ecdsa", encryptedKey.Algorithm())
	require.EqualValues(t, key.Private(), encryptedKey.Private())
}

func testEDKeyParsing(t *testing.T) {
	testEDPEM := []byte(`-----BEGIN PRIVATE KEY-----
MHICAQAwCwYJKwYBBAHaRw8BBGDkASR4b08nd+A8txI3h+1hG+7EAIxE5cdbv3gt
rwib9ibygTpRt8XjscMv+vum4zFjI2pPZbhQn6lZlumHo7g35AEkeG9PJ3fgPLcS
N4ftYRvuxACMROXHW794La8Im/Y=
-----END PRIVATE KEY-----
`)

	testEncryptedEDPEM := []byte(`-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHOMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAh8sh6C9OF2tQICCAAw
HQYJYIZIAWUDBAEqBBAmrQCFS3nRn9pWlcP3zrcLBIGAAPAps1iO5mIKFK3NKoOH
7Wt96+AuGj5npvk8P3KITWJrC5bBUCvSmBHGvH34Lq/3ZvH0pcAM83q8Ur/Rup45
oSHUCyOs7hbMiJZpLm4uKFyC/K4g9oAZh0uM8zX+nZ2lhvinG6vr3EJ+Q8PPfjhn
m5BQI0a/JyoOvDRZfW74YZk=
-----END ENCRYPTED PRIVATE KEY-----
`)

	block, _ := pem.Decode(testEDPEM)
	key, err := ParsePKCS8ToTufKey(block.Bytes)
	require.NoError(t, err, "could not parse pkcs8 to tuf key")

	block, _ = pem.Decode(testEncryptedEDPEM)
	encryptedKey, err := ParsePKCS8ToTufKey(block.Bytes, []byte("poonies"))
	require.NoError(t, err, "could not parse encrypted pkcs8 to tuf key")

	require.Equal(t, "ed25519", key.Algorithm())
	require.Equal(t, "ed25519", encryptedKey.Algorithm())
	require.EqualValues(t, key.Private(), encryptedKey.Private())
}

func TestPEMtoPEM(t *testing.T) {
	testInputPKCS1 := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEA3vRQI7s20MF0Zc3fywttsw72OkRXuTT0/JQrSuoilzOSaoLK
p7sYprIeIu9OeXqvBbwAxe3i1GViGwWM8cH9QqD05XhMz0Crr9vu2zHaZFEI9mgT
XcQxMQGntZ4xYV/rL/fddzj7+n1oKNvovS800NvPEMUkkgApdp5ES605V1q51tBp
LEYJ82xb5vT8cVseFYfA4G+gVqLNfQlasa0QsQT4YlVEDbbwT3/wuMG/m+wTx2p8
urhD+69oQbORkpqkNiEzMNidOrvtD7qyab+cUNamYU0CKOFn/KhWuoZV7EVYnc+o
evm7naYsenDq43Q5hGyacEuTjGtLnUG32d8RewIDAQABAoIBAQDeLOBfewSY6u8v
NAU7tVvP/6znS4uPiHJJ8O1jbgaiXkYd1dBVbWCXXRAjCA5PiC45rKuokfJkbdNh
0houIH5ck0D4GvWP4oY0bRqNXBShuw8PXY9O9V9/0oJpvga/XnJkDsCnOiX/7FCL
xvka7ZvYNfMWZx6WT4sCJZ0xPKHTpT09SzbhDOCLOsM4nWbs5xkXuEGPkD289z+N
OmENdcKDHz0mgYAr7hKJI3oAt2ogTjSyiQBLmxgudBUP5oJ1qY6/kYUCTYE3cjss
Y/mqfNcKtylQpTIUaUCw8BhOf3yJFA0GSI6C7hp96cjEk2dRQxAtYhSZJPA2uN+D
1/UIUeSBAoGBAO9VnVaTvkvc55upY9kUKnZcztJwG2Hf9FRrJrgC2RIaj3KNEImU
QyPgIVBXRzvdrvtvNJ6Tdb0cg6CBLJu7IeQjca2Lj4ACIzoSMF8ak6BP3cdB/fCc
2eHchqBKPWgZ23dq3CrpedtR6TbWLcswMrYdpZzpZ2eFPeStYxVhTLExAoGBAO56
tNX+Sp4N4cCeht6ttljLnGfAjeSBWv4z+xIqRyEoXbhchoppNxfnX34CrKmQM8MH
fEYHKo27u/SkhnMGyuDOtrd51+jhB0LXCOH3w6GI162HVTRJXND8nUtCPB9h/SpF
spr8Nk1Y2FtcfwkqhVphzExFzKm7eOPueevlsKJrAoGBALuvhh1Y60iOycpWggjA
ObRsf3yjkbWlbPOuu8Rd52C9F3UbjrZ1YFmH8FgSubgG1qwyvy8EMLbG36pE4niV
vbQs337bDQOzqXBmxywtqUt0llUmOUAxoOPwjlqxHYq/jE4PrOyx/2+wwpTQTUUk
XQBYK4Hrv718zdbA6gzgKsZhAoGBAMsnQufNMZmFL9xb737Assbf5QRJd1bCj1Zf
x7FIzMFFVtlYENDWIrW9R47cDmSAUGgC923cavbEh7A3e8V/ctKhpeuU40YidIIP
FyUQYNo57amI0R+yo1vw5roW2YrOedFKAIWg901asyzZFeskCufcyiHrkBbDeo+J
NtmrGJazAoGBAMOxKBm9HpFXB0h90+FA6aQgL6FfF578QTW+s5UsZUJjKunYuGmX
nYOb3iF6Kvvc/qmKDB1TInVtho1N5TcDpLTbO3/JPtJyolvYXjnBI7qXjpPxJeic
DbA919iDaEVtW1tQOQ9g7WBG0VorWUSroQSGi2o00tBJXEiEPmsJK2HL
-----END RSA PRIVATE KEY-----
`)

	testOutputPKCS8 := []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQEEggSqMIIEpgIBAAKCAQEA3vRQI7s20MF0Zc3f
ywttsw72OkRXuTT0/JQrSuoilzOSaoLKp7sYprIeIu9OeXqvBbwAxe3i1GViGwWM
8cH9QqD05XhMz0Crr9vu2zHaZFEI9mgTXcQxMQGntZ4xYV/rL/fddzj7+n1oKNvo
vS800NvPEMUkkgApdp5ES605V1q51tBpLEYJ82xb5vT8cVseFYfA4G+gVqLNfQla
sa0QsQT4YlVEDbbwT3/wuMG/m+wTx2p8urhD+69oQbORkpqkNiEzMNidOrvtD7qy
ab+cUNamYU0CKOFn/KhWuoZV7EVYnc+oevm7naYsenDq43Q5hGyacEuTjGtLnUG3
2d8RewIDAQABAoIBAQDeLOBfewSY6u8vNAU7tVvP/6znS4uPiHJJ8O1jbgaiXkYd
1dBVbWCXXRAjCA5PiC45rKuokfJkbdNh0houIH5ck0D4GvWP4oY0bRqNXBShuw8P
XY9O9V9/0oJpvga/XnJkDsCnOiX/7FCLxvka7ZvYNfMWZx6WT4sCJZ0xPKHTpT09
SzbhDOCLOsM4nWbs5xkXuEGPkD289z+NOmENdcKDHz0mgYAr7hKJI3oAt2ogTjSy
iQBLmxgudBUP5oJ1qY6/kYUCTYE3cjssY/mqfNcKtylQpTIUaUCw8BhOf3yJFA0G
SI6C7hp96cjEk2dRQxAtYhSZJPA2uN+D1/UIUeSBAoGBAO9VnVaTvkvc55upY9kU
KnZcztJwG2Hf9FRrJrgC2RIaj3KNEImUQyPgIVBXRzvdrvtvNJ6Tdb0cg6CBLJu7
IeQjca2Lj4ACIzoSMF8ak6BP3cdB/fCc2eHchqBKPWgZ23dq3CrpedtR6TbWLcsw
MrYdpZzpZ2eFPeStYxVhTLExAoGBAO56tNX+Sp4N4cCeht6ttljLnGfAjeSBWv4z
+xIqRyEoXbhchoppNxfnX34CrKmQM8MHfEYHKo27u/SkhnMGyuDOtrd51+jhB0LX
COH3w6GI162HVTRJXND8nUtCPB9h/SpFspr8Nk1Y2FtcfwkqhVphzExFzKm7eOPu
eevlsKJrAoGBALuvhh1Y60iOycpWggjAObRsf3yjkbWlbPOuu8Rd52C9F3UbjrZ1
YFmH8FgSubgG1qwyvy8EMLbG36pE4niVvbQs337bDQOzqXBmxywtqUt0llUmOUAx
oOPwjlqxHYq/jE4PrOyx/2+wwpTQTUUkXQBYK4Hrv718zdbA6gzgKsZhAoGBAMsn
QufNMZmFL9xb737Assbf5QRJd1bCj1Zfx7FIzMFFVtlYENDWIrW9R47cDmSAUGgC
923cavbEh7A3e8V/ctKhpeuU40YidIIPFyUQYNo57amI0R+yo1vw5roW2YrOedFK
AIWg901asyzZFeskCufcyiHrkBbDeo+JNtmrGJazAoGBAMOxKBm9HpFXB0h90+FA
6aQgL6FfF578QTW+s5UsZUJjKunYuGmXnYOb3iF6Kvvc/qmKDB1TInVtho1N5TcD
pLTbO3/JPtJyolvYXjnBI7qXjpPxJeicDbA919iDaEVtW1tQOQ9g7WBG0VorWUSr
oQSGi2o00tBJXEiEPmsJK2HL
-----END PRIVATE KEY-----
`)

	block, _ := pem.Decode(testInputPKCS1)
	require.NotEmpty(t, block)

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	testPrivKey, err := RSAToPrivateKey(rsaKey)
	require.NoError(t, err)

	der, err := ConvertTUFKeyToPKCS8(testPrivKey)
	require.NoError(t, err, "could not convert pkcs1 to pkcs8")

	testOutput := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	require.EqualValues(t, testOutputPKCS8, testOutput)
}

package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/docker/notary/tuf/data"
	"github.com/stretchr/testify/require"
)

func TestCertsToKeys(t *testing.T) {
	// Get root certificate
	rootCA, err := LoadCertFromFile("../../fixtures/root-ca.crt")
	require.NoError(t, err)

	// Get intermediate certificate
	intermediateCA, err := LoadCertFromFile("../../fixtures/intermediate-ca.crt")
	require.NoError(t, err)

	// Get leaf certificate
	leafCert, err := LoadCertFromFile("../../fixtures/secure.example.com.crt")
	require.NoError(t, err)

	// Get our certList with Leaf Cert and Intermediate
	certMap := map[string]*x509.Certificate{
		"a": leafCert,
		"b": intermediateCA,
		"c": rootCA,
	}
	certList := []*x509.Certificate{
		leafCert,
		intermediateCA,
		rootCA,
	}

	// Call CertsToKeys
	keys := CertsToKeys(certMap, make(map[string][]*x509.Certificate))
	require.NotNil(t, keys)
	require.Len(t, keys, 3)

	// Call GetLeafCerts
	newKeys := GetLeafCerts(certList)
	require.NotNil(t, newKeys)
	require.Len(t, newKeys, 1)

	// Call GetIntermediateCerts (checks for certs with IsCA true)
	newKeys = GetIntermediateCerts(certList)
	require.NotNil(t, newKeys)
	require.Len(t, newKeys, 2)

	// Try calling CertToKeys on a junk leaf cert that won't fingerprint
	emptyCert := x509.Certificate{}
	// Also try changing the pre-existing leaf cert into an invalid algorithm
	leafCert.PublicKeyAlgorithm = x509.DSA
	keys = CertsToKeys(map[string]*x509.Certificate{"d": &emptyCert, "e": leafCert}, make(map[string][]*x509.Certificate))
	require.Empty(t, keys)
}

func TestNewCertificate(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.AddDate(10, 0, 0)
	cert, err := NewCertificate("docker.com/alpine", startTime, endTime)
	require.NoError(t, err)
	require.Equal(t, cert.Subject.CommonName, "docker.com/alpine")
	require.Equal(t, cert.NotBefore, startTime)
	require.Equal(t, cert.NotAfter, endTime)
}

func TestKeyOperations(t *testing.T) {
	// Generate our ED25519 private key
	edKey, err := GenerateED25519Key(rand.Reader)
	require.NoError(t, err)

	// Generate our EC private key
	ecKey, err := GenerateECDSAKey(rand.Reader)
	require.NoError(t, err)

	// Generate our RSA private key
	rsaKey, err := GenerateRSAKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode our ED private key
	edPEM, err := ConvertPrivateKeyToPKCS8(edKey, data.CanonicalRootRole, "", "")
	require.NoError(t, err)

	// Encode our EC private key
	ecPEM, err := ConvertPrivateKeyToPKCS8(ecKey, data.CanonicalRootRole, "", "")
	require.NoError(t, err)

	// Encode our RSA private key
	rsaPEM, err := ConvertPrivateKeyToPKCS8(rsaKey, data.CanonicalRootRole, "", "")
	require.NoError(t, err)

	// Check to see if ED key it is encoded
	stringEncodedEDKey := string(edPEM)
	require.True(t, strings.Contains(stringEncodedEDKey, "-----BEGIN PRIVATE KEY-----"))

	// Check to see the ED key type
	testKeyBlockType(t, edPEM, nil, "ed25519")

	// Check to see if EC key it is encoded
	stringEncodedECKey := string(ecPEM)
	require.True(t, strings.Contains(stringEncodedECKey, "-----BEGIN PRIVATE KEY-----"))

	// Check to see the EC key type
	testKeyBlockType(t, ecPEM, nil, "ecdsa")

	// Check to see if RSA key it is encoded
	stringEncodedRSAKey := string(rsaPEM)
	require.True(t, strings.Contains(stringEncodedRSAKey, "-----BEGIN PRIVATE KEY-----"))

	// Check to see the RSA key type
	testKeyBlockType(t, rsaPEM, nil, "rsa")

	// Decode our ED Key
	decodedEDKey, err := ParsePEMPrivateKey(edPEM, "")
	require.NoError(t, err)
	require.Equal(t, edKey.Private(), decodedEDKey.Private())

	// Decode our EC Key
	decodedECKey, err := ParsePEMPrivateKey(ecPEM, "")
	require.NoError(t, err)
	require.Equal(t, ecKey.Private(), decodedECKey.Private())

	// Decode our RSA Key
	decodedRSAKey, err := ParsePEMPrivateKey(rsaPEM, "")
	require.NoError(t, err)
	require.Equal(t, rsaKey.Private(), decodedRSAKey.Private())

	// Encrypt our ED Key
	encryptedEDKey, err := ConvertPrivateKeyToPKCS8(edKey, data.CanonicalRootRole, "", "ponies")
	require.NoError(t, err)

	// Encrypt our EC Key
	encryptedECKey, err := ConvertPrivateKeyToPKCS8(ecKey, data.CanonicalRootRole, "", "ponies")
	require.NoError(t, err)

	// Encrypt our RSA Key
	encryptedRSAKey, err := ConvertPrivateKeyToPKCS8(rsaKey, data.CanonicalRootRole, "", "ponies")
	require.NoError(t, err)

	// Check to see if ED key it is encrypted
	stringEncryptedEDKey := string(encryptedEDKey)
	fmt.Println(stringEncryptedEDKey)
	require.True(t, strings.Contains(stringEncryptedEDKey, "-----BEGIN PRIVATE ENCRYPTED KEY-----"))
	role, _, err := ExtractPrivateKeyAttributes(encryptedEDKey)
	require.NoError(t, err)
	require.EqualValues(t, "root", role)

	// Check to see if EC key it is encrypted
	stringEncryptedECKey := string(encryptedECKey)
	require.True(t, strings.Contains(stringEncryptedECKey, "-----BEGIN PRIVATE ENCRYPTED KEY-----"))
	role, _, err = ExtractPrivateKeyAttributes(encryptedECKey)
	require.NoError(t, err)
	require.EqualValues(t, "root", role)

	// Check to see if RSA key it is encrypted
	stringEncryptedRSAKey := string(encryptedRSAKey)
	require.True(t, strings.Contains(stringEncryptedRSAKey, "-----BEGIN PRIVATE ENCRYPTED KEY-----"))
	role, _, err = ExtractPrivateKeyAttributes(encryptedRSAKey)
	require.NoError(t, err)
	require.EqualValues(t, "root", role)

	// Decrypt our ED Key
	decryptedEDKey, err := ParsePEMPrivateKey(encryptedEDKey, "ponies")
	require.NoError(t, err)
	require.Equal(t, edKey.Private(), decryptedEDKey.Private())

	// Decrypt our EC Key
	decryptedECKey, err := ParsePEMPrivateKey(encryptedECKey, "ponies")
	require.NoError(t, err)
	require.Equal(t, ecKey.Private(), decryptedECKey.Private())

	// Decrypt our RSA Key
	decryptedRSAKey, err := ParsePEMPrivateKey(encryptedRSAKey, "ponies")
	require.NoError(t, err)
	require.Equal(t, rsaKey.Private(), decryptedRSAKey.Private())

	// quick test that gun headers are being added appropriately
	// Encrypt our RSA Key, one type of key should be enough since headers are treated the same
	testGunKey, err := ConvertPrivateKeyToPKCS8(rsaKey, data.CanonicalRootRole, "ilove", "ponies")
	require.NoError(t, err)

	testNoGunKey, err := ConvertPrivateKeyToPKCS8(rsaKey, data.CanonicalRootRole, "", "ponies")
	require.NoError(t, err)

	_, gun, err := ExtractPrivateKeyAttributes(testGunKey)
	require.NoError(t, err)
	require.EqualValues(t, "ilove", gun)

	_, gun, err = ExtractPrivateKeyAttributes(testNoGunKey)
	require.NoError(t, err)
	require.EqualValues(t, "", gun)
}

func testKeyBlockType(t *testing.T, b, password []byte, expectedKeyType string) {
	block, _ := pem.Decode(b)

	var wrap data.KeyWrap
	if _, err := asn1.Unmarshal(block.Bytes, &wrap); err != nil {
		require.NoError(t, err, "unable to unmarshal key")
	}

	var privKey data.PrivateKey
	var err error
	if password == nil {
		privKey, err = ParsePKCS8ToTufKey(wrap.Key)
	} else {
		privKey, err = ParsePKCS8ToTufKey(wrap.Key, password)
	}
	if err != nil {
		require.NoError(t, err, "unable to parse to pkcs8")
	}

	require.Equal(t, expectedKeyType, privKey.Algorithm(), "key type did not match")
}

// X509PublickeyID returns the public key ID of a RSA X509 key rather than the
// cert ID
func TestRSAX509PublickeyID(t *testing.T) {
	fileBytes, err := ioutil.ReadFile("../../fixtures/notary-server.key")
	require.NoError(t, err)

	privKey, err := ParsePEMPrivateKey(fileBytes, "")
	require.NoError(t, err)
	expectedTUFID := privKey.ID()

	cert, err := LoadCertFromFile("../../fixtures/notary-server.crt")
	require.NoError(t, err)

	rsaKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	require.NoError(t, err)

	sameWayTUFID := data.NewPublicKey(data.RSAKey, rsaKeyBytes).ID()

	actualTUFKey := CertToKey(cert)
	actualTUFID, err := X509PublicKeyID(actualTUFKey)
	require.NoError(t, err)
	require.Equal(t, sameWayTUFID, actualTUFID)
	require.Equal(t, expectedTUFID, actualTUFID)
}

// X509PublickeyID returns the public key ID of an ECDSA X509 key rather than
// the cert ID
func TestECDSAX509PublickeyID(t *testing.T) {
	startTime := time.Now()
	template, err := NewCertificate("something", startTime, startTime.AddDate(10, 0, 0))
	require.NoError(t, err)
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.PublicKeyAlgorithm = x509.ECDSA

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tufPrivKey, err := ECDSAToPrivateKey(privKey)
	require.NoError(t, err)

	derBytes, err := x509.CreateCertificate(
		rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	tufKey := CertToKey(cert)
	tufID, err := X509PublicKeyID(tufKey)
	require.NoError(t, err)

	require.Equal(t, tufPrivKey.ID(), tufID)
}

func TestValidateCertificateWithSHA1(t *testing.T) {
	// Test against SHA1 signature algorithm cert first
	startTime := time.Now()
	template, err := NewCertificate("something", startTime, startTime.AddDate(10, 0, 0))
	require.NoError(t, err)
	// SHA1 signature algorithm is invalid
	template.SignatureAlgorithm = x509.ECDSAWithSHA1
	template.PublicKeyAlgorithm = x509.ECDSA

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	derBytes, err := x509.CreateCertificate(
		rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	sha1Cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	// Regardless of expiry check, this certificate should fail to validate
	require.Error(t, ValidateCertificate(sha1Cert, false))
	require.Error(t, ValidateCertificate(sha1Cert, true))
}

func TestValidateCertificateWithExpiredCert(t *testing.T) {
	// Test against an expired cert for 10 years ago, only valid for a day
	startTime := time.Now().AddDate(-10, 0, 0)
	template, err := NewCertificate("something", startTime, startTime.AddDate(0, 0, 1))
	require.NoError(t, err)
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.PublicKeyAlgorithm = x509.ECDSA

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	derBytes, err := x509.CreateCertificate(
		rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	expiredCert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	// If we don't check expiry, this cert is perfectly valid
	require.NoError(t, ValidateCertificate(expiredCert, false))
	// We should get an error when we check expiry
	require.Error(t, ValidateCertificate(expiredCert, true))
}

func TestValidateCertificateWithInvalidExpiry(t *testing.T) {
	// Test against a cert with an invalid expiry window: from 10 years in the future to 10 years ago
	startTime := time.Now().AddDate(10, 0, 0)
	template, err := NewCertificate("something", startTime, startTime.AddDate(-10, 0, 0))
	require.NoError(t, err)
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.PublicKeyAlgorithm = x509.ECDSA

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	derBytes, err := x509.CreateCertificate(
		rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	invalidCert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	// Regardless of expiry check, this certificate should fail to validate
	require.Error(t, ValidateCertificate(invalidCert, false))
	require.Error(t, ValidateCertificate(invalidCert, true))
}

func TestValidateCertificateWithShortKey(t *testing.T) {
	startTime := time.Now()
	template, err := NewCertificate("something", startTime, startTime.AddDate(10, 0, 0))
	require.NoError(t, err)
	template.SignatureAlgorithm = x509.SHA256WithRSA
	template.PublicKeyAlgorithm = x509.RSA

	// Use only 1024 bit modulus, this will fail
	weakPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	derBytes, err := x509.CreateCertificate(
		rand.Reader, template, template, &weakPrivKey.PublicKey, weakPrivKey)
	require.NoError(t, err)

	weakKeyCert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	// Regardless of expiry check, this certificate should fail to validate
	require.Error(t, ValidateCertificate(weakKeyCert, false))
	require.Error(t, ValidateCertificate(weakKeyCert, true))
}

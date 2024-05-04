package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// TODO make these ssh certs
func main() {
	// cp, err := certificates.NewCertProviderFromFiles("authserverCAPrivKey.pem", "authserverCA.pem")
	// if err != nil {
	// 	fmt.Printf("%w", err)
	// }
	// cp.CreateCertificate()

	keyFile := "authserverCAPrivKey.pem"
	certFile := "authserverCA.pem"
	cf, e := os.ReadFile(certFile)
	if e != nil {
		fmt.Println("cfload:", e.Error())
		os.Exit(1)
	}

	kf, e := os.ReadFile(keyFile)
	if e != nil {
		fmt.Println("kfload:", e.Error())
		os.Exit(1)
	}
	cpb, cr := pem.Decode(cf)
	fmt.Println(string(cr))
	kpb, kr := pem.Decode(kf)
	fmt.Println(string(kr))
	crt, e := x509.ParseCertificate(cpb.Bytes)

	if e != nil {
		fmt.Println("parsex509:", e.Error())
		os.Exit(1)
	}
	key, e := x509.ParsePKCS1PrivateKey(kpb.Bytes)
	if e != nil {
		fmt.Println("parsekey:", e.Error())
		os.Exit(1)
	}
	generate_host_cert(crt, key)
	generate_user_cert(crt, key)
	generateSSHCert(key)
}

func generate_host_cert(ca *x509.Certificate, key *rsa.PrivateKey) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	// create cert for host
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		IPAddresses: []net.IP{net.ParseIP("192.168.1.101")},
	}

	// Create private key for cert
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("host GenerateKey:", err.Error())
		os.Exit(1)
	}

	// sign cert with the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, key)
	if err != nil {
		fmt.Println("host CreateCertificate:", err.Error())
		os.Exit(1)
	}

	hostCertOut, err := os.Create("nopush/hostcert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	defer hostCertOut.Close()
	pem.Encode(hostCertOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	hostKeyOut, err := os.OpenFile("nopush/hostkey.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	defer hostKeyOut.Close()
	pem.Encode(hostKeyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
}

func generate_user_cert(ca *x509.Certificate, key *rsa.PrivateKey) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	// create cert to sign
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "koalatea",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	// Create private key for cert
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("client GenerateKey:", err.Error())
		os.Exit(1)
	}

	// sign cert with the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, key)
	if err != nil {
		fmt.Println("host CreateCert:", err.Error())
		os.Exit(1)
	}

	certOut, err := os.Create("nopush/clientcert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	keyOut, err := os.OpenFile("nopush/clientkey.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
}

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated")
	return pubKeyBytes, nil
}

func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := os.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

func generateSSHCert(caKey *rsa.PrivateKey) error {
	signer, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		return err
	}
	certValidity := time.Now().AddDate(10, 0, 0).Unix()

	// CA as openssh keys
	caPubKey, _ := generatePublicKey(&caKey.PublicKey)
	err = writeKeyToFile([]byte(caPubKey), "nopush/ssh-ca.pub")
	if err != nil {
		log.Fatal(err.Error())
	}

	// User SSH keys and cert
	privKey, _ := generatePrivateKey(4096)
	pubKey, _ := generatePublicKey(&privKey.PublicKey)
	sshPubKey, _, _, _, _ := ssh.ParseAuthorizedKey(pubKey)
	permissions := ssh.Permissions{
		CriticalOptions: map[string]string{},
		Extensions:      map[string]string{"permit-agent-forwarding": "", "permit-X11-forwarding": "", "permit-port-forwarding": "", "permit-pty": "", "permit-user-rc": ""},
	}
	cert := ssh.Certificate{
		CertType: ssh.UserCert, Permissions: permissions, Key: sshPubKey, ValidPrincipals: []string{"koalatea"}, ValidBefore: uint64(certValidity),
	}
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		return err
	}

	privateKeyBytes := encodePrivateKeyToPEM(privKey)
	err = writeKeyToFile(privateKeyBytes, "nopush/user-ssh-key")
	if err != nil {
		log.Fatal(err.Error())
	}

	err = writeKeyToFile([]byte(pubKey), "nopush/user-ssh-key.pub")
	if err != nil {
		log.Fatal(err.Error())
	}
	f, err := os.Create("nopush/user-ssh-key-cert.pub")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer f.Close()
	f.WriteString(fmt.Sprintf("ssh-rsa-cert-v01@openssh.com %s hostnameIguess", base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(cert.Marshal())))

	// Host SSH keys and cert
	privKey, _ = generatePrivateKey(4096)
	pubKey, _ = generatePublicKey(&privKey.PublicKey)
	sshPubKey, _, _, _, _ = ssh.ParseAuthorizedKey(pubKey)
	cert = ssh.Certificate{
		CertType: ssh.HostCert, Key: sshPubKey, ValidPrincipals: []string{"192.168.1.101"}, ValidBefore: uint64(certValidity),
	}
	err = cert.SignCert(rand.Reader, signer)
	if err != nil {
		return err
	}

	privateKeyBytes = encodePrivateKeyToPEM(privKey)
	err = writeKeyToFile(privateKeyBytes, "nopush/host-ssh-key")
	if err != nil {
		log.Fatal(err.Error())
	}

	err = writeKeyToFile([]byte(pubKey), "nopush/host-ssh-key.pub")
	if err != nil {
		log.Fatal(err.Error())
	}
	hostcert, err := os.Create("nopush/host-ssh-key-cert.pub")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer hostcert.Close()
	hostcert.WriteString(fmt.Sprintf("ssh-rsa-cert-v01@openssh.com %s hostnameIguess", base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(cert.Marshal())))

	return nil
}

func generateSSHCA(ca *x509.Certificate) error {
	return nil
}

// Host ssh cert
// identitiy the certificate's identity — an alphanumeric string that will identify the server. I recommend using the server's hostname. This value can also be used to revoke a certificate in future if needed.
// principal If you have DNS set up, you should use the server's FQDN (for example host.example.com) here. If not, use the hostname that you will be using in an ~/.ssh/config file to connect to the server.
// client ssh cert
// identity an alphanumeric string that will be visible in SSH logs when the user certificate is presented. I recommend using the email address or internal username of the user that the certificate is for — something which will allow you to uniquely identify a user.
// principals specifies a comma-separated list of principals that the certificate will be valid for authenticating, i.e. the *nix users which this certificate should be allowed to log in as.
// Certs for
// all infrastructure access including SSH, RDP, Kubernetes clusters, web applications, and database access

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"

	memory "github.com/hslatman/certmagic-memory-storage"
)

var (
	directory string
	root      string
	secret    string
)

type request struct {
	Challenge     string `json:"scepChallenge"`
	TransactionID string `json:"scepTransactionID"`
}

type response struct {
	Allow bool `json:"allow"`
}

func main() {

	flag.StringVar(&directory, "", "https://127.0.0.1:8443/acme/acme/directory", "The ACME directory URL to use")
	flag.StringVar(&root, "root", "", "Path to the root certificate to trust")
	flag.StringVar(&secret, "secret", "", "The webhook shared secret")
	flag.Parse()

	signingSecret, err := base64.StdEncoding.DecodeString(secret)
	fatalIf(err)

	pool, err := prepareTrustedRootPool()
	fatalIf(err)

	// create CertMagic configuration and start managing certificates
	cm := prepareCertMagic(pool)
	err = cm.ManageSync(context.Background(), []string{"127.0.0.1", "localhost"})
	fatalIf(err)

	list, err := cm.Storage.List(context.Background(), "", true)
	fatalIf(err)
	_ = list

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Post("/*", func(w http.ResponseWriter, r *http.Request) {

		dr, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("request:\n%s\n\n", string(dr))

		webhookID, err := getWebhookID(r)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = webhookID // NOTE: the webhook ID can be checked and/or used to select the right signing secret

		_ = r.TLS.PeerCertificates // NOTE: with `tls.RequireAndVerifyClientCert`, the CA will send its client certificate

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		req := &request{}
		err = json.Unmarshal(body, req)
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if signingSecret != nil { // NOTE: validating the request body signature is optional in this example
			if err = validateSignature(r, body, signingSecret); err != nil {
				log.Println(err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		log.Printf("%#+v\n", req)

		if req.Challenge != "" { // NOTE: try parsing a JWT; otherwise print the challenge value
			tok, err := jose.ParseJWS(req.Challenge)
			if err == nil {
				if err = printToken(tok); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			} else {
				fmt.Println(req.Challenge)
			}
		}

		b, err := json.Marshal(response{Allow: true}) // NOTE: this example always allows the request
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(200)
		w.Write(b)
	})

	tlsConfig := cm.TLSConfig()
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
	tlsConfig.ClientCAs = pool
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

	server := http.Server{
		Addr:      ":8081",
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	server.ListenAndServeTLS("", "")
}

func fatalIf(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func prepareTrustedRootPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if root != "" {
		roots, err := pemutil.ReadCertificateBundle(root)
		if err != nil {
			return nil, err
		}
		for _, root := range roots {
			pool.AddCert(root)
		}
	}
	return pool, nil
}

func prepareCertMagic(trustedRoots *x509.CertPool) *certmagic.Config {
	// see https://github.com/caddyserver/certmagic/pull/198/files
	var cache *certmagic.Cache
	cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.New(cache, certmagic.Config{}), nil
		},
		RenewCheckInterval: time.Minute,
	})
	cm := certmagic.New(cache, certmagic.Default)
	cm.Storage = memory.New()
	issuer := certmagic.NewACMEIssuer(cm, certmagic.ACMEIssuer{
		CA:           directory,
		TestCA:       directory,
		Email:        "someone@example.com",
		Agreed:       true,
		TrustedRoots: trustedRoots,
	})
	cm.Issuers = append(cm.Issuers, issuer)
	return cm
}

func validateSignature(r *http.Request, body []byte, signingSecret []byte) error {
	sig, err := hex.DecodeString(r.Header.Get("X-Smallstep-Signature"))
	if err != nil {
		return fmt.Errorf("invalid X-Smallstep-Signature header: %w", err)
	}

	mac := hmac.New(sha256.New, signingSecret).Sum(body)
	if ok := hmac.Equal(sig, mac); !ok {
		return errors.New("failed to verify request signature")
	}

	return nil
}

func getWebhookID(r *http.Request) (id string, err error) {
	if id := r.Header.Get("X-Smallstep-Webhook-ID"); id == "" {
		err = errors.New("X-Smallstep-Webhook-ID header missing")
	}
	return id, err
}

func printToken(tok *jose.JSONWebSignature) error {
	token, err := tok.CompactSerialize()
	if err != nil {
		return fmt.Errorf("error serializing token: %w", jose.TrimPrefix(err))
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("error decoding token: JWT must have three parts")
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("error decoding token: %w", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("error decoding token: %w", err)
	}

	m := make(map[string]json.RawMessage)
	m["header"] = header
	m["payload"] = payload
	m["signature"] = []byte(`"` + parts[2] + `"`)

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling token data: %w", err)
	}

	fmt.Println(string(b))
	return nil
}

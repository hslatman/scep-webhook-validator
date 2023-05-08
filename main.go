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
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/spf13/afero"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/pemutil"
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

	// see https://github.com/caddyserver/certmagic/pull/198/files
	var cache *certmagic.Cache
	cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(cert certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.New(cache, certmagic.Config{}), nil
		},
		RenewCheckInterval: time.Minute,
	})
	cm := certmagic.New(cache, certmagic.Default)
	cm.Storage = newMemoryStorage()
	issuer := certmagic.NewACMEIssuer(cm, certmagic.ACMEIssuer{
		CA:           directory,
		TestCA:       directory,
		Email:        "someone@example.com",
		Agreed:       true,
		TrustedRoots: pool,
	})

	cm.Issuers = append(cm.Issuers, issuer)

	// start managing certificates
	err = cm.ManageSync(context.Background(), []string{"127.0.0.1", "localhost"})
	fatalIf(err)

	tlsConfig := cm.TLSConfig()
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)
	tlsConfig.ClientCAs = pool
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

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
				token, err := tok.CompactSerialize()
				if err != nil {
					err = fmt.Errorf("error serializing token: %w", jose.TrimPrefix(err))
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				printToken(token)
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

func printToken(token string) error {
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

// memoryStorage is an in-memory implementation of certmagic.Storage
// TODO(hs): verify atomic operations; tests.
type memoryStorage struct {
	fs afero.Fs
	l  sync.Mutex
}

func newMemoryStorage() *memoryStorage {
	return &memoryStorage{
		fs: afero.NewMemMapFs(),
	}
}

func (m *memoryStorage) Lock(ctx context.Context, name string) error {
	m.l.Lock() // TODO: lock to be specific for name
	return nil
}

func (m *memoryStorage) Unlock(ctx context.Context, name string) error {
	m.l.Unlock() // TODO: unlock to be specific for name
	return nil
}

func (m *memoryStorage) Store(ctx context.Context, key string, value []byte) error {
	filename := m.filename(key)
	if err := m.fs.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return err
	}
	return afero.WriteFile(m.fs, filename, value, 0600)
}

func (m *memoryStorage) Load(ctx context.Context, key string) ([]byte, error) {
	filename := m.filename(key)
	return afero.ReadFile(m.fs, filename)
}

func (m *memoryStorage) Exists(ctx context.Context, key string) bool {
	_, err := m.fs.Stat(m.filename(key))
	return !errors.Is(err, fs.ErrNotExist)
}

func (m *memoryStorage) Delete(ctx context.Context, key string) error {
	filename := m.filename(key)
	return m.fs.Remove(filename)
}

func (m *memoryStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	result := []string{}
	walkFn := func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() {
			result = append(result, path)
		}
		return nil
	}
	err := afero.Walk(m.fs, ".", walkFn) // TODO: handle prefix and recursive correctly
	return result, err
}

func (m *memoryStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	filename := m.filename(key)
	result := certmagic.KeyInfo{}
	info, err := m.fs.Stat(filename)
	if err != nil {
		return result, err
	}
	result.Key = key
	result.IsTerminal = !info.IsDir()
	result.Modified = info.ModTime()
	result.Size = info.Size()
	return result, nil
}

func (m *memoryStorage) filename(key string) string {
	return key
}

var _ certmagic.Storage = (*memoryStorage)(nil)

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const maxRequestSize = 1 << 20

type config struct {
	listenAddress           string
	apiTokenFile            string
	keyPasswordFile         string
	caURL                   string
	caRoot                  string
	sshUserCA               string
	sshHostCA               string
	provisioner             string
	provisionerPasswordFile string
	artifactDirectory       string
	caService               string
	ldapURL                 string
	ldapUPNSuffix           string
	ldapTimeout             time.Duration
}

type api struct {
	config           config
	token            string
	authenticateLDAP func(context.Context, string, string) error
}

type authenticatedUserContextKey struct{}

var errInvalidCredentials = errors.New("invalid LDAP credentials")

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

type x509Request struct {
	Subject  string   `json:"subject"`
	SANs     []string `json:"sans"`
	Duration string   `json:"duration"`
}

type sshRequest struct {
	KeyID      string   `json:"key_id"`
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals"`
	Duration   string   `json:"duration"`
	Host       bool     `json:"host"`
}

type actionRequest struct {
	Action string `json:"action"`
}

func main() {
	cfg := config{
		listenAddress:           env("LISTEN_ADDRESS", ":8080"),
		apiTokenFile:            env("API_TOKEN_FILE", "/etc/step-ca-api/token"),
		keyPasswordFile:         env("KEY_PASSWORD_FILE", "/etc/step-ca-api/key-password"),
		caURL:                   env("CA_URL", "https://127.0.0.1:9000"),
		caRoot:                  env("CA_ROOT", "/etc/step-ca/certs/root_ca.crt"),
		sshUserCA:               env("SSH_USER_CA", "/etc/step-ca/certs/ssh_user_ca_key.pub"),
		sshHostCA:               env("SSH_HOST_CA", "/etc/step-ca/certs/ssh_host_ca_key.pub"),
		provisioner:             env("PROVISIONER", "admin"),
		provisionerPasswordFile: env("PROVISIONER_PASSWORD_FILE", "/etc/step-ca/secrets/provisioner-password.txt"),
		artifactDirectory:       env("ARTIFACT_DIRECTORY", "/var/lib/step-ca-api/artifacts"),
		caService:               env("CA_SERVICE", "step-ca.service"),
		ldapURL:                 env("LDAP_URL", "ldap://vattar.ice.land:389"),
		ldapUPNSuffix:           env("LDAP_UPN_SUFFIX", "ice.land"),
		ldapTimeout:             envDuration("LDAP_TIMEOUT", 5*time.Second),
	}

	tokenBytes, err := os.ReadFile(cfg.apiTokenFile)
	if err != nil {
		log.Fatalf("read API token: %v", err)
	}
	if err := os.MkdirAll(cfg.artifactDirectory, 0700); err != nil {
		log.Fatalf("create artifact directory: %v", err)
	}

	a := &api{config: cfg, token: strings.TrimSpace(string(tokenBytes))}
	a.authenticateLDAP = a.bindLDAP
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.index)
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/trust/root.pem", a.rootCertificate)
	mux.HandleFunc("/trust/ssh-user-ca.pub", a.sshUserCAPublicKey)
	mux.HandleFunc("/trust/ssh-host-ca.pub", a.sshHostCAPublicKey)
	mux.Handle("/v1/ca", a.authorize(http.HandlerFunc(a.caStatus)))
	mux.Handle("/v1/ca/action", a.authorize(http.HandlerFunc(a.caAction)))
	mux.Handle("/v1/certificates/x509", a.authorize(http.HandlerFunc(a.issueX509)))
	mux.Handle("/v1/certificates/ssh", a.authorize(http.HandlerFunc(a.issueSSH)))

	server := &http.Server{
		Addr:              cfg.listenAddress,
		Handler:           requestLogger(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      45 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("step-ca API listening on %s", cfg.listenAddress)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		log.Fatalf("parse %s: %v", name, err)
	}
	return duration
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		response := &loggingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(response, r)
		log.Printf("method=%s path=%s status=%d bytes=%d remote=%s duration=%s",
			r.Method, r.URL.Path, response.status, response.bytes, r.RemoteAddr,
			time.Since(start).Round(time.Millisecond))
	})
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(contents []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(contents)
	w.bytes += written
	return written, err
}

func (a *api) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if len(provided) != len(a.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(a.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}

		username, password, ok := r.BasicAuth()
		username = strings.TrimSpace(username)
		if !ok || username == "" || password == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="ice.land"`)
			writeError(w, http.StatusUnauthorized, "domain username and password are required")
			return
		}
		bindUsername := a.ldapBindUsername(username)
		if err := a.authenticateLDAP(r.Context(), bindUsername, password); err != nil {
			if errors.Is(err, errInvalidCredentials) {
				log.Printf("LDAP authentication rejected user=%q remote=%q", bindUsername, r.RemoteAddr)
				writeError(w, http.StatusUnauthorized, "invalid domain credentials")
				return
			}
			log.Printf("LDAP authentication unavailable user=%q remote=%q error=%q", bindUsername, r.RemoteAddr, err)
			writeError(w, http.StatusServiceUnavailable, "domain authentication unavailable")
			return
		}

		ctx := context.WithValue(r.Context(), authenticatedUserContextKey{}, bindUsername)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *api) ldapBindUsername(username string) string {
	if strings.ContainsAny(username, "@\\") || a.config.ldapUPNSuffix == "" {
		return username
	}
	return username + "@" + a.config.ldapUPNSuffix
}

func (a *api) bindLDAP(_ context.Context, username, password string) error {
	dialer := &net.Dialer{Timeout: a.config.ldapTimeout}
	connection, err := ldap.DialURL(a.config.ldapURL, ldap.DialWithDialer(dialer))
	if err != nil {
		return fmt.Errorf("connect to LDAP: %w", err)
	}
	defer connection.Close()
	connection.SetTimeout(a.config.ldapTimeout)
	if err := connection.Bind(username, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return errInvalidCredentials
		}
		return fmt.Errorf("LDAP bind: %w", err)
	}
	return nil
}

func authenticatedUser(ctx context.Context) string {
	username, _ := ctx.Value(authenticatedUserContextKey{}).(string)
	return username
}

func (a *api) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || r.Method != http.MethodGet {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":                    "Flokie Step CA API",
		"public_endpoints":        []string{"GET /health", "GET /trust/root.pem", "GET /trust/ssh-user-ca.pub", "GET /trust/ssh-host-ca.pub"},
		"authenticated_endpoints": []string{"GET /v1/ca", "POST /v1/ca/action", "POST /v1/certificates/x509", "POST /v1/certificates/ssh"},
	})
}

func (a *api) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *api) rootCertificate(w http.ResponseWriter, r *http.Request) {
	a.serveTrustFile(w, r, a.config.caRoot, "application/x-pem-file")
}

func (a *api) sshUserCAPublicKey(w http.ResponseWriter, r *http.Request) {
	a.serveTrustFile(w, r, a.config.sshUserCA, "text/plain; charset=utf-8")
}

func (a *api) sshHostCAPublicKey(w http.ResponseWriter, r *http.Request) {
	a.serveTrustFile(w, r, a.config.sshHostCA, "text/plain; charset=utf-8")
}

func (a *api) serveTrustFile(w http.ResponseWriter, r *http.Request, path, contentType string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(contents)
}

func (a *api) caStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemctl", "is-active", a.config.caService).CombinedOutput()
	active := err == nil && strings.TrimSpace(string(output)) == "active"
	writeJSON(w, http.StatusOK, map[string]any{
		"service": a.config.caService,
		"active":  active,
		"state":   strings.TrimSpace(string(output)),
		"ca_url":  a.config.caURL,
	})
}

func (a *api) caAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request actionRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}
	if request.Action != "start" && request.Action != "stop" && request.Action != "restart" {
		writeError(w, http.StatusBadRequest, "action must be start, stop, or restart")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemctl", request.Action, a.config.caService).CombinedOutput()
	if err != nil {
		message := commandError(err, output)
		log.Printf("CA action failed authenticated_user=%q action=%q error=%q", authenticatedUser(r.Context()), request.Action, message)
		writeError(w, http.StatusInternalServerError, message)
		return
	}
	log.Printf("CA action completed authenticated_user=%q action=%q", authenticatedUser(r.Context()), request.Action)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "action": request.Action})
}

func (a *api) issueX509(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request x509Request
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}
	request.Subject = strings.TrimSpace(request.Subject)
	if request.Subject == "" || len(request.Subject) > 255 || len(request.SANs) > 32 {
		writeError(w, http.StatusBadRequest, "subject is required and at most 32 SANs are allowed")
		return
	}
	if request.Duration == "" {
		request.Duration = "2h"
	}

	id, directory, err := a.newArtifactDirectory()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	certificatePath := filepath.Join(directory, "certificate.pem")
	privateKeyPath := filepath.Join(directory, "private-key.pem")
	args := []string{
		"ca", "certificate", request.Subject, certificatePath, privateKeyPath,
		"--ca-url=" + a.config.caURL,
		"--root=" + a.config.caRoot,
		"--provisioner=" + a.config.provisioner,
		"--provisioner-password-file=" + a.config.provisionerPasswordFile,
		"--password-file=" + a.config.keyPasswordFile,
		"--not-after=" + request.Duration,
		"--force",
	}
	for _, san := range request.SANs {
		if strings.TrimSpace(san) != "" {
			args = append(args, "--san="+strings.TrimSpace(san))
		}
	}
	if output, err := a.runStep(r.Context(), args...); err != nil {
		_ = os.RemoveAll(directory)
		message := commandError(err, output)
		log.Printf("X.509 issuance failed authenticated_user=%q subject=%q sans=%q duration=%q error=%q",
			authenticatedUser(r.Context()), request.Subject, request.SANs, request.Duration, message)
		writeError(w, http.StatusBadRequest, message)
		return
	}

	certificate, certErr := os.ReadFile(certificatePath)
	privateKey, keyErr := os.ReadFile(privateKeyPath)
	keyPassword, passwordErr := os.ReadFile(a.config.keyPasswordFile)
	if certErr != nil || keyErr != nil || passwordErr != nil {
		log.Printf("X.509 artifact read failed id=%q cert_error=%v key_error=%v password_error=%v",
			id, certErr, keyErr, passwordErr)
		writeError(w, http.StatusInternalServerError, "certificate was issued but its artifacts could not be read")
		return
	}
	log.Printf("X.509 certificate issued authenticated_user=%q id=%q subject=%q sans=%q duration=%q",
		authenticatedUser(r.Context()), id, request.Subject, request.SANs, request.Duration)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "subject": request.Subject, "sans": request.SANs,
		"certificate": string(certificate), "private_key": string(privateKey),
		"private_key_password": strings.TrimSpace(string(keyPassword)),
	})
}

func (a *api) issueSSH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request sshRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}
	request.KeyID = strings.TrimSpace(request.KeyID)
	request.PublicKey = strings.TrimSpace(request.PublicKey)
	if request.KeyID == "" || request.PublicKey == "" || len(request.Principals) == 0 || len(request.Principals) > 16 {
		writeError(w, http.StatusBadRequest, "key_id, public_key, and 1-16 principals are required")
		return
	}
	if request.Duration == "" {
		request.Duration = "2h"
	}

	id, directory, err := a.newArtifactDirectory()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	publicKeyPath := filepath.Join(directory, "identity.pub")
	if err := os.WriteFile(publicKeyPath, []byte(request.PublicKey+"\n"), 0600); err != nil {
		_ = os.RemoveAll(directory)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	args := []string{
		"ssh", "certificate", "--sign", "--force",
		"--ca-url=" + a.config.caURL,
		"--root=" + a.config.caRoot,
		"--provisioner=" + a.config.provisioner,
		"--provisioner-password-file=" + a.config.provisionerPasswordFile,
		"--not-after=" + request.Duration,
	}
	if request.Host {
		args = append(args, "--host")
	}
	for _, principal := range request.Principals {
		if strings.TrimSpace(principal) != "" {
			args = append(args, "--principal="+strings.TrimSpace(principal))
		}
	}
	args = append(args, request.KeyID, publicKeyPath)
	if output, err := a.runStep(r.Context(), args...); err != nil {
		_ = os.RemoveAll(directory)
		message := commandError(err, output)
		log.Printf("SSH issuance failed authenticated_user=%q key_id=%q principals=%q host=%t duration=%q error=%q",
			authenticatedUser(r.Context()), request.KeyID, request.Principals, request.Host, request.Duration, message)
		writeError(w, http.StatusBadRequest, message)
		return
	}

	certificatePath := strings.TrimSuffix(publicKeyPath, ".pub") + "-cert.pub"
	certificate, err := os.ReadFile(certificatePath)
	if err != nil {
		log.Printf("SSH artifact read failed id=%q path=%q error=%q", id, certificatePath, err)
		writeError(w, http.StatusInternalServerError, "SSH certificate was issued but could not be read")
		return
	}
	log.Printf("SSH certificate issued authenticated_user=%q id=%q key_id=%q principals=%q host=%t duration=%q",
		authenticatedUser(r.Context()), id, request.KeyID, request.Principals, request.Host, request.Duration)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "key_id": request.KeyID, "principals": request.Principals,
		"host": request.Host, "certificate": strings.TrimSpace(string(certificate)),
	})
}

func (a *api) newArtifactDirectory() (string, string, error) {
	id := strconv.FormatInt(time.Now().UnixNano(), 36)
	directory := filepath.Join(a.config.artifactDirectory, id)
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", "", err
	}
	return id, directory, nil
}

func (a *api) runStep(parent context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "step", args...)
	command.Env = append(os.Environ(), "STEPPATH=/etc/step-ca")
	return command.CombinedOutput()
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain one JSON object")
		return errors.New("multiple JSON values")
	}
	return nil
}

func commandError(err error, output []byte) string {
	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}
	return message
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

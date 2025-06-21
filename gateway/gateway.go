package gateway

import (
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

type HTTPClientInterface interface {
	Get(url string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
	Transport() http.RoundTripper
	SetTransport(transport http.RoundTripper)
}

type HTTPClientWrapper struct {
	Client *http.Client
}

func (w *HTTPClientWrapper) Get(url string) (*http.Response, error) {
	return w.Client.Get(url)
}

func (w *HTTPClientWrapper) Do(req *http.Request) (*http.Response, error) {
	return w.Client.Do(req)
}

func (w *HTTPClientWrapper) Transport() http.RoundTripper {
	return w.Client.Transport
}

func (w *HTTPClientWrapper) SetTransport(transport http.RoundTripper) {
	w.Client.Transport = transport
}

type GatewayClient struct {
	BaseURL    string
	HTTPClient HTTPClientInterface
}

const (
	deviceEndpoint             = "/api/v1/device"
	loginParamsEndpoint        = "/api/v1/login-params"
	loginEndpoint              = "/api/v1/login"
	authenticatedEndpoint      = "/api/v1/authenticated"
	getUserEndpoint            = "/api/v1/get_user"
	resetWanConnectionEndpoint = "/api/v1/wan/reset/connection"
)

// GatewayCheck defines the expected values for a gateway device
type GatewayCheck struct {
	ModelName    string
	Manufacturer string
}

func NewGatewayClient(baseURL string) *GatewayClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 // gateway has a self-signed certificate
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	client := &http.Client{Jar: jar, Transport: tr}
	return &GatewayClient{
		BaseURL:    baseURL,
		HTTPClient: &HTTPClientWrapper{Client: client},
	}
}

func (g *GatewayClient) Debug() {
	debugHttpClient(g.HTTPClient)
}

// LoginParams holds the values needed for login step 2.
type LoginParams struct {
	Salt  string
	Nonce string
}

func (g *GatewayClient) RequestURL(endpoint string) string {
	return g.BaseURL + endpoint
}

// GetLoginParams performs the login-params request and extracts salt and nonce cookies.
func (g *GatewayClient) GetLoginParams(username string) (*LoginParams, error) {
	loginParamData := url.Values{}
	loginParamData.Set("login", username)
	requestBody := loginParamData.Encode()

	req, err := http.NewRequest("POST", g.RequestURL(loginParamsEndpoint), strings.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("error creating login-params request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending login-params request: %w", err)
	}
	defer resp.Body.Close() // nolint:errcheck

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login-params request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var salt, nonce string
	for _, cookieHeader := range resp.Header["Set-Cookie"] {
		cookie, err := http.ParseSetCookie(cookieHeader)
		if err != nil {
			return nil, fmt.Errorf("error parsing Set-Cookie header: %w", err)
		}
		switch cookie.Name {
		case "nonce":
			nonce = cookie.Value
		case "salt":
			salt = cookie.Value
		}
	}
	if nonce == "" || salt == "" {
		return nil, fmt.Errorf("expected nonce and salt cookies in login-params response, got nonce: %s, salt: %s", nonce, salt)
	}

	logrus.WithFields(logrus.Fields{
		"salt":  salt,
		"nonce": nonce,
	}).Debug("Extracted cookies")
	return &LoginParams{Salt: salt, Nonce: nonce}, nil
}

func (g *GatewayClient) Login(password string) error {
	username, err := g.GetUser()
	if err != nil {
		return fmt.Errorf("error getting username: %w", err)
	}
	logrus.WithField("username", username).Debug("Using username")

	client := g.HTTPClient

	// Step 1: Get login parameters
	loginParams, err := g.GetLoginParams(username)
	if err != nil {
		logrus.Debugf("Error getting login parameters: %v", err)
		return err
	}
	salt := loginParams.Salt
	nonce := loginParams.Nonce

	// Calculate authentication parameters
	saltedPasswordFull := calculateSaltedPassword(salt, password)

	// Apply the substring(3) logic from APISessionManager.js
	var saltedPasswordSubstring string
	if len(saltedPasswordFull) >= 3 {
		saltedPasswordSubstring = saltedPasswordFull[3:]
	} else {
		return fmt.Errorf("calculated salted password is too short (%d) to take substring from index 3", len(saltedPasswordFull))
	}

	cnonce := generateCNonce()

	hashedCredentialsInput := username + ":" + nonce + ":" + saltedPasswordSubstring
	hashedCredentialsBytes := sha512.Sum512([]byte(hashedCredentialsInput))
	hashedCredentials := hex.EncodeToString(hashedCredentialsBytes[:])

	authKeyInput := hashedCredentials + ":0:" + cnonce // The ":0:" is explicitly from the JS code
	authKeyBytes := sha512.Sum512([]byte(authKeyInput))
	authKey := hex.EncodeToString(authKeyBytes[:])

	logrus.WithField("auth_key", authKey).Debug("Calculated auth_key")
	logrus.WithField("cnonce", cnonce).Debug("Generated cnonce")

	// Step 2: Perform login
	loginData := url.Values{}
	loginData.Set("login", username)
	loginData.Set("auth_key", authKey)
	loginData.Set("cnonce", cnonce)

	requestBody := loginData.Encode()
	req, err := http.NewRequest("POST", g.RequestURL(loginEndpoint), strings.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("error creating login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending login request: %w", err)
	}
	defer resp.Body.Close() // nolint:errcheck

	// Check login response status
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}
	logrus.Info("Login successful")
	return nil
}

func (g *GatewayClient) CheckCompatibility() error {
	expected := GatewayCheck{
		ModelName:    "BGW530-900",
		Manufacturer: "Sagemcom",
	}
	deviceURL := g.RequestURL(deviceEndpoint)
	resp, err := g.HTTPClient.Get(deviceURL)
	if err != nil {
		return fmt.Errorf("failed to GET %s: %w", deviceURL, err)
	}
	defer resp.Body.Close() // nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, deviceURL)
	}

	var devices []struct {
		Device struct {
			ModelName    string `json:"modelname"`
			Manufacturer string `json:"manufacturer"`
		} `json:"device"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		return fmt.Errorf("failed to decode device JSON: %w", err)
	}
	if len(devices) == 0 {
		return fmt.Errorf("no device info returned from %s", deviceURL)
	}
	device := devices[0].Device

	if device.ModelName != expected.ModelName {
		return fmt.Errorf("modelname mismatch: got %q, want %q", device.ModelName, expected.ModelName)
	}
	if device.Manufacturer != expected.Manufacturer {
		return fmt.Errorf("manufacturer mismatch: got %q, want %q", device.Manufacturer, expected.Manufacturer)
	}
	logrus.WithFields(logrus.Fields{
		"modelname":    device.ModelName,
		"manufacturer": device.Manufacturer,
	}).Info("Gateway compatible")
	return nil
}

// IsAuthenticated checks if the current session is authenticated.
// Returns true if authenticated (HTTP 200), false if not (HTTP 401), error otherwise.
func (g *GatewayClient) IsAuthenticated() (bool, error) {
	authURL := g.RequestURL(authenticatedEndpoint)
	resp, err := g.HTTPClient.Get(authURL)
	if err != nil {
		return false, fmt.Errorf("failed to GET %s: %w", authURL, err)
	}
	defer resp.Body.Close() // nolint:errcheck

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected status %d from %s: %s", resp.StatusCode, authURL, string(body))
	}
}

// GetUser fetches the user value from /api/v1/get_user.
// Returns the username (e.g., "admin") or an error.
func (g *GatewayClient) GetUser() (string, error) {
	getUserURL := g.BaseURL + getUserEndpoint
	resp, err := g.HTTPClient.Get(getUserURL)
	if err != nil {
		return "", fmt.Errorf("failed to GET %s: %w", getUserURL, err)
	}
	defer resp.Body.Close() // nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status %d from %s: %s", resp.StatusCode, getUserURL, string(body))
	}

	var result []struct {
		Users []struct {
			User string `json:"user"`
			Role string `json:"role"`
		} `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode get_user JSON: %w", err)
	}
	if len(result) == 0 || len(result[0].Users) == 0 {
		return "", fmt.Errorf("no user info returned from %s", getUserURL)
	}
	return result[0].Users[0].User, nil
}

func (g *GatewayClient) ResetWanConnection() error {
	routerURL := g.BaseURL

	req, err := http.NewRequest("POST", routerURL+resetWanConnectionEndpoint, nil)
	if err != nil {
		return fmt.Errorf("error preparing WAN reset request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.HTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, io.EOF) { // XXX: this is odd, but that's how it works on my gateway
			logrus.Info("Successfully reset WAN connection")
			return nil
		}
		return fmt.Errorf("error sending WAN reset request: %w", err)
	}
	defer resp.Body.Close() // nolint:errcheck

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logrus.Info("Successfully reset WAN connection")
		return nil
	}

	return fmt.Errorf("failed to reset WAN connection: status %d", resp.StatusCode)
}

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// It implements the functionality to retrieve a SAML token using xdg-open.
type XdgOpenSaml struct {
	// Parameters and options preserved exactly as in the original Java code.
	server              string // The server to call (positional parameter)
	port                int    // Port to listen for redirect (option --port / -p)
	realm               string // The authentication realm (option --realm / -r), Optional
	trustAllCertificate bool   // Option to ignore SSL certificate validation (--trust-all / -t)
}

const ID_PARAMETER_NAME string = "id"
const COOKIE_NAME string = "SVPNCOOKIE"

func main() {

	x := &XdgOpenSaml{}

	flag.StringVar(&x.server, "server", "", "The server to call")
	flag.IntVar(&x.port, "port", 8020, "Port to listen for redirect")
	flag.StringVar(&x.realm, "realm", "", "The authentication realm")
	flag.BoolVar(&x.trustAllCertificate, "trust-all", false, "Ignore SSL certificate validation")
	flag.Parse()

	if x.server == "" {
		log.Fatalf("Server parameter is required")
		os.Exit(1)
	}
	exitCode, err := x.Call()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(exitCode)
}

// Call is the main business logic method equivalent to the Java call() method.
func (x *XdgOpenSaml) Call() (int, error) {
	// Build the server URL.
	serverUrl := "https://" + x.server

	// Retrieve the cookie from the server.
	cookie, err := x.retrieveCookie(serverUrl)
	if err != nil {
		return 1, err
	}

	fmt.Println(cookie)
	return 0, nil
}

// result is used to mimic CompletableFuture's result handling.
type result struct {
	cookie string
	err    error
}

// retrieveCookie creates an HTTP server, launches the xdg-open command,
// and waits for the SAML redirect to capture the cookie.
func (x *XdgOpenSaml) retrieveCookie(urlStr string) (string, error) {
	// Get local address "127.0.0.1"
	localAddress := "127.0.0.1"
	addr := net.JoinHostPort(localAddress, strconv.Itoa(x.port))

	// Create a channel to receive the cookie result.
	cookieResult := make(chan result, 1)

	// Create HTTP server with the CookieRetrieverHttpHandler.
	handler := &CookieRetrieverHttpHandler{
		cookieResult:        cookieResult,
		url:                 urlStr,
		trustAllCertificate: x.trustAllCertificate,
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	// Start listening.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	// Start the HTTP server in a separate goroutine.
	go func() {
		srv.Serve(listener)
	}()

	// Execute the xdg-open command.
	// Construct the URL with optional realm parameter.
	urlBuilder := strings.Builder{}
	urlBuilder.WriteString(urlStr)
	urlBuilder.WriteString("/remote/saml/start?redirect=1")
	if x.realm != "" {
		urlBuilder.WriteString("&realm=")
		urlBuilder.WriteString(x.realm)
	}
	cmdStr := urlBuilder.String()
	cmd := exec.Command("xdg-open", cmdStr)
	err = cmd.Start()
	if err != nil {
		// Stop the server before returning.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		return "", err
	}

	// Wait up to 5 minutes for the cookie.
	select {
	case res := <-cookieResult:
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		return res.cookie, res.err
	case <-time.After(5 * time.Minute):
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		return "", fmt.Errorf("timeout waiting for cookie")
	}
}

// CookieRetrieverHttpHandler is the HTTP handler to capture the cookie from the redirect.
type CookieRetrieverHttpHandler struct {
	cookieResult        chan result
	url                 string
	trustAllCertificate bool
}

// ServeHTTP processes the incoming HTTP request.
func (h *CookieRetrieverHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Wrap in a closure to handle panic and error similar to try-catch.
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				errMsg := fmt.Sprintf("%v", rec)
				sendResponse(w, 500, errMsg)
				h.cookieResult <- result{cookie: "", err: fmt.Errorf("%s", errMsg)}
			}
		}()
		// Extract the query string from the URL.
		query := r.URL.RawQuery
		if idPtr := extractId(query); idPtr != nil {
			// If the id parameter is present, retrieve the cookie using it.
			cookie, err := h.retrieveCookieFromId(*idPtr)
			if err == nil {
				sendResponse(w, 200, "XdgOpenSaml Retrieved Cookie! Connecting ...")
				h.cookieResult <- result{cookie: cookie, err: nil}
			} else {
				sendResponse(w, 500, err.Error())
				h.cookieResult <- result{cookie: "", err: err}
			}
		} else {
			// If the id parameter is missing, send error response.
			errorMessage := "ERROR: Redirect does not contain \"" + ID_PARAMETER_NAME + "\" parameter " + r.URL.String()
			sendResponse(w, 500, errorMessage)
			h.cookieResult <- result{cookie: "", err: fmt.Errorf("%s", errorMessage)}
		}
	}()
}

// extractId processes the request query and extracts the id parameter value.
// It mimics the Java implementation which returns the substring starting from '='.
func extractId(requestQuery string) *string {
	parts := strings.Split(requestQuery, "&")
	for _, s := range parts {
		if strings.HasPrefix(s, ID_PARAMETER_NAME) {
			idx := strings.Index(s, "=")
			if idx != -1 {
				value := s[idx:]
				return &value
			}
		}
	}
	return nil
}

// sendResponse writes the HTTP response headers and message.
func sendResponse(w http.ResponseWriter, code int, message string) {
	// In the Java code, the response length is set as message length.
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(code)
	// Write the message to the response body.
	_, err := io.WriteString(w, message)
	if err != nil {
		// Error in sending response to browser; print the error.
		fmt.Println("Error sending response:", err)
	}
}

// retrieveCookieFromId sends an HTTP GET request to obtain the cookie using the id.
func (h *CookieRetrieverHttpHandler) retrieveCookieFromId(id string) (string, error) {
	// Build the request URI.
	reqUri := h.url + "/remote/saml/auth_id?id=" + id
	req, err := http.NewRequest("GET", reqUri, nil)
	if err != nil {
		return "", err
	}
	// Set up TLS configuration.
	tlsConfig := &tls.Config{}
	if h.trustAllCertificate {
		// If trusting all certificates, set InsecureSkipVerify.
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
	}
	// Send the request.
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 400 {
		// If response is successful, extract the cookie.
		cookie, err := extractCookie(resp)
		if err != nil {
			//return "", &CannotRetrieveException{message: "Missing " + COOKIE_NAME + " in response " + resp.Status}
			return "", fmt.Errorf("message: Missing %s in response %s", COOKIE_NAME, resp.Status)
		}
		return cookie, nil
	} else {
		// If status code is error, read the response and return the error.
		bodyBytes, _ := io.ReadAll(resp.Body)
		// return "", &CannotRetrieveException{message: "Error retrieving Cookie [" + strconv.Itoa(resp.StatusCode) + "]\"\n" + string(bodyBytes)}
		return "", fmt.Errorf("message: Error retrieving Cookie [%s]\n %s", strconv.Itoa(resp.StatusCode), string(bodyBytes))
	}
}

// extractCookie examines the response headers for the cookie.
func extractCookie(resp *http.Response) (string, error) {
	// Check all "Set-Cookie" headers.
	cookies := resp.Header["Set-Cookie"]
	for _, s := range cookies {
		if strings.HasPrefix(s, COOKIE_NAME) {
			// Split by ";" and take the first element.
			parts := strings.Split(s, ";")
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("cookie not found")
}

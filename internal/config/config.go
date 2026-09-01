package config

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Config holds application and Omada-specific runtime configuration.
type Config struct {
	Port                       int
	AppEnv                     string
	LogLevel                   string
	OMADABaseURL               string
	OMADAUsername              string
	OMADAPassword              string
	OMADASite                  string
	OMADAControllerID          string
	OMADAAuthPath              string
	OMADAAuthMethod            string
	OMADARevocationPath        string
	AdminToken                 string
	ResidentsAPIURL            string
	EmployeeEnrollmentPassword string
	OMADATLSInsecure           bool
	OMADAMock                  bool
	UsersFile                  string
	PortalSessionTTL           time.Duration
	ClientAuthDuration         time.Duration
	RateLimitRequests          int
	RateLimitWindow            time.Duration
}

func Load() (Config, error) {
	port, err := strconv.Atoi(getEnv("APP_PORT", "8080"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid APP_PORT: %w", err)
	}

	portalTTL, err := time.ParseDuration(getEnv("PORTAL_SESSION_TTL", "5m"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid PORTAL_SESSION_TTL: %w", err)
	}

	authDuration, err := time.ParseDuration(getEnv("CLIENT_AUTH_DURATION", "24h"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid CLIENT_AUTH_DURATION: %w", err)
	}

	limit, err := strconv.Atoi(getEnv("RATE_LIMIT_REQUESTS", "20"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid RATE_LIMIT_REQUESTS: %w", err)
	}

	window, err := time.ParseDuration(getEnv("RATE_LIMIT_WINDOW", "1m"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid RATE_LIMIT_WINDOW: %w", err)
	}

	insecure, err := strconv.ParseBool(getEnv("OMADA_TLS_INSECURE", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid OMADA_TLS_INSECURE: %w", err)
	}
	mock, err := strconv.ParseBool(getEnv("OMADA_MOCK", "false"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid OMADA_MOCK: %w", err)
	}

	return Config{
		Port:                       port,
		AppEnv:                     getEnv("APP_ENV", "development"),
		LogLevel:                   getEnv("LOG_LEVEL", "INFO"),
		OMADABaseURL:               getEnv("OMADA_BASE_URL", "https://192.168.10.X:8043"),
		OMADAUsername:              getEnv("OMADA_USERNAME", ""),
		OMADAPassword:              getEnv("OMADA_PASSWORD", ""),
		OMADASite:                  getEnv("OMADA_SITE", ""),
		OMADAControllerID:          getEnv("OMADA_CONTROLLER_ID", ""),
		OMADAAuthPath:              getEnv("OMADA_AUTHORIZATION_PATH", ""),
		OMADAAuthMethod:            getEnv("OMADA_AUTHORIZATION_METHOD", http.MethodPost),
		OMADARevocationPath:        getEnv("OMADA_REVOCATION_PATH", ""),
		AdminToken:                 getEnv("ADMIN_API_TOKEN", ""),
		ResidentsAPIURL:            getEnv("RESIDENTS_API_URL", "http://localhost:8080/api/residents"),
		EmployeeEnrollmentPassword: getEnv("EMPLOYEE_ENROLLMENT_PASSWORD", ""),
		OMADATLSInsecure:           insecure,
		OMADAMock:                  mock,
		UsersFile:                  getEnv("USERS_FILE", "./users.json"),
		PortalSessionTTL:           portalTTL,
		ClientAuthDuration:         authDuration,
		RateLimitRequests:          limit,
		RateLimitWindow:            window,
	}, nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}

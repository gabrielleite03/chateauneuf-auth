package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"network-auth-service/internal/adapters/omada"
	localrepo "network-auth-service/internal/adapters/repository/local"
	residentrepo "network-auth-service/internal/adapters/repository/residents"
	"network-auth-service/internal/application/auth"
	"network-auth-service/internal/config"
	"network-auth-service/internal/ports"
	"network-auth-service/internal/transport/http"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	repo, err := localrepo.NewRepository(cfg.UsersFile)
	if err != nil {
		panic(err)
	}

	var authorizer ports.NetworkAuthorizer
	var revoker ports.NetworkRevoker
	if cfg.OMADAMock {
		mock := omada.MockNetwork{}
		authorizer, revoker = mock, mock
		logger.Warn("omada_mock_enabled", "warning", "network access is only simulated")
	} else {
		client := omada.NewClient(cfg.OMADABaseURL, cfg.OMADAUsername, cfg.OMADAPassword, cfg.OMADASite, cfg.OMADAControllerID, cfg.OMADAAuthPath, cfg.OMADAAuthMethod, cfg.OMADATLSInsecure, 10*time.Second)
		client.SetRevokePath(cfg.OMADARevocationPath)
		client.SetOpenAPI(cfg.OMADAOpenAPIClientID, cfg.OMADAOpenAPIClientSecret, cfg.OMADAOpenAPIControllerID, cfg.OMADASiteID)
		authorizer, revoker = client, client
	}
	svc := auth.NewService(repo, authorizer, logger, cfg.PortalSessionTTL, cfg.ClientAuthDuration)
	svc.SetEmployeeAuthDuration(cfg.EmployeeAuthDuration)
	accountSvc := auth.NewAccountService(repo, revoker, residentrepo.NewHTTPDirectory(cfg.ResidentsAPIURL))
	accountSvc.SetResidentCredentialNotifier(residentrepo.NewHTTPNotifier(cfg.ResidentCredentialNotifyURL, cfg.InternalAPIToken))
	accountSvc.SetEmployeeEnrollmentPassword(cfg.EmployeeEnrollmentPassword)

	h := transporthttp.NewHandler(svc, logger, cfg.PortalSessionTTL)
	adminHandler := transporthttp.NewAdminHandler(accountSvc, cfg.AdminToken)
	mux := transporthttp.NewRouter(h, adminHandler)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("server_shutdown_failed", "error", err)
		}
	}()

	logger.Info("server_started", "port", cfg.Port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server_failed", "error", err)
		os.Exit(1)
	}
}

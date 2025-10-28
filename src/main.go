package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xmtp/xmtpd/pkg/gateway"
)

const EXPECTED_ISSUER = "convos.org"

var (
	ErrMissingToken     = errors.New("missing JWT token")
	ErrInvalidToken     = errors.New("invalid JWT token")
	ErrInvalidSignature = errors.New("invalid token signature")
	ErrMissingPublicKey = errors.New("JWT_PUBLIC_KEY environment variable not set")
	ErrInvalidPublicKey = errors.New("invalid public key format")
	ErrTokenExpired     = errors.New("token has expired")
)

// parsePublicKey parses a PEM-encoded ECDSA public key
func parsePublicKey(pemKey string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, ErrInvalidPublicKey
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrInvalidPublicKey
	}

	return ecdsaPub, nil
}

// jwtIdentityFn creates an identity function that verifies JWTs using ECDSA
func jwtIdentityFn(publicKey *ecdsa.PublicKey) gateway.IdentityFn {
	return func(ctx context.Context) (gateway.Identity, error) {
		authHeader := gateway.AuthorizationHeaderFromContext(ctx)
		if authHeader == "" {
			return gateway.Identity{}, gateway.NewUnauthenticatedError(
				"Missing JWT token",
				ErrMissingToken,
			)
		}

		claims := jwt.RegisteredClaims{}

		// Parse and verify the token
		token, err := jwt.ParseWithClaims(
			authHeader,
			&claims,
			func(token *jwt.Token) (interface{}, error) {
				// Verify signing method is ECDSA
				if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, gateway.NewPermissionDeniedError(
						"Invalid signing method",
						ErrInvalidSignature,
					)
				}
				return publicKey, nil
			},
			jwt.WithIssuer(EXPECTED_ISSUER),
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{"ES256"}),
		)

		if err != nil {
			return gateway.Identity{}, gateway.NewPermissionDeniedError(
				"failed to validate token",
				err,
			)
		}

		// Extract claims
		if !token.Valid {
			return gateway.Identity{}, gateway.NewPermissionDeniedError(
				"failed to validate token",
				ErrInvalidToken,
			)
		}

		// Use the subject claim (deviceId) as the user identifier
		deviceID, err := claims.GetSubject()
		if err != nil || deviceID == "" {
			return gateway.Identity{}, gateway.NewPermissionDeniedError(
				"failed to get deviceId from token",
				err,
			)
		}

		// Validate token expiration
		if time.Now().After(claims.ExpiresAt.Time) {
			return gateway.Identity{}, gateway.NewPermissionDeniedError(
				"token has expired",
				ErrTokenExpired,
			)
		}

		// Return identity based on JWT claims
		return gateway.NewUserIdentity(deviceID), nil
	}
}

func main() {
	// Load JWT public key from environment
	publicKeyPEM := os.Getenv("JWT_PUBLIC_KEY")
	if publicKeyPEM == "" {
		log.Fatalf("JWT_PUBLIC_KEY environment variable not set")
	}

	// Replace literal \n with actual newlines
	publicKeyPEM = strings.ReplaceAll(publicKeyPEM, "\\n", "\n")

	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		log.Fatalf("Failed to parse JWT public key: %v", err)
	}

	log.Println("✓ JWT authentication configured with ECDSA P-256")
	log.Printf("✓ JWT issuer validation: %s", EXPECTED_ISSUER)

	gatewayService, err := gateway.NewGatewayServiceBuilder(gateway.MustLoadConfig()).
		WithIdentityFn(jwtIdentityFn(publicKey)).
		WithAuthorizers(func(ctx context.Context, identity gateway.Identity, req gateway.PublishRequestSummary) (bool, error) {
			// All authenticated requests are authorized
			// @lourou todo: add rate limiting here
			// Use identity to ratelimit the request
			return true, nil
		}).
		Build()

	if err != nil {
		log.Fatalf("Failed to build gateway service: %v", err)
	}

	log.Println("✓ Gateway service started successfully")
	gatewayService.WaitForShutdown()
}

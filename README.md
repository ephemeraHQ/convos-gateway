# Convos Gateway Service

XMTP payer gateway service for the Convos messaging app with JWT authentication and rate limiting.

## Features

- **JWT Authentication**: ECDSA P-256 signature verification with `convos.org` issuer validation
- **Rate Limiting**: 100 requests per minute per deviceID using Redis
- **Token Expiration**: Automatic validation of JWT expiry times
- **Per-Device Limits**: Each device gets independent rate limit buckets based on JWT subject (deviceID)

## Setup

1. Copy `.env.example` to `.env` and fill in required values:
   - `JWT_PUBLIC_KEY`: ECDSA P-256 public key (PEM format) for JWT verification
   - `XMTPD_REDIS_URL`: Redis connection URL (e.g., `redis://localhost:6777`)
   - Get Alchemy URLs for the XMTP Ropsten chain (APP_CHAIN) and Base Sepolia (SETTLEMENT_CHAIN)
   - Generate a payer private key: `xmtpd-cli keys generate`
   - Set the appropriate XMTP environment for your needs

2. Start Redis:
   ```bash
   docker-compose up -d redis
   ```

3. Run the gateway service:
   - Local development: `./dev/start`
   - Docker: `./dev/up`

## JWT Requirements

The gateway expects JWTs with:
- **Algorithm**: ES256 (ECDSA with P-256)
- **Issuer**: `convos.org`
- **Subject**: deviceID (used for rate limiting)
- **Expiration**: Required and validated

## Rate Limiting

- **Limit**: 100 requests per minute per deviceID
- **Backend**: Redis-based distributed rate limiting
- **Isolation**: Each deviceID gets its own rate limit bucket

To adjust rate limits, modify `rateLimitCapacity` and `rateLimitRefillTime` in `src/main.go`.

## Customizing

This Gateway Service subsidizes publishing to the XMTP network for authenticated Convos users. The authorization logic validates JWTs and enforces per-device rate limits to prevent abuse.

Learn more about customizing Gateway Services [here](https://docs.xmtp.org/fund-agents-apps/run-gateway).

## Installing the xmtpd-cli (optional)

### MacOS
```
brew tap xmtp/tap
brew install xmtpd-cli
```

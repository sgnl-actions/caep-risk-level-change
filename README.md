# CAEP Risk Level Change Event Transmitter

This action transmits CAEP (Continuous Access Evaluation Protocol) Risk Level Change events as Security Event Tokens (SET) to specified receivers. It implements the [OpenID CAEP 1.0 Final specification](https://openid.net/specs/openid-caep-1_0-final.html) for risk level change notifications.

## Overview

The CAEP Risk Level Change event communicates that the risk level associated with a principal has changed. This is used for:
- Triggering step-up authentication when risk increases
- Adjusting access policies based on risk signals
- Notifying downstream systems of compromised credentials or suspicious activity
- Integration with ZScaler and other SSF-compatible receivers

## Prerequisites

- Node.js 22 runtime environment
- Configured authentication (Bearer, Basic, or OAuth2)
- Target receiver endpoint that accepts Security Event Tokens

## Configuration

### Input Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `subject` | text | Yes | Subject identifier JSON (e.g., `{"format":"email","email":"user@example.com"}`) |
| `audience` | text | Yes | Intended recipient of the SET |
| `principal` | text | Yes | Type of principal: `USER`, `DEVICE`, `SESSION`, `TENANT`, `ORG_UNIT`, `GROUP`, or a custom URI |
| `current_level` | text | Yes | Current risk level: `LOW`, `MEDIUM`, `HIGH` |
| `previous_level` | text | No | Previous risk level: `LOW`, `MEDIUM`, `HIGH` |
| `risk_reason` | text | No | Free-text reason (e.g., `PASSWORD_FOUND_IN_DATA_BREACH`) |
| `event_timestamp` | text | No | Unix timestamp (seconds) when the event occurred (defaults to now) |
| `initiating_entity` | text | No | What initiated the change: `admin`, `user`, `policy`, `system` |
| `reason_admin` | text | No | Admin-readable reason (JSON i18n object or plain string) |
| `reason_user` | text | No | User-readable reason (JSON i18n object or plain string) |
| `address` | text | No | Destination URL override (defaults to ADDRESS env var) |

### Outputs

| Name | Type | Description |
|------|------|-------------|
| `status` | text | Operation result: `success` or `failed` |
| `statusCode` | number | HTTP status code from the SET receiver |
| `body` | text | Response body from the SET receiver |
| `retryable` | boolean | Whether the error is retryable |

## Usage Examples

### Basic Risk Level Increase

```json
{
  "subject": "{\"format\":\"email\",\"email\":\"user@example.com\"}",
  "audience": "https://receiver.example.com",
  "principal": "USER",
  "current_level": "HIGH"
}
```

### Full Risk Event with Context

```json
{
  "subject": "{\"format\":\"email\",\"email\":\"user@example.com\"}",
  "audience": "https://receiver.example.com",
  "principal": "DEVICE",
  "current_level": "HIGH",
  "previous_level": "LOW",
  "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH",
  "initiating_entity": "system",
  "reason_admin": "{\"en\":\"Credential compromised in breach\",\"fr\":\"Identifiant compromis\"}",
  "reason_user": "Your password may have been exposed. Please change it immediately."
}
```

## Event Structure

The action creates a CAEP Risk Level Change event following this structure:

```json
{
  "iss": "https://sgnl.ai/",
  "aud": "https://receiver.example.com",
  "iat": 1234567890,
  "jti": "unique-event-id",
  "sub_id": {
    "format": "email",
    "email": "user@example.com"
  },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/risk-level-change": {
      "event_timestamp": 1234567890,
      "principal": "USER",
      "current_level": "HIGH",
      "previous_level": "LOW",
      "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH",
      "initiating_entity": "system",
      "reason_admin": {"en": "Credential compromised"},
      "reason_user": {"en": "Your password may have been exposed"}
    }
  }
}
```

## Error Handling

Retryable errors (automatic retry): 429, 502, 503, 504
Non-retryable errors (permanent failure): 400, 401, 403, 404

## Development

```bash
npm install
npm test
npm run build
npm run lint
npm run validate
```

## References

- [OpenID CAEP 1.0 Final Specification](https://openid.net/specs/openid-caep-1_0-final.html)
- [RFC 8417 - Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)

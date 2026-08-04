const { jest } = import.meta;

// Mock dependencies before importing the script
jest.unstable_mockModule('@sgnl-ai/set-transmitter', () => ({
  transmitSET: jest.fn()
}));

jest.unstable_mockModule('@sgnl-actions/utils', () => ({
  signSET: jest.fn(),
  getBaseURL: jest.fn(),
  getAuthorizationHeader: jest.fn(),
  SGNL_USER_AGENT: 'SGNL-CAEP-Hub/2.0'
}));

const { transmitSET } = await import('@sgnl-ai/set-transmitter');
const { signSET, getBaseURL, getAuthorizationHeader } = await import('@sgnl-actions/utils');
const script = (await import('../src/script.mjs')).default;

describe('CAEP Risk Level Change Transmitter', () => {
  const mockContext = {
    environment: {
      ADDRESS: 'https://receiver.example.com/.well-known/ssf'
    },
    secrets: {
      BEARER_AUTH_TOKEN: 'test-token'
    },
    crypto: {
      signJWT: jest.fn()
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();
    getBaseURL.mockReturnValue('https://receiver.example.com/.well-known/ssf');
    getAuthorizationHeader.mockResolvedValue('Bearer test-token');
    signSET.mockResolvedValue('signed-jwt-token');
    transmitSET.mockResolvedValue({
      status: 'success',
      statusCode: 202,
      body: '',
      retryable: false
    });
  });

  describe('invoke', () => {
    test('should transmit risk level change with required fields', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.statusCode).toBe(202);

      // Verify SET payload structure
      const setPayload = signSET.mock.calls[0][1];
      expect(setPayload.aud).toBe('https://receiver.example.com');
      expect(setPayload.sub_id).toEqual({ format: 'email', email: 'user@example.com' });

      const eventPayload = setPayload.events['https://schemas.openid.net/secevent/caep/event-type/risk-level-change'];
      expect(eventPayload.principal).toBe('USER');
      expect(eventPayload.current_level).toBe('HIGH');
      expect(eventPayload.event_timestamp).toBeDefined();
    });

    test('should include all optional fields when provided', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'DEVICE',
        current_level: 'HIGH',
        previous_level: 'LOW',
        risk_reason: 'PASSWORD_FOUND_IN_DATA_BREACH',
        initiating_entity: 'system',
        reason_admin: '{"en":"Credential compromised","fr":"Identifiant compromis"}',
        reason_user: 'Your password was found in a data breach'
      };

      await script.invoke(params, mockContext);

      const setPayload = signSET.mock.calls[0][1];
      const eventPayload = setPayload.events['https://schemas.openid.net/secevent/caep/event-type/risk-level-change'];

      expect(eventPayload.principal).toBe('DEVICE');
      expect(eventPayload.current_level).toBe('HIGH');
      expect(eventPayload.previous_level).toBe('LOW');
      expect(eventPayload.risk_reason).toBe('PASSWORD_FOUND_IN_DATA_BREACH');
      expect(eventPayload.initiating_entity).toBe('system');
      expect(eventPayload.reason_admin).toEqual({ en: 'Credential compromised', fr: 'Identifiant compromis' });
      expect(eventPayload.reason_user).toEqual({ en: 'Your password was found in a data breach' });
    });

    test('should auto-wrap plain string reason_admin as i18n object', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'MEDIUM',
        reason_admin: 'Risk elevated due to suspicious activity'
      };

      await script.invoke(params, mockContext);

      const setPayload = signSET.mock.calls[0][1];
      const eventPayload = setPayload.events['https://schemas.openid.net/secevent/caep/event-type/risk-level-change'];

      expect(eventPayload.reason_admin).toEqual({ en: 'Risk elevated due to suspicious activity' });
    });

    test('should pass through JSON i18n object for reason_user', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH',
        reason_user: '{"en":"High risk detected","de":"Hohes Risiko erkannt"}'
      };

      await script.invoke(params, mockContext);

      const setPayload = signSET.mock.calls[0][1];
      const eventPayload = setPayload.events['https://schemas.openid.net/secevent/caep/event-type/risk-level-change'];

      expect(eventPayload.reason_user).toEqual({ en: 'High risk detected', de: 'Hohes Risiko erkannt' });
    });

    test('should use custom event_timestamp when provided', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH',
        event_timestamp: '1700000000'
      };

      await script.invoke(params, mockContext);

      const setPayload = signSET.mock.calls[0][1];
      const eventPayload = setPayload.events['https://schemas.openid.net/secevent/caep/event-type/risk-level-change'];

      expect(eventPayload.event_timestamp).toBe(1700000000);
    });

    test('should default event_timestamp to current time when not provided', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH'
      };

      const before = Math.floor(Date.now() / 1000);
      await script.invoke(params, mockContext);
      const after = Math.floor(Date.now() / 1000);

      const setPayload = signSET.mock.calls[0][1];
      const eventPayload = setPayload.events['https://schemas.openid.net/secevent/caep/event-type/risk-level-change'];
      expect(eventPayload.event_timestamp).toBeGreaterThanOrEqual(before);
      expect(eventPayload.event_timestamp).toBeLessThanOrEqual(after);
    });

    test('should not include reason fields when not provided', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH'
      };

      await script.invoke(params, mockContext);

      const setPayload = signSET.mock.calls[0][1];
      const eventPayload = setPayload.events['https://schemas.openid.net/secevent/caep/event-type/risk-level-change'];
      expect(eventPayload.reason_admin).toBeUndefined();
      expect(eventPayload.reason_user).toBeUndefined();
    });

    test('should handle non-retryable HTTP errors from transmitSET', async () => {
      transmitSET.mockResolvedValue({
        status: 'failed',
        statusCode: 400,
        body: '{"error":"Invalid request"}',
        retryable: false
      });

      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('failed');
      expect(result.statusCode).toBe(400);
      expect(result.retryable).toBe(false);
    });

    test('should use ADDRESS from environment when address not provided', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH'
      };

      await script.invoke(params, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(params, mockContext);
    });

    test('should accept custom principal values (spec extensibility)', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'https://vendor.example.com/principal-type/service-account',
        current_level: 'MEDIUM'
      };

      await script.invoke(params, mockContext);

      const setPayload = signSET.mock.calls[0][1];
      const eventPayload = setPayload.events['https://schemas.openid.net/secevent/caep/event-type/risk-level-change'];

      expect(eventPayload.principal).toBe('https://vendor.example.com/principal-type/service-account');
    });

    test('should throw on invalid subject JSON', async () => {
      const params = {
        subject: 'not valid json',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Invalid subject JSON');
    });

    test('should use address param for URL override', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH',
        address: 'https://custom-url.example.com/events'
      };

      await script.invoke(params, mockContext);

      expect(getBaseURL).toHaveBeenCalledWith(params, mockContext);
    });

    test('should pass auth header to transmitSET', async () => {
      const params = {
        subject: '{"format":"email","email":"user@example.com"}',
        audience: 'https://receiver.example.com',
        principal: 'USER',
        current_level: 'HIGH'
      };

      await script.invoke(params, mockContext);

      expect(getAuthorizationHeader).toHaveBeenCalledWith(mockContext);
      expect(transmitSET).toHaveBeenCalledWith(
        'signed-jwt-token',
        'https://receiver.example.com/.well-known/ssf',
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token',
            'User-Agent': 'SGNL-CAEP-Hub/2.0'
          })
        })
      );
    });
  });

  describe('error handler', () => {
    test('should return retry_requested for 429', async () => {
      const params = { error: { message: 'HTTP 429 Too Many Requests' } };
      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    });

    test('should return retry_requested for 502', async () => {
      const params = { error: { message: 'HTTP 502 Bad Gateway' } };
      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    });

    test('should return retry_requested for 503', async () => {
      const params = { error: { message: 'HTTP 503 Service Unavailable' } };
      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    });

    test('should return retry_requested for 504', async () => {
      const params = { error: { message: 'HTTP 504 Gateway Timeout' } };
      const result = await script.error(params, mockContext);
      expect(result.status).toBe('retry_requested');
    });

    test('should re-throw non-retryable errors', async () => {
      const params = { error: { message: 'HTTP 400 Bad Request' } };
      await expect(script.error(params, mockContext)).rejects.toEqual({ message: 'HTTP 400 Bad Request' });
    });
  });

  describe('halt handler', () => {
    test('should return halted status', async () => {
      const result = await script.halt({}, mockContext);
      expect(result.status).toBe('halted');
    });
  });
});

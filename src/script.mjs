import { transmitSET } from '@sgnl-ai/set-transmitter';
import { signSET, getBaseURL, getAuthorizationHeader, SGNL_USER_AGENT } from '@sgnl-actions/utils';

// Event type constant
const RISK_LEVEL_CHANGE_EVENT = 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change';

/**
 * Parse subject JSON string
 */
function parseSubject(subjectStr) {
  try {
    return JSON.parse(subjectStr);
  } catch (error) {
    throw new Error(`Invalid subject JSON: ${error.message}`, { cause: error });
  }
}

/**
 * Parse reason - auto-wraps plain strings as i18n objects per CAEP spec.
 * If input is a JSON object, use it directly. If plain string, wrap as {"en": value}.
 */
function parseReason(reasonStr) {
  if (!reasonStr) return undefined;

  try {
    const parsed = JSON.parse(reasonStr);
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed;
    }
  } catch {
    // Not JSON - fall through to auto-wrap
  }

  // Auto-wrap plain strings as i18n object per CAEP spec MUST requirement
  return { en: reasonStr };
}

export default {
  /**
   * Main execution handler - transmits a CAEP Risk Level Change event as a Security Event Token
   *
   * @param {Object} params - Job input parameters
   * @param {string} params.subject - Subject identifier JSON
   * @param {string} params.audience - Intended recipient of the SET
   * @param {string} params.principal - Type of principal (USER, DEVICE, SESSION, TENANT, ORG_UNIT, GROUP, or custom)
   * @param {string} params.current_level - Current risk level (LOW, MEDIUM, HIGH)
   * @param {string} [params.previous_level] - Previous risk level (LOW, MEDIUM, HIGH)
   * @param {string} [params.risk_reason] - Free-text reason for the risk level change
   * @param {string} [params.event_timestamp] - Unix timestamp (seconds) when the event occurred
   * @param {string} [params.initiating_entity] - Entity that initiated the change (admin, user, policy, system)
   * @param {string} [params.reason_admin] - Admin-readable reason (JSON i18n object or plain string)
   * @param {string} [params.reason_user] - User-readable reason (JSON i18n object or plain string)
   * @param {string} [params.address] - Optional destination URL override
   * @param {Object} context - Execution context with secrets, environment, and crypto
   * @returns {Object} Transmission result with status, statusCode, body, and retryable flag
   */
  invoke: async (params, context) => {

    const address = getBaseURL(params, context);
    const authHeader = await getAuthorizationHeader(context);

    // Parse parameters
    const subject = parseSubject(params.subject);

    // Build event payload
    const eventPayload = {
      event_timestamp: params.event_timestamp
        ? parseInt(params.event_timestamp, 10)
        : Math.floor(Date.now() / 1000),
      principal: params.principal,
      current_level: params.current_level
    };

    // Add optional event claims
    if (params.previous_level) {
      eventPayload.previous_level = params.previous_level;
    }
    if (params.risk_reason) {
      eventPayload.risk_reason = params.risk_reason;
    }
    if (params.initiating_entity) {
      eventPayload.initiating_entity = params.initiating_entity;
    }
    if (params.reason_admin) {
      eventPayload.reason_admin = parseReason(params.reason_admin);
    }
    if (params.reason_user) {
      eventPayload.reason_user = parseReason(params.reason_user);
    }

    // Build the SET payload (reserved claims will be added during signing)
    const setPayload = {
      aud: params.audience,
      sub_id: subject,
      events: {
        [RISK_LEVEL_CHANGE_EVENT]: eventPayload
      }
    };

    const jwt = await signSET(context, setPayload);

    // Transmit the SET
    return await transmitSET(jwt, address, {
      headers: {
        'Authorization': authHeader,
        'User-Agent': SGNL_USER_AGENT
      }
    });
  },

  /**
   * Error handler for retryable failures
   */
  error: async (params, _context) => {
    const { error } = params;

    if (error.message?.includes('429') ||
        error.message?.includes('502') ||
        error.message?.includes('503') ||
        error.message?.includes('504')) {
      return { status: 'retry_requested' };
    }

    throw error;
  },

  /**
   * Cleanup handler
   */
  halt: async (_params, _context) => {
    return { status: 'halted' };
  }
};

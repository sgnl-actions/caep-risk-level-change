#!/usr/bin/env node

/**
 * Development runner for testing the CAEP Risk Level Change transmitter locally.
 * This will fail without a real crypto context, but demonstrates the expected parameters.
 */

import script from '../src/script.mjs';

const mockContext = {
  environment: {
    ADDRESS: 'https://receiver.example.com/.well-known/ssf'
  },
  secrets: {
    BEARER_AUTH_TOKEN: 'dev-test-token'
  },
  crypto: {
    signJWT: async (payload, header) => {
      console.log('Mock signJWT called with:', JSON.stringify({ payload, header }, null, 2));
      return 'mock-signed-jwt-token';
    }
  }
};

const mockParams = {
  subject: '{"format":"email","email":"user@example.com"}',
  audience: 'https://receiver.example.com',
  principal: 'USER',
  current_level: 'HIGH',
  previous_level: 'LOW',
  risk_reason: 'PASSWORD_FOUND_IN_DATA_BREACH',
  initiating_entity: 'system',
  reason_admin: '{"en":"Credential found in known breach database"}',
  reason_user: 'Your password may have been exposed in a data breach'
};

async function runDev() {
  console.log('Running CAEP Risk Level Change transmitter in development mode...\n');
  console.log('Parameters:', JSON.stringify(mockParams, null, 2));
  console.log('\n' + '='.repeat(50) + '\n');

  try {
    const result = await script.invoke(mockParams, mockContext);
    console.log('\n' + '='.repeat(50));
    console.log('Completed successfully!');
    console.log('Result:', JSON.stringify(result, null, 2));
  } catch (error) {
    console.log('\n' + '='.repeat(50));
    console.error('Failed:', error.message);

    if (script.error) {
      console.log('\nAttempting error recovery...');
      try {
        const recovery = await script.error({ ...mockParams, error }, mockContext);
        console.log('Recovery result:', JSON.stringify(recovery, null, 2));
      } catch (recoveryError) {
        console.error('Recovery failed:', recoveryError.message);
      }
    }
  }
}

runDev().catch(console.error);

/* eslint-disable global-require */
const jwt = require('jsonwebtoken');
const metadata = require('gcp-metadata');
const googleAuthLibrary = require('google-auth-library');

jest.mock('gcp-metadata');

const keys = {
  private: '-----BEGIN EC PRIVATE KEY-----\n'
    + 'MHcCAQEEIPUmxazBncw4n67VjpKyqXlblZyQ2W+WumvNQRY9trCyoAoGCCqGSM49\n'
    + 'AwEHoUQDQgAEozHv2OYhIXe2vLsBYzmcYEZl0rDcK0iNP04hjSCCa7i74yWp989o\n'
    + 'EX/NJAeWmlYLW1MUh8A7QbLZLMTFAIKehQ==\n'
    + '-----END EC PRIVATE KEY-----\n',
  public: '-----BEGIN CERTIFICATE-----\n'
    + 'MIIBEDCBuAIJAJsSvHuCuN8BMAoGCCqGSM49BAMCMBExDzANBgNVBAMMBnVudXNl\n'
    + 'ZDAeFw0yMTA2MTcxMzU0MjZaFw0yMTA3MTcxMzU0MjZaMBExDzANBgNVBAMMBnVu\n'
    + 'dXNlZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKMx79jmISF3try7AWM5nGBG\n'
    + 'ZdKw3CtIjT9OIY0ggmu4u+MlqffPaBF/zSQHlppWC1tTFIfAO0Gy2SzExQCCnoUw\n'
    + 'CgYIKoZIzj0EAwIDRwAwRAIgKkQh8lDUZDm2by5b9CSleW06pGjc76fJ99f8A5Ah\n'
    + 'c9YCIFnMx0ZHkOK9NBLADm4hM76l96D1UWygWwsM77MYl5Nb\n'
    + '-----END CERTIFICATE-----\n',
};

const payload = {
  aud: '/projects/12345/apps/test',
  email: 'test@google.com',
  exp: Math.floor(Date.now() / 1000) + 30,
  iat: Math.floor(Date.now() / 1000) - 30,
  iss: 'https://cloud.google.com/iap',
  sub: 'accounts.google.com:1234567890',
};

const testJwt = jwt.sign(payload, keys.private, { algorithm: 'ES256', header: { kid: 'tests' } });

describe('Middleware verification', () => {
  beforeAll(() => {
    metadata.isAvailable.mockResolvedValue(true);
    metadata.project.mockImplementation(async (field) => (
      field === 'numeric-project-id'
        ? '12345'
        : 'test'
    ));
  });

  it('should successfully verify the IAP header', async () => {
    // Mocks
    googleAuthLibrary.OAuth2Client.prototype.getIapPublicKeys = (
      jest.fn().mockResolvedValue({ pubkeys: { tests: keys.public } }));

    const iap = require('./index');
    const options = { logger: console };
    const middleware = iap.verify(options);

    const req = { get: () => (testJwt) };
    const res = { send: () => {} };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toBeCalled();
    expect(req.iap.info).toMatchObject(payload);
  });

  it('should 401 if unsuccessful', async () => {
    // Mocks
    googleAuthLibrary.OAuth2Client.prototype.getIapPublicKeys = (
      jest.fn().mockRejectedValue());

    const logger = { error: jest.fn() };
    const iap = require('./index');
    const options = { logger };
    const middleware = iap.verify(options);

    const req = { get: () => (testJwt) };
    const res = { send: () => {} };
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalled();
    expect(req.iap).toBeUndefined();
  });
});

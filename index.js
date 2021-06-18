const metadata = require('gcp-metadata');
const { OAuth2Client } = require('google-auth-library');

const client = new OAuth2Client();

let cachedAud;

const audience = async () => {
  const metadataAvailable = await metadata.isAvailable();

  if (!cachedAud && metadataAvailable) {
    const [projectNumber, projectId] = await Promise.all([
      metadata.project('numeric-project-id'),
      metadata.project('project-id'),
    ]);

    cachedAud = `/projects/${projectNumber}/apps/${projectId}`;
  }

  return cachedAud;
};

const verify = (opts = {}) => async (req, res, next) => {
  const options = {
    error: (request, response) => response.send(401),
    logger: () => {},
    ...opts,
  };

  const assertion = req.get('X-Goog-IAP-JWT-Assertion');

  try {
    const aud = await audience();

    const { pubkeys } = await client.getIapPublicKeys();

    const ticket = await client.verifySignedJwtWithCertsAsync(
      assertion,
      pubkeys,
      aud,
      ['https://cloud.google.com/iap'],
    );

    const info = ticket.getPayload();

    req.iap = { info };

    next();
  } catch (err) {
    options.logger.error(err);
    options.error(req, res, next);
  }
};

module.exports = {
  verify,
};

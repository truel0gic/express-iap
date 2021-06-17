const metadata = require('gcp-metadata');
const { OAuth2Client } = require('google-auth-library');

const client = new OAuth2Client();

let aud;

const audience = async () => {
  const metadataAvailable = await metadata.isAvailable();

  if (!aud && metadataAvailable) {
    const [projectNumber, projectId] = await Promise.all([
      metadata.project('numberic-project-id'),
      metadata.project('project-id'),
    ]);

    aud = `/projects/${projectNumber}/apps/${projectId}`;
  }

  return aud;
};

const verify = (req, res, next) => {
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
    res.send(401);
  }
};

module.exports = {
  verify,
};

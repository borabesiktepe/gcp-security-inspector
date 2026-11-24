const https = require('https');
const crypto = require('crypto');

async function makeGoogleApiRequest(credentials, url, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const { client_email, private_key } = credentials;
    const jwtHeader = { alg: 'RS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const jwtClaimSet = {
      iss: client_email,
      scope: 'https://www.googleapis.com/auth/cloud-platform',
      aud: 'https://www.googleapis.com/oauth2/v4/token',
      exp: now + 3600,
      iat: now
    };
    const headerBase64 = Buffer.from(JSON.stringify(jwtHeader)).toString('base64url');
    const claimSetBase64 = Buffer.from(JSON.stringify(jwtClaimSet)).toString('base64url');
    const signatureInput = `${headerBase64}.${claimSetBase64}`;
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(signatureInput);
    const signature = signer.sign(private_key, 'base64url');
    const jwt = `${headerBase64}.${claimSetBase64}.${signature}`;
    const tokenReqOptions = {
      hostname: 'www.googleapis.com',
      path: '/oauth2/v4/token',
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    };
    const tokenReq = https.request(tokenReqOptions, (tokenRes) => {
      let tokenData = '';
      tokenRes.on('data', (chunk) => { tokenData += chunk; });
      tokenRes.on('end', () => {
        const tokenResponse = JSON.parse(tokenData);
        const accessToken = tokenResponse.access_token;
        if (!accessToken) return reject(new Error(`Failed to get access token: ${tokenData}`));
        const apiReqOptions = new URL(url);
        const options = {
          hostname: apiReqOptions.hostname,
          path: apiReqOptions.pathname + apiReqOptions.search,
          method,
          headers: { 'Authorization': `Bearer ${accessToken}` }
        };
        if (method === 'POST') {
          options.headers['Content-Type'] = 'application/json';
        }
        const apiReq = https.request(options, (apiRes) => {
          let apiData = '';
          apiRes.on('data', (chunk) => { apiData += chunk; });
          apiRes.on('end', () => {
            try {
              const response = JSON.parse(apiData);
              resolve(response);
            } catch (error) {
              reject(new Error(`Failed to parse API response: ${apiData}`));
            }
          });
        });
        apiReq.on('error', (error) => { reject(new Error(`API request error: ${error.message}`)); });
        if (method === 'POST' && body) {
          apiReq.write(JSON.stringify(body));
        } else if (method === 'POST') {
          apiReq.write('{}');
        }
        apiReq.end();
      });
    });
    tokenReq.on('error', (error) => { reject(new Error(`Token request error: ${error.message}`)); });
    tokenReq.write(`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`);
    tokenReq.end();
  });
}

module.exports = { makeGoogleApiRequest }; 
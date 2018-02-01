'use strict';

console.log("Loading...");

const path = require('path');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const request = require('request');

// TODO: BETTER USE .well-known/openid-configuration endpoint for real.
const ISSUER = process.env.ISSUER;
const JWKS_SUFFIX = process.env.JWKS_SUFFIX;
const separator = (ISSUER.endsWith('/') || JWKS_SUFFIX.startsWith('/')) ? '' : '/';
const JWKS_URI = ISSUER + separator + JWKS_SUFFIX;
console.log("JWKS URI: " + JWKS_URI);

// Generate policy to allow this user on this API:
const generatePolicy = (principalId, effect, resource) => {
  const authResponse: any = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument: any = {};
    policyDocument.Version = '2012-10-17';
    
    policyDocument.Statement = [];
    const statementOne: any = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  console.log("Generated policy:" + JSON.stringify(authResponse));

  return authResponse;
};

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
module.exports.authorize = (event, context, cb) => {
  console.log('Auth function invoked');
  if (event.authorizationToken) {
    // Remove 'bearer ' from token:
    const token = event.authorizationToken.substring(7);
    // Make a request to the iss + .well-known/jwks.json URL:
    request(
      { url: JWKS_URI, json: true },
      (error, response, body) => {
        if (error || response.statusCode !== 200) {
          console.log('Request error:', error);
          cb('Unauthorized');
        }
        const keys = body;
        // Based on the JSON of `jwks` create a Pem:
        const k = keys.keys[0];
        const jwkArray = {
          kty: k.kty,
          n: k.n,
          e: k.e,
        };
        const pem = jwkToPem(jwkArray);

        // Verify the token:
        jwt.verify(token, pem, { issuer: ISSUER }, (err, decoded) => {
          if (err) {
            console.log('Unauthorized user:', err.message);
            cb('Unauthorized');
          } else {
            cb(null, generatePolicy(decoded.sub, 'Allow', event.methodArn));
          }
        });
      });
  } else {
    console.log('No authorizationToken found in the header.');
    cb('Unauthorized');
  }
};

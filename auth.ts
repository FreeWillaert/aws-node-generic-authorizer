'use strict';

import * as _ from 'lodash';
import * as jwt from 'jsonwebtoken';

const path = require('path');
const jwkToPem = require('jwk-to-pem');
const request = require('request');

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
module.exports.authorize = (event, context, cb) => {
  console.log('Auth function invoked');

  const issuer = getIssuer();
  const jwksUri = composeJwksUri(issuer);

  if (event.authorizationToken) {
    // Remove 'bearer ' from token:
    const token = event.authorizationToken.substring(7);

    request(
      { url: jwksUri, json: true },
      (error, response, body) => {
        if (error || response.statusCode !== 200) {
          console.log('Request error:', error);
          cb('Unauthorized');
        }
        const keys = body.keys;
        // Based on the JSON of `jwks` create a Pem:

        // Lookup the key in the keys collection by kid; take the first item from the array if no kid available.
        const decodedJwt: any = jwt.decode(token, { complete: true});
        const tokenkid = decodedJwt.header && decodedJwt.header.kid;

        let key = keys[0];
        if(tokenkid) {
          key = _.filter(keys, k => k.kid === tokenkid)[0];
        }
        
        const pem = jwkToPem(key);

        // Verify the token:
        jwt.verify(token, pem, { issuer }, (err, verifiedJwt: any) => {
          if (err) {
            console.log('Unauthorized user:', err.message);
            cb('Unauthorized');
          } else {
            cb(null, generatePolicy(verifiedJwt.sub, 'Allow', event.methodArn));
          }
        });
      });
  } else {
    console.log('No authorizationToken found in the header.');
    cb('Unauthorized');
  }
};

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

function getIssuer(): string {
    // TODO: BETTER USE .well-known/openid-configuration endpoint for real.
  return process.env.ISSUER;
}

function composeJwksUri(issuer: string): string {
  const separator = (issuer.endsWith('/') || process.env.JWKS_SUFFIX.startsWith('/')) ? '' : '/';
  const jwksUri = issuer + separator + process.env.JWKS_SUFFIX;
  console.log("JWKS URI: " + jwksUri);

  return jwksUri;
}
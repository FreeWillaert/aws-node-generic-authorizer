'use strict';

// import * as path from 'path';

import * as _ from 'lodash';
import * as jwt from 'jsonwebtoken';
import fetch from 'node-fetch';
import * as cache from 'memory-cache';

import { lowerCaseFieldNames } from './util/lowerCaseFieldNames';

const jwkToPem = require('jwk-to-pem');
const request = require('request');

let jwksCacheSeconds = 0;

// TODO: Use an ILogger with a default implementation.

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
module.exports.authorize = (event: IAuthorizerEvent, context, cb) => {
  console.log("Handling event: " + JSON.stringify(event));
  console.log("Handling context: " + JSON.stringify(context));

  try {
    const issuer = getIssuer();
    const audience = getAudience(); // optional
    const jwksUri = composeJwksUri(issuer);
    setJwksCacheSeconds();
    const sharedKey = getSharedKey();

    const jwtToken = getJwtToken(event);

    if (!jwtToken) throw new Error('No JWT token found.');

    console.log("JWT Token:" + jwtToken);

    getJwks(jwksUri)
      .then(jwks => {

        const publicKey = getPublicKey(jwtToken, jwks);

        const verifiedJwt: any = jwt.verify(jwtToken, publicKey, { issuer, audience });

        cb(null, generatePolicy(verifiedJwt.sub, 'Allow', event.methodArn, verifiedJwt, sharedKey));
      })
      .catch(error => {
        console.error('Error:', error);
        cb('Unauthorized');
      });
  } catch (error) {
    console.error('Error:', error);
    cb('Unauthorized');
  }
};

// Generate policy to allow this user on this API:
function generatePolicy(principalId: string, effect: string, resource: string, userData: any, sharedKey?: string): IAuthorizerResponse {
  if (!effect || !resource) throw new Error("Effect and Resource are required.");

  const authorizerResponse: IAuthorizerResponse = {
    principalId: principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource
        }
      ]
    },
    context: {
      "userData": JSON.stringify(userData)
    }
  };

  if(sharedKey) {
    // TODO: sharedKey name should be configurable?
    authorizerResponse.context.sharedKey = sharedKey; // TODO: Test that this can be used with HTTP backends.
  }

  console.log("Generated response:" + JSON.stringify(authorizerResponse));

  return authorizerResponse;
};

function getPublicKey(token: string, jwks: any) {
  // Lookup the key in the keys collection by kid; take the first item from the array if no kid available.
  const decodedJwt: any = jwt.decode(token, { complete: true });
  const tokenkid = decodedJwt.header && decodedJwt.header.kid;

  let key = jwks[0];
  if (tokenkid) {
    key = _.filter(jwks, k => k.kid === tokenkid)[0];
  }

  return jwkToPem(key);
}

function getJwtToken(event: IAuthorizerEvent) {

  let authorizationHeader = event.authorizationToken;

  if (!authorizationHeader) {
    lowerCaseFieldNames(event.headers);
    authorizationHeader = event.headers && event.headers.authorization;
  }

  if (!authorizationHeader) throw new Error("No Authorization Header found.");

  // Remove 'bearer ' from header value:
  return authorizationHeader.substring(7);
}

function getIssuer(): string {
  return process.env.ISSUER;
}

function getJwksCacheSeconds(): number {
  return (process.env.JWKS_CACHE_SECONDS) ? +process.env.JWKS_CACHE_SECONDS : null;
}

function setJwksCacheSeconds() {
  jwksCacheSeconds = getJwksCacheSeconds() || jwksCacheSeconds;
}

function getAudience(): string {
  return process.env.AUDIENCE;
}

function getSharedKey(): string {
  return process.env.SHARED_KEY;
}

function composeJwksUri(issuer: string): string {

  if (!issuer) throw new Error("No issuer.");

  const separator = (issuer.endsWith('/') || process.env.JWKS_SUFFIX.startsWith('/')) ? '' : '/';
  const jwksUri = issuer + separator + process.env.JWKS_SUFFIX;
  console.log("JWKS URI: " + jwksUri);

  return jwksUri;
}

function getJwks(jwksUri: string): Promise<any> {

  let jwks = cache.get(jwksUri);

  if(jwks) return Promise.resolve(jwks);
  
  // TODO: BETTER USE .well-known/openid-configuration endpoint for real.
  return fetch(jwksUri)
    .then(res => {
      if (res.status !== 200) throw new Error("Error getting JWKS: " + res.statusText);
      return res.json();
    })
    .then(body => {
      if (!body.keys) throw new Error("JWKS has no keys: " + JSON.stringify(body));
      const jwks = body.keys;

      cache.put(jwksUri, jwks, jwksCacheSeconds*1000);

      return jwks;
    });
}
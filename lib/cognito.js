'use strict';

const axios = require('axios');
const qs = require('qs');
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');

class Cognito {
  constructor() {}

  static get implictGrantUrl() { return `${Cognito.authDomain}/login?client_id=${Cognito.clientId}&scope=${Cognito.scope}&redirect_uri=${Cognito.callBackUrl}&response_type=token`; }
  static get authCodeGrantUrl() { return `${Cognito.authDomain}/login?client_id=${Cognito.clientId}&scope=${Cognito.scope}&redirect_uri=${Cognito.callBackUrl}&response_type=code`; }
  static getAccessToken(req) { return req.cookies.AWSCognito_accessToken; }

  // For Implict grant
  //
  static getAccessTokenCallback(callbackToken) {
    let match = callbackToken.match(/&access_token=(.*)&expires_in=3600&token_type=Bearer$/);
    if (!match) { return false; }
    else { return match[1]; }
  }

  // For Authorization Code grant
  //
  static async getTokens(authorizationCode) {
    let response = await axios({
      method: "post",
      url: `${Cognito.authDomain}/oauth2/token`,
      data: qs.stringify({
        grant_type: "authorization_code",
        code: authorizationCode,
        client_id: Cognito.clientId,
        redirect_uri: Cognito.callBackUrl
      }),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    if (!response.data || !response.data.access_token || !response.data.refresh_token) {
      return Promise.reject("Missing access or refresh token!")
    }
    else {
      return Promise.resolve({
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token
      });
    }
  }

  // Set token to cookies
  //
  static setCookie(res, accessToken, refreshToken, contextPath, domain) {
    let now = new Date(), cookies = [];
    if (typeof accessToken === "string") {
      cookies.push(`AWSCognito_accessToken=${accessToken}; Path=${contextPath}/; Domain=${domain}; Expires=${(new Date(now.getTime() + Cognito.accessTokenExp * 1000)).toUTCString()}; HttpOnly`);
    }
    if (typeof refreshToken === "string") {
      cookies.push(`AWSCognito_refreshToken=${refreshToken}; Path=${contextPath}/; Domain=${domain}; Expires=${(new Date(now.getTime() + Cognito.refreshTokenExp * 1000)).toUTCString()}; HttpOnly`);
    }
    res.setHeader("Set-Cookie", cookies);
  }

  // Check if having valid accessToken or refreshToken
  //
  static async checkToken(req, res) {
    if (req.cookies.AWSCognito_accessToken) { return Promise.resolve(req.cookies.AWSCognito_accessToken); }
    else if (req.cookies.AWSCognito_refreshToken) {
      let username = req.cookies.AWSCognito_username;
      if (!username) { return Promise.resolve(false); }

      let cognitoUser = new AmazonCognitoIdentity.CognitoUser({
        Username: username,
        Pool: new AmazonCognitoIdentity.CognitoUserPool(Cognito.poolData)
      });

      let token = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: req.cookies.AWSCognito_refreshToken });
      let refreshSession = new Promise((resolve, reject) => {
        cognitoUser.refreshSession(token, (err, session) => {
        if (session) { resolve(session); }
        else if (err) { reject(err); }
      })});

      let error;
      refreshSession = await refreshSession.catch(err => error = err);
      if (error && error.message !== "Invalid Refresh Token") { return Promise.reject(error); }
      else if (error && error.message === "Invalid Refresh Token") { return Promise.resolve(false); }

      let accessToken = refreshSession.accessToken.getJwtToken();
      Cognito.setCookie(res, accessToken);

      return Promise.resolve(accessToken);
    }
  }
}

module.exports = Cognito;
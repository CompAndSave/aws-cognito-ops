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

  // Get the accessToken / refreshToken via API
  //
  static async getTokenByAPI(username, password, needRefreshToken) {
    const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
      Username: username,
      Password: password
    });

    let cognitoUser = new AmazonCognitoIdentity.CognitoUser({
      Username: username,
      Pool: new AmazonCognitoIdentity.CognitoUserPool(Cognito.poolData)
    });

    let error, tokens = await new Promise((resolve, reject)=> {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (result)=> {
          if (needRefreshToken) {
            resolve({
              accessToken: result.getAccessToken().getJwtToken(),
              refreshToken: result.getRefreshToken().getToken()
            });
          }
          else {
            resolve(result.getAccessToken().getJwtToken());
          }
        },
        onFailure: (err)=> reject(err)
      });
    }).catch(err => error = err);

    if (error) { return Promise.reject(error); }
    else { return Promise.resolve(tokens); }
  }

  // Set token to cookies
  // type = "accessToken" or "refreshToken"
  // Using Lambda at AWS, only one cookie can be set in one http response
  //
  static setCookie(res, type, token, contextPath = Cognito.defaultContextPath, domain = Cognito.defaultCookieDomain) {
    let now = new Date();
    if (type !== "accessToken" && type !== "refreshToken") { return false; }

    res.setHeader("Set-Cookie", 
                  type === "accessToken" ? `AWSCognito_accessToken=${token}; Path=${contextPath}/; Domain=${domain}; Expires=${(new Date(now.getTime() + Cognito.accessTokenExp * 1000)).toUTCString()}; HttpOnly` :
                           `AWSCognito_refreshToken=${token}; Path=${contextPath}/; Domain=${domain}; Expires=${(new Date(now.getTime() + Cognito.refreshTokenExp * 1000)).toUTCString()}; HttpOnly`
                 );

    return true;
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
      let refreshSession = new Promise((resolve, reject)=> {
        cognitoUser.refreshSession(token, (err, session)=> {
        if (session) { resolve(session); }
        else if (err) { reject(err); }
      })});

      let error;
      refreshSession = await refreshSession.catch(err => error = err);
      if (error && error.message !== "Invalid Refresh Token" && error.message !== "Refresh Token has been revoked") { return Promise.reject(error); }
      else if (error && (error.message === "Invalid Refresh Token" || error.message === "Refresh Token has been revoked")) { return Promise.resolve(false); }

      let accessToken = refreshSession.accessToken.getJwtToken();
      Cognito.setCookie(res, "accessToken", accessToken, Cognito.defaultContextPath, Cognito.defaultCookieDomain);

      return Promise.resolve(accessToken);
    }
  }

  // local sign out by clearing token cookie
  //
  static signOut(res, path = Cognito.defaultContextPath, domain = Cognito.defaultCookieDomain) {
    res.clearCookie("AWSCognito_accessToken", { path: `${path}/`, domain: domain });
    res.clearCookie("AWSCognito_refreshToken", { path: `${path}/`, domain: domain });
    res.clearCookie("AWSCognito_username", { path: `${path}/`, domain: domain });
    return true;
  }

  // getSession by authenticated user
  //
  static async getSession(cognitoUser) {
    let error;

    await new Promise((resolve, reject)=> {
      cognitoUser.getSession((err)=> {
        if (err) { reject(err); }
        resolve();
      });
    }).catch(err => error = err);

    if (error) { return Promise.reject(error); }
    return Promise.resolve(cognitoUser);
  }

  // Global signOut for authenticated session - refreshToken is invalidated, accessToken will work until they are expired
  // https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GlobalSignOut.html
  //
  static async globalSignOut(username) {
    let error, cognitoUser = new AmazonCognitoIdentity.CognitoUser({
      Username: username,
      Pool: new AmazonCognitoIdentity.CognitoUserPool(Cognito.poolData)
    });

    // Need to getSession in order to GlobalSignOut
    //
    await Cognito.getSession(cognitoUser);

    await new Promise((resolve, reject)=> {
      cognitoUser.globalSignOut({
        onSuccess: ()=> resolve(),
        onFailure: (err)=> reject(err)
      });
    }).catch(err => error = err);

    if (error) { return Promise.reject(error); }
    else { return Promise.resolve(true); }
  }

  // Change password on authenticated session
  //
  static async changePassword(username, oldPassword, newPassword) {
    let error, cognitoUser = new AmazonCognitoIdentity.CognitoUser({
      Username: username,
      Pool: new AmazonCognitoIdentity.CognitoUserPool(Cognito.poolData)
    });

    // Need to getSession in order to changePassword
    //
    await Cognito.getSession(cognitoUser);

    await new Promise((resolve, reject)=> {
      cognitoUser.changePassword(oldPassword, newPassword, (err)=> {
        if (err) { reject(err); }
        resolve();
      });
    }).catch(err => error = err);

    if (error) { return Promise.reject(error); }
    else { return Promise.resolve(true); }
  }
  
  // Forgot Password flow for unauthenticated session
  // sendForgotPasswordCode - initiate the password reset, AWS Cognito will email the verification code to user
  // updatePassword - update password by using the verification code
  //
  static async sendForgotPasswordCode(username) {
    let error, cognitoUser = new AmazonCognitoIdentity.CognitoUser({
      Username: username,
      Pool: new AmazonCognitoIdentity.CognitoUserPool(Cognito.poolData)
    });

    await new Promise((resolve, reject)=> {
      cognitoUser.forgotPassword({
        onSuccess: ()=> resolve(),
        onFailure: (err)=> reject(err)
      });
    }).catch(err => error = err);

    if (error) { return Promise.reject(error); }
    else { return Promise.resolve(true); }
  }

  static async confirmPassword(username, newPassword, verificationCode) {
    let error, cognitoUser = new AmazonCognitoIdentity.CognitoUser({
      Username: username,
      Pool: new AmazonCognitoIdentity.CognitoUserPool(Cognito.poolData)
    });

    await new Promise((resolve, reject)=> {
      cognitoUser.confirmPassword(verificationCode, newPassword, {
        onSuccess() { resolve(); },
        onFailure(err) { reject(err); }
      });
    }).catch(err => error = err);

    if (error) { return Promise.reject(error); }
    else { return Promise.resolve(true); }
  }
}

module.exports = Cognito;
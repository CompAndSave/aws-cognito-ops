'use strict';

const axios = require('axios');
const qs = require('qs');
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');

class Cognito {
  /**
   * @class
   * @classdesc - Class with different methods for authentication via AWS Cognito and ExpressJS
   */
  constructor() {}

  /**
   * Get Implicit Grant URL
   * 
   * @returns {string} Implicit Grant URL string
   */
  static get implicitGrantUrl() { return `${Cognito.authDomain}/login?client_id=${Cognito.clientId}&scope=${Cognito.scope}&redirect_uri=${Cognito.callBackUrl}&response_type=token`; }
  
  /**
   * Get Authorization Code Grant URL
   * 
   * @returns {string} Authorization Code Grant URL string
   */
  static get authCodeGrantUrl() { return `${Cognito.authDomain}/login?client_id=${Cognito.clientId}&scope=${Cognito.scope}&redirect_uri=${Cognito.callBackUrl}&response_type=code`; }

  /**
   * Get the access token from server cookie
   * 
   * @param {object} req ExpressJS request object
   * @returns {string} accessToken string
   */
  static getAccessToken(req) { return req.cookies.AWSCognito_accessToken; }

  /**
   * For Implict Grant - Extract the accessToken from the callback url
   * 
   * @param {*} callbackToken postback token return from Cognito (Implict Grant flow)
   * @returns {boolean}
   */
  static getAccessTokenCallback(callbackToken) {
    let match = callbackToken.match(/&access_token=(.*)&expires_in=3600&token_type=Bearer$/);
    if (!match) { return false; }
    else { return match[1]; }
  }

  /**
   * For Authorization Code Grant - Obtain accessToken and/or refreshToken from authorization code
   * 
   * @param {string} authorizationCode authorization code returned from Cognito (Authorization Code Grant flow)
   * @returns {object} token object
   */
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

  /**
   * Get the accessToken / refreshToken via API
   * 
   * @param {string} username Username
   * @param {string} password Password
   * @param {boolean} [needRefreshToken=false] set true if refreshToken is needed, default is false
   * @returns {object} token or error object
   */
  static async getTokenByAPI(username, password, needRefreshToken = false) {
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

  /**
   * Set token to cookies
   * Using Lambda at AWS, only one cookie can be set in one http response
   * 
   * @param {object} res ExpressJS response object
   * @param {string} type "accessToken" or "refreshToken"
   * @param {string} token token string
   * @param {string} [contextPath=Cognito.defaultContextPath] context path string without trailing forward slash, default value: Cognito.defaultContextPath
   * @param {string} [domain=Cognito.defaultCookieDomain] domain string, default value: Cognito.defaultCookieDomain
   * @returns {boolean} true if success or false
   */
  static setCookie(res, type, token, contextPath = Cognito.defaultContextPath, domain = Cognito.defaultCookieDomain) {
    let now = new Date();
    if (type !== "accessToken" && type !== "refreshToken") { return false; }

    res.setHeader("Set-Cookie", type === "accessToken" ? 
      `AWSCognito_accessToken=${token}; Path=${contextPath}/; Domain=${domain}; Expires=${(new Date(now.getTime() + Cognito.accessTokenExp * 1000)).toUTCString()}; HttpOnly` :
      `AWSCognito_refreshToken=${token}; Path=${contextPath}/; Domain=${domain}; Expires=${(new Date(now.getTime() + Cognito.refreshTokenExp * 1000)).toUTCString()}; HttpOnly`
    );

    return true;
  }

  /**
   * Check if having valid accessToken or refreshToken
   * 
   * @param {object} req ExpressJS request object
   * @param {object} res ExpressJS response object
   * @returns {string|object|boolean} return accessToken string if valid
   */
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

  /**
   * Local sign out by clearing token cookie
   * Note: res.cookie() and res.clearCookie() do not work with serverless
   * 
   * @param {object} res ExpressJS response object
   * @param {string} type "accessToken" or "refreshToken"
   * @param {string} [contextPath=Cognito.defaultContextPath] context path string without trailing forward slash, default value: Cognito.defaultContextPath
   * @param {string} [domain=Cognito.defaultCookieDomain] domain string, default value: Cognito.defaultCookieDomain
   * @returns {boolean} true if success or false
   */
  static signOut(res, type, contextPath = Cognito.defaultContextPath, domain = Cognito.defaultCookieDomain) {
    if (type !== "accessToken" && type !== "refreshToken") { return false; }

    res.setHeader("Set-Cookie", type === "accessToken" ? 
      `AWSCognito_accessToken=; Path=${contextPath}/; Domain=${domain}; Expires=${(new Date()).toUTCString()};` :
      `AWSCognito_refreshToken=; Path=${contextPath}/; Domain=${domain}; Expires=${(new Date()).toUTCString()};`
    );
    return true;
  }

  /**
   * getSession by authenticated user
   * 
   * @param {object} cognitoUser Cognito User object
   * @returns {object} Cognito User object with session set
   */
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

  /**
   * Global signOut for authenticated session - refreshToken is invalidated, accessToken will work until they are expired
   * Reference: {@link https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GlobalSignOut.html}
   * 
   * @param {string} username Username
   * @returns {object|boolean} true if success or error object
   */
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

  /**
   * Change password on authenticated session
   * 
   * @param {string} username Username
   * @param {string} oldPassword Current / Old password
   * @param {string} newPassword New password
   * @returns {object|boolean} true if success or error object
   */
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
  
  /**
   * Forgot Password flow for unauthenticated session
   * sendForgotPasswordCode - initiate the password reset, AWS Cognito will email the verification code to user
   * confirmPassword - update password by using the verification code
   * 
   * @param {string} username Username
   * @returns {object|boolean} true if success or error object
   */
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

  /**
   * update password by using the verification code
   * 
   * @param {string} username Username
   * @param {string} newPassword New password
   * @param {string} verificationCode Verification code
   * @returns {object|boolean} true if success or error object
   */
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
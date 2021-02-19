# Authentication opertions via AWS Cognito and ExpressJS
## Features:
* Authorization Code Grant and Implicant Grant via AWS Host UI
* Get access and/or refresh tokens via API
* Refresh session by refresh token
* Add tokens to cookie
* Global and local sign out
* Change Password
* Forgot Password

**Initiatization is required when app starts. Here is an example.**

```
Cognito.authDomain = process.env.AWS_COGNITO_OAUTH_DOMAIN;
Cognito.clientId = process.env.AWS_COGNITO_NODE_APP_CLIENT_ID;
Cognito.scope = process.env.AWS_COGNITO_SCOPE;
Cognito.callBackUrl = process.env.AWS_COGNITO_CALLBACK_URL;
Cognito.accessTokenExp = process.env.AWS_COGNITO_ACCESSTOKEN_EXP;
Cognito.refreshTokenExp = process.env.AWS_COGNITO_REFRESHTOKEN_EXP;
Cognito.pool_region = process.env.AWS_COGNITO_POOL_REGION;
Cognito.defaultContextPath = process.env.CONTEXT_PATH;
Cognito.defaultCookieDomain = process.env.COOKIE_DOMAIN;
Cognito.poolData = {
  UserPoolId: process.env.AWS_COGNITO_USERPOOL_ID,
  ClientId: process.env.AWS_COGNITO_NODE_APP_CLIENT_ID
};
```

## Examples:
```
// Get access / refresh token via API
//
let error, result = await Cognito.getTokenByAPI(username, password, rememberDevice).catch(err => error = err);
if (error) { return res.json({ success: false, message: error.message || JSON.stringify(error) }); }

// Set access token to httpOnly cookie
//
Cognito.setCookie(res, "accessToken", accessToken);

// Set refresh token to httpOnly cookie
//
Cognito.setCookie(res, "refreshToken", refreshToken);

// Forgot password flow - Send verification code and then confirm new password
// Authenticated session is not required
// send verfication code
//
await Cognito.sendForgotPasswordCode(username).catch(err => error = err);

// confirm password
//
await Cognito.confirmPassword(username, newPassword, verificationCode).catch(err => error = err);

// change password
// Authenticated session is required
//
await Cognito.changePassword(username, oldPassword, newPassword).catch(err => error = err);

// Local sign out
//
Cognito.signOut(res);

// Global sign out
// Authenticated session is required
//
await Cognito.globalSignOut(username).catch(err => error = err);

```

**References:**
* https://medium.com/@janitha000/authentication-using-amazon-cognito-and-nodejs-c4485679eed8
* https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
* https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-integration.html
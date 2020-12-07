# Authentication opertions via AWS Cognito and ExpressJS
## Features:
* Authorization Code Grant and Implicant Grant via AWS Host UI
* Refresh session by refresh token
* Add tokens to cookie

**Initiatization is required when app starts. Here is an example.**

```
Cognito.authDomain = process.env.AWS_COGNITO_OAUTH_DOMAIN;
Cognito.clientId = process.env.AWS_COGNITO_NODE_APP_CLIENT_ID;
Cognito.scope = process.env.AWS_COGNITO_SCOPE;
Cognito.callBackUrl = process.env.AWS_COGNITO_CALLBACK_URL;
Cognito.accessTokenExp = process.env.AWS_COGNITO_ACCESSTOKEN_EXP;
Cognito.refreshTokenExp = process.env.AWS_COGNITO_REFRESHTOKEN_EXP;
Cognito.pool_region = process.env.AWS_COGNITO_POOL_REGION;
Cognito.poolData = {
  UserPoolId: process.env.AWS_COGNITO_USERPOOL_ID,
  ClientId: process.env.AWS_COGNITO_NODE_APP_CLIENT_ID
};
```

**References:**
* https://medium.com/@janitha000/authentication-using-amazon-cognito-and-nodejs-c4485679eed8
* https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
* https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-integration.html
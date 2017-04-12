# Demo 6: OpenID Connect using Auth0

In [Demo 5](../demo5_oauth2-using-auth0) we set up a Resource Server as well as an Auth0 Authorization Server to demonstrate how to use OAuth2 to authorize requests from a client (Postman) to the Resource Server. [OpenID Connect](http://openid.net/specs/openid-connect-core-1_0.html) (OIDC) is really just an identity layer on top of OAuth2, where _authentication_ occurs and information about the user's identity is passed back in the OAuth2 response.

## Invoking OIDC using Postman

The good news is Auth0 is already an OIDC Provider so enabling OIDC in an Authorization Code Grant flow is as simple as including OIDC scopes in the authorization request. Therefore to demo OIDC, we can start where we left off in Demo 5:

1. Run the [Demo 5 Resource Server](../demo5_oauth2-using-auth0#testing).
1. Configure OAuth2 in Auth0 just like we did in [Demo 5](../demo5_oauth2-using-auth0#authorization-server-auth0)
1. Configure Postman just like we did in [Demo 5](../demo5_oauth2-using-auth0#calling-the-resource-server-using-postman), except when we click the **Get New Access Token** button, change the **Scope** property so that we prepend a few OIDC scopes:

   * Scope: `openid email profile read:timesheets create:timesheets`

> The `openid` scope is required for OIDC to activate at all during the flow. The `email` and `profile` scopes will return specific user profile claims.

The result is that the response from Auth0 will not only contain an `access_token`, but also an `id_token`. That ID Token will contain all of the OIDC claims about the user associated with the `email` and `profile` scopes. The client can then use that `id_token` as a representation of the authenticated user. 

Here's an example JSON `payload` of the resulting ID Token:

```json
{
  "email": "user1@example.com",
  "email_verified": false,
  "name": "user1@example.com",
  "nickname": "user1",
  "picture": "https://s.gravatar.com/avatar/111d68d06e2d317b5a59c2c6c5bad808?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fus.png",
  "updated_at": "2017-04-12T15:08:54.869Z",
  "iss": "https://YOUR_AUTH0_DOMAIN/",
  "sub": "auth0|YOUR_USER_ID",
  "aud": "POSTMAN_CLIENT_ID",
  "exp": 1492045736,
  "iat": 1492009736
}
```

Now the client (Postman) can continue on and call the Resource Server with the `access_token`, which provides the same authorization as the access token obtained in Demo 5. And if it was a real client, it could store the ID Token locally and use it as a representation of the authenticated user, aka the user's identity. For example, if the client were a regular website, it may use the claims in the ID Token to build a local server-side session that's tracked with a cookie. If the client were a Single Page App, it may just store the ID Token in local storage.

## Obtaining the User Profile via the UserInfo Endpoint

OIDC also defines its own Resource Server endpoint called `/userinfo` that allows the client to fetch the authenticated user's profile. This is an alternative to consuming the ID Token itself and can be a handy way to get user profile updates until the `access_token` expires.

To call the `/userinfo` endpoint, you actually use the same `access_token` you would use to call your own Resource Owner endpoint. If you look at the access token generated with OIDC enabled, you'll notice it has an extra audience (`aud` claim) that's specifically for the `/userinfo` endpoint in your Auth0 tenant:

```json
{
  "iss": "https://YOUR_AUTH0_DOMAIN.auth0.com/",
  "sub": "auth0|YOUR_USER_ID",
  "aud": [
    "https://example.com/api/timesheets",
    "https://YOUR_AUTH0_DOMAIN/userinfo"
  ],
  "azp": "POSTMAN_CLIENT_ID",
  "exp": 1492096136,
  "iat": 1492009736,
  "scope": "openid email profile read:timesheets create:timesheets"
}
```

Just use cURL or Postman to perform a GET request to that endpoint, passing the `access_token` as a bearer token:

```bash
curl "https://YOUR_AUTH0_DOMAIN/userinfo" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

And you'll get a JSON response that look like this:

```json
{
  "sub": "auth0|YOUR_USER_ID",
  "email": "user1@example.com",
  "email_verified": false,
  "name": "user1@example.com",
  "nickname": "user1",
  "picture": "https://s.gravatar.com/avatar/111d68d06e2d317b5a59c2c6c5bad808?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fus.png",
  "updated_at": "2017-04-12T15:08:54.869Z"
}
```

Basically you get back all the same claims as what are in the ID Token, minus the core OIDC ID Token claims like `iss`, `aud`, `exp`, and `iat`.

# Demo 5: OAuth2 using Auth0

This demo is very similar to [Demo 4](../demo4_simple-oauth2) except we're using Auth0 as the OAuth2 Authorization Server instead of using our own.

## Resource Server

This demo's Resource Server is identical to the [Demo 4 Resource Server](demo4_simple-oauth2/SimpleOAuth2.ResourceServer), except that it verifies the JWT access token using the configured Auth0 tenant's public key. The JWT access token can therefore only have been asymmetrically signed using RS256 by Auth0 using the Auth0 tenant's private key. This is a more secure approach vs the HS256-signed JWTs used in Demo 4, which require the shared secret to be stored at the both the Authorization Server and the Resource Server.

### Testing

Before you can run the Resource Server, it requires some configuration to be set via [Secret Manager](https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets), so your Auth0-specific configuration isn't hard-coded into the [appsettings.json](Auth0OAuth2.ResourceServer/appsettings.json) file:

```bash
dotnet user-secrets set Auth0:Domain YOUR_AUTH0_DOMAIN
dotnet user-secrets set Auth0:ApiIdentifier https://example.com/api/timesheets
```

Because of the nature of the asymmetrically-signed JWTs, there's no way to generate an access token for this Resource Server by hand (eg. using [jwt.io](https://jwt.io/)) unless you have access to the private key, which only Auth0 has. We will obtain one in the next step by performing an OAuth2 flow with Auth0. 

But if you did have a token, the process is the same as with Demo 4. First, you would run the resource server:

```bash
cd Auth0OAuth2.ResourceServer
dotnet run
```

and then call the API using cURL or Postman:

```bash
curl "http://localhost:5000/api/timesheets" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## Authorization Server (Auth0)

Instead of a very limited custom OAuth2 Authorization Server like we had in [Demo 4](demo4_simple-oauth2/SimpleOAuth2.AuthorizationServer), in this demo we're going to use a full-featured Auth0 implementation.

Here are the steps to getting one ready for our demo:

1. If you haven't done so already, [sign up](https://auth0.com/) for a free Auth0 account.
1. Create a new [API](https://manage.auth0.com/#/apis) for our Resource Server:
   * Name: `Timesheets API`
   * Identifier: `https://example.com/api/timesheets`
   * Add these scopes under the **Scopes** tab:
     * Name: `create:timesheets`, Description: `Create your timesheets`
     * Name: `read:timesheets`, Description: `Read your timesheets`
1. Create a new [client](https://manage.auth0.com/#/clients) for "First-Party" Postman:
   * Name: `Postman (First-Party)`
   * Type: `Regular Web App`
   * Allowed Callback URL: `https://www.getpostman.com/oauth2/callback`
1. Create a new [client](https://manage.auth0.com/#/clients) for "Third-Party" Postman:
   * Name: `Postman (Third-Party)`
   * Type: `Regular Web App`
   * Allowed Callback URL: `https://www.getpostman.com/oauth2/callback`
1. Create a new [user](https://manage.auth0.com/#/users) in the `Username-Password-Authentication` database connection that we can use to perform authentication

### First-Party vs. Third-Party

By default all clients in Auth0 are first-party, which means your Auth0 tenant assumes they are apps belonging to the same organization who's managing the tenant itself. Therefore Auth0 trusts the client and will not prompt the user for consent when obtaining an authorization grant. Any scopes that a first-party client requests will be automatically granted, as long as they have been in the respective API.

However, we also want to demonstrate third-party client behavior, where the Auth0 tenant doesn't trust the client because they have been developed by a third party. In this scenario the user should be be prompted during the authorization process on whether or not they are willing to authorize the third-party client to have the scopes requested. 

At the time of this writing, the only way to configure a client in Auth0 to be third-party is to use the **Auth0 Management API** - Dashboard GUI support is coming soon. To do this, follow steps `5` through `16` of the [Auth0 Configuration](https://gist.github.com/twistedstream/c145ed12f6f12a9a8b7e939d51a3f2d5#auth0-configuration) section of this **3rd Party Client Setup for Auth0 API Authorization** guide. Do this only for the `Postman (Third-Party)` client created above.

## Calling the Resource Server using Postman

Instead of testing an OAuth2 flow directly with the Authorization Server (Auth0), [like we did in Demo 4](../demo4_simple-oauth2/README.md#testing-1), we'll jump right to using [Postman](https://www.getpostman.com/) to call our Resource Server. And like in Demo 4, we'll use the built-in Postman OAuth2 Authorization feature to obtain the required access token.

Open Postman and prepare a GET request to the URL `http://localhost:5000/api/timesheets` which requires an access token with at least the `read:timesheets` scope.

To obtain that access token, under the _Authorization_ tab, change the **Type** from `No Auth` to `OAuth 2.0`. Then click the **Get New Access Token** button and populate the dialog with the following values:

* Token Name: `Auth0 Token` (this is arbitrary)
* Auth URL: `https://YOUR_AUTH0_DOMAIN/authorize?audience=https://example.com/api/timesheets`
* Access Token URL: `https://YOUR_AUTH0_DOMAIN/oauth/token`
* Client ID: `CLIENT_ID`
* Client Secret: `CLIENT_SECRET`
* Scope: `read:timesheets create:timesheets`
* Grant Type: `Authorization Code`

> NOTE: The **Auth URL** that points to your Auth0 tenant has a special query parameter called `audience`. This tells Auth0 what API (Resource Server) that the client wants access to since your tenant could have more than one API defined.

### Testing the First-Party Client

Start by using the `CLIENT_ID` and `CLIENT_SECRET` values from the `Postman (First-Party)` client you created in Auth0.

When you click the **Request Token** button a popup web view will open and you will be taken through the flow. You most likely need to first authenticate the user. If successful you will see a new result under **Existing Tokens** called `Auth0 Token`. If you select it, you will see its contents on the right-hand side, which will include an `access_token`.

Click the **Use Token** button to attach it to the `Authorization` header of the GET request as a `Bearer` token. Click the Postman **Send** button and the Resource Server should respond with 200 and JSON data representing the user's timesheets.

### Testing the Third-Party Client

To see third-party client behavior, obtain another access token in Postman, but this time use the `CLIENT_ID` and `CLIENT_SECRET` values from the `Postman (Third-Party)` client you created in Auth0. Everything will be the same as with the first-party client except you will also be prompted for consent in the popup web view.

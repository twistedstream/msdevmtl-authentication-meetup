# Demo 4: Simple OAuth2

In this demo, we're demonstrating a simple OAuth2 server implementation (Authorization Code Grant Flow only).

## Resource Server

The first component is the [Resource Server](SimpleOAuth2.ResourceServer) (API) that we're trying to protect. It's a very simple API with a handlful of endpoints. Only one of them requires no authorization at all ([/api/ping](./SimpleOAuth2.ResourceServer/Controllers/PingController.cs#L12)). The others require a valid access token and some even require specific scopes to be present.

This resource server expects the access token to be a non-expired, symmetrically-signed JWS with a specifc set of claims like issuer (`iss`) and audience (`aud`). Scope comes from the the `scope` claim.

### Testing

To test the resource server itself without using the OAuth2 server to generate the access token, you can use [jwt.io](https://jwt.io) to craft a self-signed JWS (HS256). It needs the following payload:

```json
{
  "sub": "1234567890",
  "iss": "https://oauth.example.com/",
  "aud": "https://api.example.com/",
  "exp": 1491403378,
  "iat": 1491399778,
  "scope": "read:timesheets create:timesheets"
}
```

where `exp` and `iat` need to be valid (i.e. the token hasn't been issued in the future and has not yet expired). 

You can generate the `iat` (Issued At) claim using [epochconverter.com](https://www.epochconverter.com/). Then just calculate an `exp` (Expires) claim by adding whatever expiration timespan you want (eg. 1 hour = 3600 seconds).

Then sign the token using [the secret configured in the resource server configuration](./SimpleOAuth2.ResourceServer/appsettings.json#L12).

With a generated token, you can then run the resource server:

```bash
cd SimpleOAuth2.ResourceServer
dotnet run
```

and then call the API using cURL or Postman:

```bash
curl "http://localhost:5000/api/timesheets" \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## Authorization Server

The second component is the OAuth2 [Authorization Server](SimpleOAuth2.AuthorizationServer) itself. While this sample server witten in ASP.NET Core MVC follows to the [OAuth2 spec](https://tools.ietf.org/html/rfc6749), it only performs a narrow set of functionality, namely: the [Authorization Code Grant](https://tools.ietf.org/html/rfc6749#section-4.1) flow. And even with that specific flow, it has several limitations, including:

* The server does not have support for issuing refresh tokens via the `offline_access` scope. 
* Once an authorization grant is issued, there's no mechanism through the app to remove it. You need to either edit the data directly in the SQLite DB or drop the database and start over.

Additionally the only scopes that a client can request that the server will grant are the ones configured in the [appsettings.json](SimpleOAuth2.AuthorizationServer/appsettings.json) file. In the end, this Authorization Server is only meant to be a sample and to demonstrate the complexity required just to impliment a simple OAuth2 flow. Regardless, the server does provide a means to authenticate a Resource Owner (user) and allow that user to grant the authorization request from the client, if the client is flagged as third-party.

### Testing

To test a direct interaction with the Authorization Server, first start it up:

```bash
cd SimpleOAuth2.AuthorizationServer
dotnet run
```

Before you can test a flow, you're going to want to register a user (Resource Owner) within the Authorization Server. Do that here:

```
http://localhost:5000/Account/Register
```

Now to start an authotization flow, navigate to this URL:

```
http://localhost:5000/oauth2/authorize?client_id=client_id_2&response_type=code&redirect_uri=https%3A%2F%2Fapp2.example.com%2Fcallback&scope=read:timesheets%20create:timesheets&state=my-state
```

This will perform an OAuth2 authorization request (Authorization Code Grant flow) for `client_id_2`, requesting scopes `read:timesheets` and `create:timesheets`, sending a `state` value of `my-state`, and ultimately redirecting back to `https://app2.example.com/callback`, which is one of the registered allowed callback URLs for `client_id_2`.

If you weren't already authenticated (which you should be since you just registered your user before attempting the flow), then you first end up at the login page to authentcate. Once authenticated, you should get prompted with a Consent Page, where the Authorization Server is asking the user if they are OK with allowing the client access to those specific scopes. This prompt occurs for two reasons:

1. The client (in this case `client_id_2`) is configured as "third party", which means its not implicitly trusted by the Authorization Server. If you were to try this same flow using client `client_id_1`, which is a "first party" client, you would never be prompted with a Consent Page.
2. There is no existing grant already stored in the Authorization Server that gives the client the same requested scopes.

After you click the **Allow** button on the Consent Page, a grant is created in the database for that specific user / client ID combination and the Authorization Server will redirect to the `redirect_uri`, adding the authorization `code` and `state` as query params:

```
https://app2.example.com/callback?code=578edd30b6884dadb92e09607b5a8596&state=my-state
```

You'll get a DNS error in the browser since that domain name doesn't exist, but you can take the `code` in the URL query and use it to complete the flow, which is done by calling the Token endpoint. This call would be made on the server-side of the client web application.

To do that here, first create a bash variable to store the code:

```bash
AUTHORIZATION_CODE=your-code
```

Then perform this cURL call:

```bash
curl -i "http://localhost:5000/oauth2/token" \
  -X POST \
  -d "code=$AUTHORIZATION_CODE&client_id=client_id_2&client_secret=client_secret_2&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fapp2.example.com%2Fcallback"
```

If successful, you'll get back something like this:

```json
{
  "access_token": "your.access.token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

where `access_token` is the access token (in JTW format) that can be used to call the [Resource Server](#resource-server).

## Calling the Resource Server using Postman

To tie everything together, you can also call the Resource Server from [Postman](https://www.getpostman.com/), where Postman is the "client". Postman has a built-in feature where it can perform an OAuth2 Authorization Code Grant flow with an Authorization Server to obtain a token to call your API. Here's how to make all of this work with our sample:

First, we need to start up both the Resource Server and the Authorization Server locally on different ports. In the `resource_server` directory, we're going to start the Resource Server on the default port (5000):

```bash
dotnet run
```

And then in the `SimpleOAuth2.AuthorizationServer` directory, we'll start the Authorization Server on port 5001:

```bash
ASPNETCORE_URLS="http://*:5001" dotnet run
```

Now we can open Postman and prepare a **GET** request to the URL `http://localhost:5000/api/timesheets` which requires an access token with at least the `read:timesheets` scope.

To obtain that access token, under the _Authorization_ tab, change the **Type** from `No Auth` to `OAuth 2.0`. Then click the **Get New Access Token** button and populate the dialog with the following values:

* Token Name: `Demo Token` (this is arbitrary)
* Auth URL: `http://localhost:5001/oauth2/authorize`
* Access Token URL: `http://localhost:5001/oauth2/token`
* Client ID: `client_id_2`
* Client Secret: `client_secret_2`
* Scope: `read:timesheets create:timesheets`
* Grant Type: `Authorization Code`
* Request access token locally: **CHECKED** (this is important)

A web view will open and you will be taken through the flow. You most likely need to first authenticate the user and then approve the authorization grant. If successful you will see a new token under **Existing Tokens** called `Demo Token`. If you select it, you will see its contents on the right-hand side. 

Click the **Use Token** button to attach it to the `Authorization` header of the GET request as a `Bearer` token. Click the Postman **Send** button and the Resource Server should respond with 200 and JSON data representing the user's timesheets!

## Debugging in VS Code

VS Code debug config files ([launch.json](.vscode/launch.json) and [tasks.json](.vscode/tasks.json)) have been provided in this repository that allow you to debug either the Resource Server or Authorization Server in [VS Code](https://code.visualstudio.com/). In the Debug tab, just choose the conifguration (`Resource Server` or `Authorization Server`) and run. They are configured to run on different ports (`5000` and `5001`, respectively).

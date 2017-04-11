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

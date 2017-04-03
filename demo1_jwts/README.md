# Demo 1: JWTs

Open https://jwt.io (Incognito) and examine the following JWT:

   ```
   eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJqYXNvbkBnbWFpbC5jb20iLCJnaXZlbl9uYW1lIjoiSmFzb24iLCJmYW1pbHlfbmFtZSI6IkJvdXJuZSIsInBpY3R1cmUiOiJodHRwczovL2ltYWdlcy1uYS5zc2wtaW1hZ2VzLWFtYXpvbi5jb20vaW1hZ2VzL00vTVY1Qk1UYzBNRFkxTXpnNU9GNUJNbDVCYW5CblhrRnRaVFl3TWpBd056WTIuX1YxXy5qcGciLCJnZW5lZGVyIjoibWFsZSIsImxvY2FsZSI6ImVuIn0.JEZAzufYlgOKeDJqKki3xqIYo8jdaD4ZLSJyoPuOO_M
   ```

Observations:

* This is an “Unsecured JWT” since it has no signature
* This is _not_ an OpenID Connect **ID Token** since it’s not signed and it’s missing some required claims: `iss`, `aud`, `exp`, and `iat`
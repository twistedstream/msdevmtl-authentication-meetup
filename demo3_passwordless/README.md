# Demo 3: Passwordless

This demo simply demonatrates an implementation of "passwordless" authentication, which is essentially authentication that uses one of the three known authentication factors _besides_ "something you know" (aka a shared secret/password):

1. Something you know
1. Something you have (passwordless)
1. Something you are (passwordless)

Auth0 provides a variety [passwordless](https://auth0.com/passwordless) options. Some are "something you have" (eg. an OTP received over SMS) and some are "something you are" (eg. iOS TouchID, which uses biometrics).

The sample code in this demo was taken from the [Authenticate users with a one-time code via SMS in a SPA](https://auth0.com/docs/connections/passwordless/spa-sms) docs page, but actually contains Passwordless examples for all channels (email, TouchID).

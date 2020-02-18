# go-imap-oauth2

This is a oauth2 provider that use a imap server as authentication backend. To use it is quite easy!

To configure your client you need two urls.

1. The AuthURL:  "http://myownoauth2server.com:9096/authorize"
2. The TokenURL: "http://myownoauth2server.com:9096/token"


The oauth2 Server need a valid SSL Zertificate. If you dont have, some clients can denied to work with it.


# irma-saml-bridge — repo notes

Go service (module root) that is a SAML 2.0 identity provider for the Signicat
broker: AuthnRequest in, Yivi disclosure through an IRMA server, signed
Response out. It replaced a Java 17 service (Spring Boot, OpenSAML) and must
keep behaving like it towards the broker.

## Build & test

- `go vet ./... && go test -race ./...`. The Go version is set in `go.mod`;
  CI runs gofmt, `go fix`, `go mod tidy`, golangci-lint and govulncheck with
  that version, so check with `GOTOOLCHAIN=go<that version>`.
- The tests run the whole service against a service provider (gosaml2) and an
  IRMA server played by the test (`harness_test.go`). No network or Docker.
- `static/assets/app.js` and `app.css` are built from `assets/` by the node
  stage of the Dockerfile and embedded. They are not in the repository; only
  `static/assets/.gitkeep` is, so that `go:embed all:static` has a file.
- Go stays on the release line golangci-lint in the shared workflow is built
  with. A newer `go` line in `go.mod` makes the lint job refuse to run.

## Layout

- `internal/saml`: metadata of the service providers, the HTTP-Redirect
  binding and its signature, the AuthnRequest, the Response and its
  signature, the bridge's own metadata.
- `internal/token` (JWTs), `internal/disclosure` (IRMA session result),
  `internal/irma` (starting a session), `internal/replay` (answered
  requests).
- Root: `config.go`, `keys.go`, `server.go` (routes), `request.go`,
  `assert.go`, `testsp.go` (the `/test` endpoints).
- `testdata/java`: what the Java image answered for config.test.json and
  dev-keys. `TestResponseMatchesJava`, `TestMetadataMatchesJava` and
  `TestVerifyAcceptsRequestsSignedByOpenSAML` compare against it.

## Gotchas

- Towards the broker nothing may change: entity ID, metadata, SSO URL,
  certificate, NameID, attribute names, what is signed, lifetimes. The
  metadata is byte for byte that of the Java service, and the Response equal
  to it outside the signature. Keep `testdata/java` and the tests on it.
- Only the Response is signed. The Assertion has no signature of its own,
  although the brokers' metadata says `WantAssertionsSigned`. That is how the
  Java service did it and what the broker accepts today.
- goxmldsig canonicalizes in place. `Sign` gives it a copy of the Response;
  given the Response itself it strips `xmlns:xsd`, which `xsi:type="xsd:string"`
  still needs. It also cannot write an `InclusiveNamespaces` prefix list, so
  the transform has none where OpenSAML wrote `PrefixList="xsd"`.
- Serialize with `CanonicalText` and `CanonicalAttrVal`. etree otherwise
  writes a carriage return as it is, the receiver's parser turns it into a
  line feed, and the digest no longer matches.
- goxmldsig refuses a certificate outside its validity period. `Verify` pins
  the clock inside it: the bridge signs with an expired certificate, as the
  Java service did, and `dev-keys/idp.crt` expired in 2022. For the same
  reason tests that put gosaml2 on the other side generate a certificate.
- Certificates in service provider metadata are not checked for validity
  either. The ones in `dev-keys/metadata` and one in the ops repository are
  expired and must keep working.
- The redirect signature covers the raw query string. `DecodeRedirect` takes
  the message, the relay state and the signed octets from one pass over it.
  Do not read `r.URL.Query()` next to it.
- A request without an `AssertionConsumerServiceURL` goes to the endpoint
  with the HTTP-Redirect binding, not to the default endpoint. The brokers
  only list HTTP-POST, so they must and do send the URL.
- A condiscon value counts only when it is typed `xsi:type="xs:string"`.
  OpenSAML ignored other values silently and the request fell back to
  `defaultCondiscon`.
- The assertion parameters JWT keeps the claim names and types of the Java
  service (`aparams`, with `request_error` as a JSON string), so that both
  versions read each other's tokens during a rolling update. It is signed
  with the key that also signs the IRMA session requests, hence the check on
  `sub`.
- A request is remembered as answered only after a successful `/assert`.
  Refusing a second `GET /request` would break phones, which reload the page
  when the user returns from the Yivi app. The memory is per process.
- The image needs `/bin/sh`, `openssl` and a writable `/usr/local`: the ops
  repository starts the container with `scripts/entrypoint.sh`, which runs
  `mkdir /usr/local/keys` and `openssl rsa`. Do not move to distroless
  before that script is gone.
- The ops repository (`irma-saml-bridge-ops`) deploys to dev on every pull
  request, and dev runs the `:edge` image with `imagePullPolicy: Always`.
  Changes to it are listed in the pull request here instead of opened there.
- Docker Desktop does not share `/private/tmp`: a bind mount from there shows
  up as an empty directory. Copy files into the container with `docker cp`.

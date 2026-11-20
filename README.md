# irma-saml-bridge

A SAML 2.0 identity provider that lets a user log in by disclosing attributes
with the Yivi app. It makes Yivi available through the Signicat identity
broker: the broker sends a SAML AuthnRequest, the bridge runs a disclosure
session at an IRMA server, and the broker gets a signed SAML Response with
the disclosed attributes.

The bridge is a Go service. It used to be a Java 17 service built on Spring
Boot and OpenSAML; the Go service serves the same endpoints, reads the same
`config.json` and sends the same metadata and Responses.

In the `docs` directory you can find a [flow diagram](docs/flow_diagram.pdf)
and [endpoint documentation](docs/endpoints.pdf), both written for the Java
service.

## How a login goes

1. The broker redirects the browser to `/request` with a signed AuthnRequest
   (HTTP-Redirect binding).
2. The bridge checks the request, starts a disclosure session at the IRMA
   server and answers with a page that shows the QR code.
3. The user discloses with the Yivi app. The page fetches the signed session
   result from the IRMA server and posts it to `/assert`.
4. The bridge checks the result and answers with a signed SAML Response,
   which the page posts to the broker's AssertionConsumerService.

When something goes wrong after step 2, the page asks `/errorassert` for a
Response with the status `Responder` / `AuthnFailed` and posts that instead.

The bridge keeps no session. What it needs to remember between steps 2 and 4
travels through the browser in a JWT it signs itself.

## Endpoints

All paths are below the context path, `/irma-saml-bridge` by default.

| Path | Purpose |
| --- | --- |
| `GET /request` | Takes the AuthnRequest and shows the page with the QR code |
| `POST /assert` | Turns an IRMA session result into a SAML Response |
| `POST /errorassert`, `POST /errorassert/abort` | Make a Response for a failed or cancelled login |
| `POST /report` | Logs an error that happened in the browser |
| `GET /metadata` | SAML metadata of the identity provider |
| `GET /assets/…` | Script and style sheet of the page |
| `GET /actuator/health`, `/actuator/health/liveness`, `/actuator/health/readiness` | Probes, in the format of Spring Boot's actuator |
| `/test/…` | A built-in service provider for testing, see [below](#testing-without-a-broker) |

The service listens on plain HTTP on port 8080. TLS is terminated in front of
it.

## Configuration

### Environment

| Variable | Description |
| --- | --- |
| `CONFIG_PATH` | Path of the configuration file. Defaults to `./config.json` |
| `SERVER_SERVLET_CONTEXT_PATH` | Path the service is served under. Defaults to `/irma-saml-bridge` |
| `SERVER_PORT` | Port to listen on. Defaults to `8080` |

The names are those the Java service read. There, `CONFIG_PATH` was a JVM
system property (`java -DCONFIG_PATH=…`); it is an environment variable now.

### config.json

| Key | Description |
| --- | --- |
| `issuerName` | Entity ID of this identity provider. Defaults to `host` |
| `host` | Host the bridge is reached on, with port if needed. Used for the URLs in the metadata |
| `postfix` | Path after the host, normally the same as the context path |
| `httpsUsed` | Whether the bridge and the IRMA server are reached over https. Defaults to `true` |
| `jwtPrivateKeyPath` | RSA private key that signs the session requests for the IRMA server. The IRMA server has its public half as the key of the requestor named `issuerName` |
| `irmaPublicKeyPath` | RSA public key of the IRMA server, which verifies its session results |
| `testIrmaPrivateKeyPath` | RSA private key that plays the IRMA server for `/test/assert`. Leave it `null` in production |
| `samlCertificatePath` | Certificate that is published in the metadata and in every Response |
| `samlPrivateKeyPath` | RSA private key of that certificate, which signs the Responses |
| `samlMetadataPath` | Directory with the metadata of the service providers that may use the bridge |
| `requestTtlInSec` | How old an AuthnRequest may be. Defaults to 360 |
| `responseTtlInSec` | How long an assertion is valid. Defaults to 360 |
| `defaultCondiscon` | What to ask the user for when the request does not say. Required |
| `defaultMap` | The IRMA server to use: `host` is the host the browser and the app reach it on, `irmaServiceHost` the host the bridge calls, `postfix` the path after either. `{spName}` in `host` and `postfix` is replaced by the `ProviderName` of the request, in lower case, or `test`. Required |
| `irmaMapping` | The same per service provider, by `ProviderName` in lower case |
| `irmaServerTlsInsecureSkipVerify` | Do not verify the certificate of the IRMA server. The Java service never did. Leave it out unless the IRMA server cannot present a valid certificate |

Keys are read as DER, the format the Java service needed, or as PEM. Private
keys may be PKCS#8 or PKCS#1. The service does not start when a file is
missing, when the SAML key does not belong to the certificate, or when a
metadata file cannot be read.

See [config.default.json](config.default.json) and
[config.test.json](config.test.json) for examples.

### Service provider metadata

Every file in `samlMetadataPath` is read at startup: one `EntityDescriptor`,
or an `EntitiesDescriptor` with several. Files whose name starts with a dot
and directories are skipped. Restart the service after changing a file.

A service provider is known by its `entityID`. Its requests are verified
with the certificates its `SPSSODescriptor` lists for signing, and a
Response only goes to one of its `AssertionConsumerService` locations.
Metadata past its `validUntil` is not used. The signature on a metadata file
is not checked: a file is trusted because it is in the directory.

## What a request may ask

The attributes to disclose are a condiscon, as in an
[IRMA session request](https://irma.app/docs/condiscon/). A request can
carry it in six ways:

1. Not at all: `defaultCondiscon` is used.
2. `md:RequestedAttribute` elements named after attribute identifiers, in a
   `req-attr:RequestedAttributes` extension. The attributes of one
   credential are asked together.
3. A `md:RequestedAttribute` named `condiscon` in that extension, with the
   condiscon as JSON in an `AttributeValue` of type `xs:string`.
4. The same, named `signicat:param:condiscon`, as the Signicat broker sends
   it.
5. A plain `saml:Attribute` named `condiscon` in the `Extensions`.
6. The condiscon as JSON in the `Format` of the `NameIDPolicy`.

In the Response every disclosed attribute is a `saml:Attribute` named after
its attribute identifier. The `NameID` is the value of the first attribute by
identifier.

## What is checked

On `/request`:

- The query is read once: the request that is verified is the request that
  is used. A repeated `SAMLRequest`, `RelayState`, `SigAlg` or `Signature`
  is refused.
- The inflated request is at most 128 KiB of XML without a document type
  declaration. There are no entities to expand and nothing external to
  fetch.
- The request is an AuthnRequest with an `ID`, `Version="2.0"` and an
  `IssueInstant` that is at most `requestTtlInSec` old.
- The `Issuer` is a service provider with valid metadata, and the query
  string signature (`SigAlg` RSA with SHA-256, SHA-384 or SHA-512) verifies
  with one of its signing keys. An unsigned request is refused.
- An `AssertionConsumerServiceURL` is one of the service provider's
  endpoints. Without one, its endpoint with the HTTP-Redirect binding is
  used.
- The request was not answered before.

On `/assert`:

- The session result is a JWT signed with the key in `irmaPublicKeyPath`,
  and it has not expired.
- The parameters are a JWT the bridge signed for this purpose.
- The proof status is `VALID`, the disclosed attributes satisfy the
  condiscon of the request, and the result comes from the IRMA session that
  was started for this request.
- The request is answered once. Until then it may be loaded again, which a
  phone does when the user comes back from the Yivi app.

Every Response is signed (RSA-SHA256 over the whole Response, exclusive
canonicalization) and verified with the bridge's own certificate before it
is handed out.

The memory of answered requests is per process. With more than one replica,
a request answered by one is not known to the others.

## Build and test

```bash
go vet ./...
go test -race ./...
```

The tests run the whole service against a service provider and an IRMA
server that the test plays; no network or Docker is needed.

The page needs `static/assets/app.js` and `static/assets/app.css`. They are
built from `assets/` by the node stage of the Dockerfile and are not in the
repository. To build them yourself, with Node.js and Yarn installed:

```bash
assets/build.sh
```

### With Docker

Run an IRMA server that your phone can reach, set its address in
`config.test.json` (`host` and `irmaServiceHost`) and in the `--url` option
of the IRMA server in [docker-compose.yml](docker-compose.yml), and start
everything:

```bash
docker compose up --build
```

### Testing without a broker

The `/test` endpoints play the service provider:

| Path | Purpose |
| --- | --- |
| `GET /test/metadata` | Metadata of the test service provider |
| `GET /test/request` | Sends a signed AuthnRequest to `/request` |
| `POST /test/return` | Where the Response for a test request goes. It is not verified |
| `GET /test/assert` | Plays a complete login and shows the Response as XML. Needs `testIrmaPrivateKeyPath` |
| `POST /test/errorassert`, `/test/errorassert/abort` | The same for a failed login |

The bridge refuses the test service provider like any other until its
metadata is in the metadata directory:

```bash
curl -o ./dev-keys/metadata/sidn-irma-saml-bridge.xml http://localhost:8080/irma-saml-bridge/test/metadata
```

Restart, and open http://localhost:8080/irma-saml-bridge/test/request. You
should see the QR code. Scan it with the Yivi app in developer mode. After
disclosing you land on a page that says the response was received but not
verified.

`/test/request` makes one request per request form:

| Request form | URL |
| --- | --- |
| Default | `/test/request` |
| Requested attributes | `/test/request?mode=attributes&request=["irma-demo.sidn-pbdf.email.email","irma-demo.sidn-pbdf.mobilenumber.mobilenumber"]` |
| Condiscon | `/test/request?mode=condiscon&request=[[["irma-demo.sidn-pbdf.email.email"]],[["irma-demo.sidn-pbdf.mobilenumber.mobilenumber"]]]` |
| Condiscon, Signicat name | `/test/request?mode=condiscon-signicat&request=…` |
| Condiscon in the NameIDPolicy | `/test/request?mode=condiscon-nameid&request=…` |
| Condiscon in an Attribute | `/test/request?mode=condiscon-attribute&request=…` |

Add `fake-issuer` for a request from an unknown service provider and
`old-request` for one that is a day old. Both must be refused.

## Deployment

The image is `ghcr.io/privacybydesign/irma-saml-bridge`: the binary at
`/irma-saml-bridge` on Alpine, running as an unprivileged user. It contains
a shell and `openssl` because
[irma-saml-bridge-ops](https://github.com/privacybydesign/irma-saml-bridge-ops)
starts the container with a script that converts the mounted PEM keys to DER
before it starts the bridge.

Logs go to standard output. There is no log file.

Generate your own keys for production, as the development keys in
`dev-keys` were made with [`bin/init.sh`](bin/init.sh). The key in
`jwtPrivateKeyPath` must be the one the IRMA server knows the requestor by.

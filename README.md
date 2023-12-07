# irma-saml-bridge
IRMA-SAML bridge enabling IRMA as a Service via the Signicat Identity Broker. It acts as a SAML Identity Provider, giving access to IRMA credentials as SAML attributes.

## Quick start
### Setup
You require `docker` to be installed, including `docker-compose`. This setup was tested on **Ubuntu 20.04 LTS**.

```bash
$ sudo apt install docker.io docker-compose
```

Firstly run `ngrok` or similar such that the IRMA instance to use is accessible from the internet.

This step is unnecessary if you use a pre-existing IRMA instance, or if your development machine is accessible by your phone from the local network.

```bash
$ ngrok http 8081
```

Copy the **HTTPS url** (for example: https://9dac70c8cabf.ngrok.io) into `config.test.json` (see example below) and set the URL in the Docker Compose configuration for the IRMA instance as `--url=https://9dac70c8cabf.ngrok.io`.

```json
{
	"issuerName": "sidn-irma-saml-bridge",
	"host": "localhost:8080",
	"postfix": "/irma-saml-bridge",
	"jwtPrivateKeyPath": "./dev-keys/jwt.der",
	"testIrmaPrivateKeyPath": "./dev-keys/irma-test.der",
	"irmaPublicKeyPath": "./dev-keys/irma-test.pub.der",
	"samlCertificatePath": "./dev-keys/idp.crt",
	"samlPrivateKeyPath": "./dev-keys/idp.der",
	"samlMetadataPath": "./dev-keys/metadata",
    "httpsUsed": false,
    "requestTtlInSec": 900,
    "responseTtlInSec": 900,
	"defaultMap": {
		"host": "9dac70c8cabf.ngrok.io",
		"irmaServiceHost": "9dac70c8cabf.ngrok.io",
		"postfix": ""
	},
	"irmaMapping": {
		"test": {
			"host": "9dac70c8cabf.ngrok.io",
			"irmaServiceHost": "9dac70c8cabf.ngrok.io",
			"postfix": ""
		}
	}
}
```

Now initialize the various crypto keys, build assets and run the project:
```bash
$ docker-compose up
```

By default, `docker-compose` caches docker images, so on a second run the previous built images will be used. A fresh build can be enforced using the `--build` flag.
```bash
$ docker-compose up --build
```

#### Without `ngrok`
To run the Docker setup without `ngrok`, we need to change three minor things:
 * Make the `--url` option of the IRMA server configuration in [docker-compose.yml](./docker-compose.yml) use the URL of your choice (for example `http://192.168.0.2:port`)
 * Update the IRMA server domain in [config.test.json](./config.test.json) to the domain of the `--url` option from your IRMA server configuration (see above). In here, use the port of the IRMA server (8089). The NGINX middleware is not necessary for localhost configurations. Make sure you update all `"host"` and `"irmaServiceHost"` fields.

### Building manually
We have a bash script for building the `sidn-irma-saml-bridge` manually. As prerequisite for this script, you need to install Maven for OpenJDK 17, Node.js and `yarn` first.
```bash
$ bin/build.sh
```

After building, the JAR artifact can be found in the `./artifacts/` directory.

You can also check the `Dockerfile` for details on how to build and run.

### Project integration test
We will now proceed by testing your configuration and setup by integrating with a mock-up SAML Service Provider.

First you need to register this SAML Service Provider, by copying its metadata to the appropriate folder.
```bash
curl -o ./dev-keys/metadata/sidn-irma-saml-bridge.xml http://localhost:8080/irma-saml-bridge/test/metadata
```

Note that you need to restart the project for the configuration change to take hold immediately.

```bash
docker-compose down
docker-compose up
```

You can now visit [the test endpoint](http://localhost:8080/irma-saml-bridge/test/request) with your browser.
This endpoint initiates the Service Provider so-called Authentication Request to our IRMA SAML bridge Identity Provider.
You will be redirected immediately.

Now you should see an IRMA QR code. If not, something is wrong with your setup. Note that you have to enable **developer mode** in the IRMA app before scanning this QR code will work (as the IRMA instance is not running in Production mode). Scan the QR-code and issue your name.

You should not at any time encounter a (red) error screen during this process.

You will redirected to a page with the following text:
```
This is a placeholder page to which you have been redirected. No SAML response was verified. It is fine to see this page when testing.
```

This placeholder page does not test the consumption of the SAML response, only the consumption of a valid SAML Authentication Request. For an end-to-end test, we will now integrate with a public service.

### SAMLtest
First, you must establish a metadata link between your IdP and the SAMLtest Service Prodiver by using the [upload form](https://samltest.id/upload.php). Upload the [metadata file](http://127.0.0.1:8080/irma-saml-bridge/metadata) to this form.

You may need to change the following properties in the metadata file:
* the `entityID`, if it is already registered with SAMLtest.
* the `NameIDFormat` to `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`, as we use this field not as it was intended for.
* the `SingleSignOnService` to use the `http` (non-HTTPS) path, i.e. http://localhost:8080/irma-saml-bridge/request, as our server can not respond with HTTPS.

Secondly we need to trust the SAMLtest Service Provider by adding their metadata to our folder.
``` bash
curl -o ./dev-keys/metadata/samltest.xml https://samltest.id/saml/sp
```

Again, you need to restart the project for the configuration change to take hold immediately.

```bash
docker-compose down
docker-compose up
```

You can now perform the test by going to https://samltest.id/start-idp-test/, and by entering `sidn-irma-saml-bridge` or whatever you changed the `entityID` to. Again, scan the QR and you will be redirected. It is not possible (anymore) to view the disclosed credentials using this service.

## Development with IntelliJ IDEA Ultimate
For development you may use any environment you please, but this guide restricts solely to the paid IntelliJ IDEA Ultimate environment.

1. Open this project in IntelliJ, wait for the indices to be built, and open **Run** > **Edit Configurations**.
2. Run 'mvn clean install' to import all dependencies
3. Start IrmaSamlBridgeApplication configuration

You now still need to use an IRMA instance to talk to. You can use the IRMA instance as provided by the docker-compose file, but you will need to run your TomEE instance on a different port if you do so. You can change this port in the **Server** tab under **HTTP port**. Do not forget to change the `host` entry in your configuration file appropriately.

## Configuration options
The IRMA SAML bridge can be configured with a file called `config.json` in the current working directory. You can also use the environment variable `CONFIG_PATH` like `-DCONFIG_PATH='./config.json'` to use a path other than the current working directory for this file.
But it also possible to put the application.yaml and config.json in a config directory in the classpath
**Note:** when not using `CONFIG_PATH` you probably need to change the working directory of your Tomcat instance to the directory containing your locally checked out git repository for the IRMA SAML bridge.

In the JSON file add the following key-value pairs:

These keyfiles need to be referred to by the bridge. You can set the following values in this configuration file:
* `issuerName`: The issuerName for this SAML Identity Provider. When unset/null will use host. This issuerName will be used as EntityID in the SAML session.
* `host`: the default host for this IRMA SAML bridge. Emitted in metadata files, tests etc. May be overridden in specific metadata files if so desired.
* `postfix`: path after the hostname for this IRMA SAML bridge.
* `jwtPrivateKeyPath`: the RSA private key used by this bridge in DER format.
* `testIrmaPrivateKeyPath`: the RSA private key possibly used by this bridge to simulate IRMA go messages in DER format. May be NULL (i.e. in production).
* `irmaPublicKeyPath`: the RSA public key used by IRMA Go in DER format.
* `samlCertificatePath`: the certificate used to sign SAML responses and assertions.
* `samlPrivateKeyPath`: the RSA private key used to sign SAML responses and assertions in DER format.
* `samlMetadataPath`: a folder containing all metadata files.
* `httpsUsed`: should https used for the connection with the IRMA server, default is true
* `requestTtlInSec` ttl for the request in seconds, default is 360
* `responseTtlInSec` ttl for the request in seconds, default is 360
* `defaultCondiscon`: the default condiscon to use when the client does not provide one. This option is mandatory.
* `defaultMap`: Default IRMA host to use when no SAML issuer was matched in the irmaMapping. You can use `{spName}` to provide a dynamic mapping for wildcard hostnames or postfixes.
* `irmaMapping`: a dictionary which specifies for each SAML issuer what IRMA host should be used. Uses the Issuer field in Authnrequests, and uses entityID from the metadata files to make a match.

Such a file will look as follows:
```json
{
	"issuerName": null,
	"host": "localhost:8080",
	"postfix": "/irma-saml-bridge",
	"jwtPrivateKeyPath": "./dev-keys/jwt.key",
	"testIrmaPrivateKeyPath": "./dev-keys/irma.key",
	"irmaPublicKeyPath": "./dev-keys/irma.key.pub",
	"samlCertificatePath": "./dev-keys/idp.crt",
	"samlPrivateKeyPath": "./dev-keys/idp.key",
	"samlMetadataPath": "./dev-keys/metadata",
    "httpsUsed": false,
    "requestTtlInSec": 900,
    "responseTtlInSec": 900,
	"defaultCondiscon": [
		[
			[
				"pbdf.gemeente.personalData.fullname"
			]
		]
	],
	"defaultMap": {
		"host": "{spName}.irma-brug.example.com",
		"irmaServiceHost": "irma-brug.example.com",
		"postfix": ""
	},
	"irmaMapping": {
		"klant": {
			"host": "irma.klant.nl",
			"irmaServiceHost": "irma-brug.example.com",
			"postfix": "/"
		}
	}
}
```
## logging
Default location of logging is in the directory /logs.
The location can be changed by setting the logging.file.path during startup with JVM parameter -Dlogging.file.path=/whatever/path

## Health
To check if the application is UP, goto http://localhost:8080/irma-saml-bridge/actuator/health
```
{
   "status":"UP",
   "groups":[
      "liveness",
      "readiness"
   ]
}
```
The health endpoints http://localhost:8080/irma-saml-bridge/actuator/health/liveness or http://localhost:8080/irma-saml-bridge/actuator/health/readiness can be used in tools like Kubernetes 
## In production
When running the sidn-irma-saml-bridge in production, you are required to generate your own key material analog to the development keys in the `dev-keys` directory. The `openssl` commands to generate these keys are documented in [`bin/init.sh`](bin/init.sh).

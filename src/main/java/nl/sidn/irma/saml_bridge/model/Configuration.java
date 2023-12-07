package nl.sidn.irma.saml_bridge.model;

import lombok.Data;
import nl.sidn.irma.saml_bridge.exception.InvalidConfigurationException;

import java.util.Map;

/**
 * Configuration for SIDN IRMA bridge daemon, parsed from JSON.
 */
@Data
public class Configuration {
	/** The default host for this IRMA SAML bridge.
	 * Emitted in metadata files, tests etc.
	 * May be overridden in specific metadata files if so desired.
	 */
	private String host;

	/** The path after the hostname for this IRMA SAML bridge i.e. /irma-saml-bridge or similar **/
	private String postfix;

	/** The issuerName for this SAML Identity Provider. When unset/null will use host. */
	private String issuerName;

	/** Path to private key which we use to sign JWT messages */
	private String jwtPrivateKeyPath;

	/** Path to private key used to simulate the IRMA go instance, might be NULL (i.e. in production) */
	private String testIrmaPrivateKeyPath;

	/** Path to public key of the IRMA go instance we will communicate with, used to verify their messages */
	private String irmaPublicKeyPath;

	/** Path to certificate used to sign SAML responses and assertions */
	private String samlCertificatePath;

	/** Path to private key used to sign SAML responses and assertions */
	private String samlPrivateKeyPath;

	/** Path to directory containing all metadata files */
	private String samlMetadataPath;

	/** Default condiscon when none is provided by SP. */
	private String[][][] defaultCondiscon;

	/** The default IRMA Host + Prefix to use. In both {spName} is replaced with the corresponding spName. */
	private IrmaPath defaultMap;

	/** A mapping from SAML issuer name to IRMA Host + Prefix */
	private Map<String, IrmaPath> irmaMapping;

	/** Is Https enabled **/
	private boolean httpsUsed = true;

	/** Time how long client requests can be used. **/
	private int requestTtlInSec = 360;

	/** Time how long our assertions can be used. **/
	private int responseTtlInSec = 360;

	/**
	 * @return The issuerName for this SAML Identity Provider. When unset/null will use host.
	 */
	public String getIssuerName() {
		if (this.issuerName == null) {
			return this.host;
		}
		return issuerName;
	}

	/**
	 * Checks whether the current configuration is valid.
	 * In case it is invalid, an exception is thrown with details about the problem.
	 * @throws InvalidConfigurationException
	 */
	public void validate() throws InvalidConfigurationException {
		if (this.getDefaultCondiscon() == null) {
			throw new InvalidConfigurationException("No defaultCondiscon is specified");
		}
	}

	public String getProtocol() {
		return isHttpsUsed() ? "https://" : "http://";
	}

	public String constructUrl(String path) {
		return getProtocol() + getHost() + getPostfix() + path;
	}
}

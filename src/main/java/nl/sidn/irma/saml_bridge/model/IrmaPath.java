package nl.sidn.irma.saml_bridge.model;

import lombok.Data;

/**
 * A configuration stanza specifying at what HTTP path our IRMA go instance is accessible.
 */
@Data
public class IrmaPath {
	/** The hostname of the IRMA go server i.e. irma.klant.nl **/
	private String host;

	/** The hostname of the IRMA go server i.e. irma.klant.nl, for the backend call to start a session **/
	private String irmaServiceHost;

	/** The path after the hostname for the IRMA go server i.e. /v1 or similar **/
	private String postfix;
}

package nl.sidn.irma.saml_bridge.model;

import lombok.Data;

/**
 *  An assertion request as passed to the javascript applet.
 *  Contains assertParameters, again consumed by this Tomcat daemon.
 *  Contains an IRMA token, a disclosure response from IRMA go.
 */
@Data
public class AssertRequest {
	/**
	 * AssertParameters as a signed JWT.
	 */
	private String parameters;

	/**
	 * IRMA disclosure request as a signed JWT.
	 */
	private String token;
}

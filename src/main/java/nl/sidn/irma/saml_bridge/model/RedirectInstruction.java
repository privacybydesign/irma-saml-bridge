package nl.sidn.irma.saml_bridge.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;

/**
 * An object instructing our javascript frontend to redirect the end user to some SAML endpoint,
 * resulting in the end user being redirected to our client.
 */
@Data
@Builder
@AllArgsConstructor
@RequiredArgsConstructor
public class RedirectInstruction {
	/** The SAML response as a base64 inflated string. */
	private String samlResponse;

	/** The service URL to redirect the end user to whilst delivering the samlResponse and relayState. */
	private String serviceUrl;

	/** An optional string that the original service provider handed to us, to hand back to the service provider 1:1. */
	private String relayState;

}

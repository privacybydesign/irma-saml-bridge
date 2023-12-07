package nl.sidn.irma.saml_bridge.model;

/**
 * Status of the response as yielded in the SAML Response.
 */
public enum ResultStatus {
	/** User was authenticated with a specific attribute. */
	SUCCESS,
	/** User was not authenticated either due to canceling, or due to an unforeseen error. */
	FAILED,
}

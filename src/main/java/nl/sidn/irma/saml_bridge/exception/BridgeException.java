package nl.sidn.irma.saml_bridge.exception;

import org.springframework.http.HttpStatusCode;

/**
 * A wrapping exception around acceptable error types that can be directly
 * communicated to the end user.
 */
public class BridgeException extends Exception {
	private HttpStatusCode httpStatusCode;
	private String message;

	public BridgeException(HttpStatusCode httpStatusCode, String message) {
		this.httpStatusCode = httpStatusCode;
		this.message = message;
	}

	@SuppressWarnings("javadoc")
	public int getHttpStatusCode() {
		return httpStatusCode.value();
	}

	public String getMessage() {
		return message;
	}
}

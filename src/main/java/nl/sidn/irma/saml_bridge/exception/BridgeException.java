package nl.sidn.irma.saml_bridge.exception;

import lombok.Getter;
import org.springframework.http.HttpStatusCode;

/**
 * A wrapping exception around acceptable error types that can be directly
 * communicated to the end user.
 */
public class BridgeException extends Exception {
	private final HttpStatusCode httpStatusCode;
	@Getter
    private String message;

	public BridgeException(HttpStatusCode httpStatusCode, String message) {
		this.httpStatusCode = httpStatusCode;
		this.message = message;
	}

	public int getHttpStatusCode() {
		return httpStatusCode.value();
	}

}

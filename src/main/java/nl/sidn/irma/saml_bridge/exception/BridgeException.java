package nl.sidn.irma.saml_bridge.exception;

import org.springframework.http.HttpStatusCode;

/**
 * A wrapping exception around acceptable error types that can be directly
 * communicated to the end user.
 */
public class BridgeException extends Exception {
    private final HttpStatusCode httpStatusCode;

    public BridgeException(HttpStatusCode httpStatusCode, String message) {
        super(message);
        this.httpStatusCode = httpStatusCode;
    }

    public int getHttpStatusCode() {
        return httpStatusCode.value();
    }

}

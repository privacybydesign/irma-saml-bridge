package nl.sidn.irma.saml_bridge.model;

import lombok.Data;

/**
 * A client-side error (in Javascript) that needs to be logged.
 */
@Data
public class ClientError {
	/** The javascript error as a text message. */
	private String message;

	/** The source file the client side code was executing when the error happened. */
	private String source;

	/** The line in the source file the client side code was executing when the error happened. */
	private int lineno;

	/** The starting column in the source file the client side code was executing when the error happened. */
	private int colno;
}

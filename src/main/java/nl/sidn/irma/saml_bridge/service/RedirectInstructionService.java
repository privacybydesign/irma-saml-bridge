package nl.sidn.irma.saml_bridge.service;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.EncodingException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import nl.sidn.irma.saml_bridge.model.*;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.xml.transform.TransformerException;
import java.security.cert.CertificateEncodingException;

/**
 * A service that takes care of populating redirect instructions, which are used to send SAML responses back.
 * Can be used for both successful or failed assertion requests.
 */
@Slf4j
@Service
public class RedirectInstructionService {
	private final OpenSamlService openSamlService;

	public RedirectInstructionService(
			OpenSamlService openSamlService
	) {
		this.openSamlService = openSamlService;
	}

	public RedirectInstruction create(AssertParameters assertParameters, ResultStatus status) throws BridgeException {
		return create(assertParameters, null, status);
	}

	/**
	 * @param assertParameters The assertion parameters this redirect instruction is intended for.
	 * @param disclosure May be null in case status is not SUCCESS.
	 * @param status The status that should be returned as part of this response.
	 * @return A properly populated return instruction.
	 * @throws BridgeException
	 */
	public RedirectInstruction create(AssertParameters assertParameters, Disclosure disclosure, ResultStatus status) throws BridgeException {
		// Create a SAML assertion.
		Response assertion = this.openSamlService.createAssertionResponse(assertParameters, disclosure, status);

		// Encode that SAML assertion as a signed XML response.
		String samlResponse;
		try {
			samlResponse = this.openSamlService.marshallResponse(assertion);
		} catch (MarshallingException e) {
			log.error("action=\"redirectinstruction.create\", error=\"Failed to marshall assertion\"", e);
			throw new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to marshall assertion");
		} catch (TransformerException e) {
			log.error("action=\"redirectinstruction.create\", error=\"Failed to write assertion\"", e);
			throw new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to write assertion");
		} catch (SignatureException | CertificateEncodingException e) {
			// Something was misconfigured with the private key for signing.
			log.error("action=\"redirectinstruction.create\", error=\"Failed to write signature\"", e);
			throw new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to write signature");
		}

		// For debugging we always validate our own signature, but continue when it is invalid.
		try {
			this.openSamlService.verifyAssertionResponse(samlResponse);
		} catch (SignatureException | XMLParserException | UnmarshallingException e) {
			log.error("action=\"redirectinstruction.create\", error=\"Failed to validate signature or format of our assertion\"", e);
			throw new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to validate signature or format of our assertion");
		}

		// Construct the set of instructions to the React applet.
		try {
			return RedirectInstruction.builder()
					.samlResponse(Base64Support.encode(samlResponse.getBytes(), false))
					.serviceUrl(assertParameters.getServiceUrl())
					.relayState(assertParameters.getRelayState())
					.build();
		} catch (EncodingException e) {
			throw new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed with encoding issue: " + e.getMessage());
		}

	}
}

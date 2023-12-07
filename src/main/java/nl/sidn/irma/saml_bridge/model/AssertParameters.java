package nl.sidn.irma.saml_bridge.model;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import lombok.Builder;
import lombok.Data;

import java.util.Map;
import java.util.TreeMap;

/**
 * Parameters as used by the REST called AssertServlet to generate a SAML assertion.
 *
 * This object is passed to the browser / javascript applet, to be passed back again to Tomcat.
 * The intention of this mechanism is to defer the session state to the browser, such that
 * we do not need to keep a database around, and become stateless for easy redundancy.
 *
 * Note that the attributeType needs to be checked to the actual received IRMA response
 * when constructing an assertion.
 */
@Data
@Builder
public class AssertParameters {
	private String spName;
	private String requestId;
	private String serviceUrl;
	private String issuer;
	private String condiscon;
	private String relayState;
	private RequestError requestError;

	/**
	 * Construct a Key-Value-pair object with the fields of this object.
	 * Used to construct a JWT object to be passed over to the browser and back again.
	 *
	 * @return A mapping of the fields in this object.
	 */
	public Map<String, Object> toTreeMap() throws JsonProcessingException {
		Map<String, Object> map = new TreeMap<>();
		map.put("sp_name", this.spName);
		map.put("request_id", this.requestId);
		map.put("service_url", this.serviceUrl);
		map.put("issuer", this.issuer);
		map.put("condiscon", this.condiscon);
		map.put("relay_state", this.relayState);
		map.put("request_error", new ObjectMapper().writeValueAsString(this.requestError));
		return map;
	}

	/**
	 * Reconstruct the object from a JWT claims object by deconstructing the mapping from `toTreeMap`.
	 * @param claims
	 * @return The assert parameters object.
	 */
	public static AssertParameters fromClaims(Claims claims) throws JsonProcessingException {
		@SuppressWarnings("unchecked")
		Map<String, Object> params = (Map<String, Object>) claims.get("aparams");

		return AssertParameters.builder()
				.spName((String) params.get("sp_name"))
				.requestId((String) params.get("request_id"))
				.serviceUrl((String) params.get("service_url"))
				.issuer((String) params.get("issuer"))
				.condiscon((String) params.get("condiscon"))
				.relayState((String) params.get("relay_state"))
				.requestError(new ObjectMapper().readValue((String) params.get("request_error"), RequestError.class))
				.build();
	}
}

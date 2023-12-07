package nl.sidn.irma.saml_bridge.model;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Data;
import nl.sidn.irma.saml_bridge.exception.MalformedException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * An IRMA disclosure extracted from a JSON object.
 * 
 * See https://irma.app/docs/api-irma-server/#get-session-token-result for the structure of the response.
 */
@Data
public class Disclosure {
	/** The disclosed attributeset, i.e. "[irma-demo.MijnOverheid.ageLower.over18]" */
	private Map<String, String> attributes;

	/** Status of the related to the session. Can be VALID, INVALID, etc. */
	private String proofStatus;

	/** Session token or identifier. */
	private String token;

	/**
	 * Extract a Disclosure from a JWT IRMA session result.
	 * 
	 * @param jwt A JWT session result adhering to the documentation as per https://irma.app/docs/api-irma-server/#get-session-token-result.
	 * @return The disclosure.
	 * @throws MalformedException
	 */
	public static Disclosure fromJwt(Jws<Claims> jwt) throws MalformedException {
		ArrayList<ArrayList<Map<String, Object>>> disclosed;

		try {
			// First allocate a temporary value, due to analysis bug in Eclipse
			@SuppressWarnings("unchecked")
			ArrayList<ArrayList<Map<String, Object>>> tmp = (ArrayList<ArrayList<Map<String, Object>>>) jwt.getBody().get("disclosed");
			disclosed = tmp;

		} catch (ClassCastException e) {
			throw new MalformedException();
		}

		Map<String, String> attributes = new TreeMap<>();
		for (List<Map<String, Object>> con : disclosed) {
			boolean allPresent = true;
			Map<String, String> ourAttributes = new TreeMap<>();

			for (Map<String, Object> attribute : con) {
				String status = (String) attribute.get("status");
				// TODO: Optional attributes (with status NULL) cannot be handled.
				if (!status.equals("PRESENT")) {
					allPresent = false;
					break;
				}
				ourAttributes.put((String) attribute.get("id"), (String) attribute.get("rawvalue"));
			}

			if (allPresent) {
				// TODO: Handle case when multiple conjunctions contain the same attribute type.
				attributes.putAll(ourAttributes);
			}
		}

		Disclosure result = new Disclosure();
		result.attributes = attributes;
		result.proofStatus= (String) jwt.getBody().get("proofStatus");
		result.token = (String) jwt.getBody().get("token");

		return result;
	}

	/**
	 * Checks whether our attributes fulfill the specified condiscon.
	 * @param condiscon
	 * @return Compliance or failure.
	 */
	public boolean fulfillsCondiscon(String[][][] condiscon) {
		for (String[][] discon : condiscon) {
			if (!this.fulfillsDiscon(discon)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Checks whether our attributes fulfill the specified discon.
	 * @param discon
	 * @return Compliance or failure.
	 */
	public boolean fulfillsDiscon(String[][] discon) {
		for (String[] con : discon) {
			if (this.fulfillsCon(con)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks whether our attributes fulfill the specified con.
	 * @param con
	 * @return Compliance or failure.
	 */
	public boolean fulfillsCon(String[] con) {
		for (String id : con) {
			if (!this.attributes.keySet().contains(id)) {
				return false;
			}
		}
		return true;
	}
}

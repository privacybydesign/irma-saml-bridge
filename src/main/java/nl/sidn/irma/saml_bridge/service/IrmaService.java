package nl.sidn.irma.saml_bridge.service;

import lombok.extern.slf4j.Slf4j;
import nl.sidn.irma.saml_bridge.exception.BridgeException;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
public class IrmaService {

    private static final String LOG_MESSAGE = "action=\"request-flow\", warning=\"Error with http status {} - during IRMA start session: {}\"";

    private final RestTemplate restTemplate;

    public IrmaService(
            RestTemplate restTemplate
    ) {
        this.restTemplate = restTemplate;
    }

    public String startSession(String token, String host) throws BridgeException {
        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    host + "/session",
                    HttpMethod.POST,
                    new HttpEntity<>(token, getRequestHeader()),
                    String.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                return response.getBody();
            }

        } catch (HttpClientErrorException e) {
            log.error(LOG_MESSAGE, e.getStatusCode().value(), e.getMessage());
            throw new BridgeException(e.getStatusCode(), e.getMessage());
        } catch (Exception e) {
            log.error(LOG_MESSAGE, HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
            throw new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong when trying to connect with the IRMA server");
        }
        log.error(LOG_MESSAGE, HttpStatus.INTERNAL_SERVER_ERROR, "Start session was not successful");
        throw new BridgeException(HttpStatus.INTERNAL_SERVER_ERROR, "Start session was not successful");
    }

    HttpHeaders getRequestHeader() {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE);
        return headers;
    }
}

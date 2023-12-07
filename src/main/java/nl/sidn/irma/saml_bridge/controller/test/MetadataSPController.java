package nl.sidn.irma.saml_bridge.controller.test;

import lombok.extern.slf4j.Slf4j;
import nl.sidn.irma.saml_bridge.service.OpenSamlService;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;

/**
 * Generates the SAML metadata.xml file for this Identity Provider.
 */
@Slf4j
@Controller
@RequestMapping("/test/metadata")
public class MetadataSPController {

    private final OpenSamlService openSamlService;

    public MetadataSPController(
            OpenSamlService openSamlService) {
        this.openSamlService = openSamlService;
    }

    @GetMapping(value = "")
    public void testMetadata(
            HttpServletResponse response) throws IOException {
        // Default to Internal Server Error
        response.setStatus(500);

        EntityDescriptor metadata;
        try {
            metadata = this.openSamlService.createSPMetadata();
        } catch (CertificateEncodingException e) {
            log.error("Failed to emit certificate", e);
            return;
        }

        String samlResponse;
        try {
            samlResponse = this.openSamlService.marshallMetadata(metadata);
        } catch (MarshallingException e) {
            log.error("Failed to marhshall assertion", e);
            return;
        } catch (TransformerException e) {
            log.error("Failed to write assertion", e);
            return;
        }

        // We were able to generate the file, go back to 200 OK.
        response.setStatus(200);
        response.getWriter().write(samlResponse);
    }
}

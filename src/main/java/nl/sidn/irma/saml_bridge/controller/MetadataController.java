package nl.sidn.irma.saml_bridge.controller;

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

@Slf4j
@Controller
@RequestMapping("/metadata")
public class MetadataController {
    private final OpenSamlService openSamlService;

    public MetadataController(
            OpenSamlService openSamlService) {
        this.openSamlService = openSamlService;
    }

    @GetMapping(value = "")
    public void metadata(HttpServletResponse response) throws IOException {
        // Default to Internal Server Error
        response.setStatus(500);

        EntityDescriptor metadata;
        try {
            metadata = openSamlService.createIdPMetadata();
        } catch (CertificateEncodingException e) {
            log.error("action=\"metadata-flow.create-idp-metadata\", error=\"Failed to emit certificate\"", e);
            response.getWriter().write("Failed to emit certificate");
            return;
        }

        String samlResponse;
        try {
            samlResponse = openSamlService.marshallMetadata(metadata);

        } catch (MarshallingException e) {
            log.error("action=\"metadata-flow.marshall-metadata\", error=\"Failed to marshall assertion\"", e);
            response.getWriter().write("Failed to marshall assertion");
            return;
        } catch (TransformerException e) {
            log.error("action=\"metadata-flow.marshall-metadata\", error=\"Failed to write assertion\"", e);
            response.getWriter().write("Failed to write assertion");
            return;
        }

        // We were able to generate the file, go back to 200 OK.
        response.setStatus(200);
        response.getWriter().write(samlResponse);
    }
}

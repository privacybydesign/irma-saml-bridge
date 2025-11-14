package nl.sidn.irma.saml_bridge.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import nl.sidn.irma.saml_bridge.model.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(SpringExtension.class)
class ConfigurationServiceTest {

    ObjectMapper objectMapper;

    ConfigurationService configurationService;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        configurationService = new ConfigurationService(objectMapper);
    }

    @Test
    void getConfigurationTest() {
        final Configuration configuration = configurationService.getConfiguration();
        assertNotNull(configuration);
    }

}
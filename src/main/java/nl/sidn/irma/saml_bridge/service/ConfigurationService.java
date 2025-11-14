package nl.sidn.irma.saml_bridge.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import nl.sidn.irma.saml_bridge.exception.InvalidConfigurationException;
import nl.sidn.irma.saml_bridge.model.Configuration;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * Service that loads the JSON configuration for the SIDN IRMA SAML bridge at boot.
 * <p>
 * TODO reload every minute
 */

@Slf4j
@Service
public class ConfigurationService {
    private static final String CONFIG_PATH = "./config.json";
    private static final String DEFAULT_CONFIG_PATH = "./config.default.json";
    private final ObjectMapper objectMapper;

    @Getter
    private Configuration configuration;

    public ConfigurationService(
            final ObjectMapper objectMapper
    ) {
        this.objectMapper = objectMapper;
        initialize();
    }

    /**
     * Initializes the configuration by locating and loading a JSON configuration file.
     *
     * <p>Resolution order:
     * <ol>
     *   <li>If the system property {@code CONFIG_PATH} is set, that path is used.</li>
     *   <li>Otherwise, if a {@code config.json} file exists in the working directory,
     *       it is used.</li>
     *   <li>Otherwise, {@code config.default.json} is loaded as a fallback.</li>
     * </ol>
     *
     * <p>If the configuration file cannot be read or contains invalid values,
     * this method throws an {@link IllegalStateException}, causing application
     * startup to fail fast with a clear error.
     *
     * <p>On successful loading, the configuration is parsed, validated, and stored
     * in {@link #configuration}.
     */
    private void initialize() {
        String path = System.getProperty("CONFIG_PATH");
        if (StringUtils.isEmpty(path)) {
            final File file = new File(CONFIG_PATH);
            path = file.exists() ? CONFIG_PATH : DEFAULT_CONFIG_PATH;
        }

        try (final FileReader fr = new FileReader(path)) {
            configuration = objectMapper.readValue(fr, Configuration.class);
            log.info("action=\"initialize\", Loaded configuration from path=\"{}\"", path);
            configuration.validate();
        } catch (final InvalidConfigurationException e) {
            log.error("Invalid configuration was found", e);
            throw new IllegalStateException("Invalid configuration at " + path, e);
        } catch (final IOException e) {
            log.error("Could not load configuration from {}", path, e);
            throw new IllegalStateException("Could not load configuration from " + path, e);
        }
    }

}

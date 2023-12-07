package nl.sidn.irma.saml_bridge.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import nl.sidn.irma.saml_bridge.exception.InvalidConfigurationException;
import nl.sidn.irma.saml_bridge.model.Configuration;
import org.springframework.stereotype.Service;

import java.io.FileReader;
import java.io.IOException;

/**
 * Service that loads the JSON configuration for the SIDN IRMA SAML bridge at boot.
 * 
 * TODO reload every minute
 */

@Slf4j
@Service
public class ConfigurationService {
	private static final String DEFAULT_CONFIG_PATH = "./config.json";
	private final ObjectMapper objectMapper;

	private Configuration configuration;

	public ConfigurationService(
			ObjectMapper objectMapper
	) {
		this.objectMapper = objectMapper;
		initialize();
	}

	/**
	 * Loads JSON configuration from CONFIG_PATH, or from DEFAULT_CONFIG_PATH.
	 */
	private void initialize() {
		String path = System.getProperty("CONFIG_PATH");

		if (path == null) {
			path = DEFAULT_CONFIG_PATH;
		}
		try {
			FileReader fr = new FileReader(path);
			configuration = objectMapper.readValue(fr, Configuration.class);
			log.info("action=\"initialize\", Loaded configuration from path=\"{}\"", path);

			configuration.validate();
		} catch (InvalidConfigurationException e) {
			log.error("Invalid configuration was found", e);
		} catch (NullPointerException | IOException e) {
			log.error("Could not load configuration", e);
		}
	}

	@SuppressWarnings("javadoc")
	public Configuration getConfiguration() {
		return configuration;
	}
}

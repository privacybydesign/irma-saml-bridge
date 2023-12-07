package nl.sidn.irma.saml_bridge.config;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SamlConfiguration {

    @Bean
    public ParserPool parserPool() throws ComponentInitializationException {
        BasicParserPool basicParserPool = new BasicParserPool();
        basicParserPool.setMaxPoolSize(100);
        basicParserPool.setCoalescing(true);
        basicParserPool.setIgnoreComments(true);
        basicParserPool.setIgnoreElementContentWhitespace(true);
        basicParserPool.setNamespaceAware(true);
        basicParserPool.initialize();
        return basicParserPool;
    }
}

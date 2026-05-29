package nl.sidn.irma.saml_bridge.config;

import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.xml.impl.BasicParserPool;
import net.shibboleth.shared.xml.ParserPool;
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

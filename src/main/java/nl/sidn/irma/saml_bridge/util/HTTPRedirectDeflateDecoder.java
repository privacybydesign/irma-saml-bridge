/*
 * Inspired on the OpenSAML class with the same name, but uses the jakarta servlet
 * API instead of the javax servlet API.
 *
 * The original license is included below.
 * 
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.sidn.irma.saml_bridge.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

import org.apache.commons.text.StringEscapeUtils;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.BindingDescriptor;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

/**
 * SAML 2.0 HTTP Redirect decoder using the DEFLATE encoding method.
 * 
 * This decoder only supports DEFLATE compression.
 */
public class HTTPRedirectDeflateDecoder implements SAMLMessageDecoder {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(HTTPRedirectDeflateDecoder.class);

    /**
     * Optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext}
     * created.
     */
    @Nullable
    private BindingDescriptor bindingDescriptor;

    /**
     * HTTPServletRequest used to retrieve the message to be decoded.
     */
    private HttpServletRequest httpServletRequest;

    /** Parser pool used to deserialize the message. */
    @Nonnull
    private ParserPool parserPool;

    /** Message context. */
    private MessageContext messageContext;

    /** Whether the decoder is initialized */
    private boolean isInitialized;

    /** Whether the decoder is destroyed */
    private boolean isDestroyed;

    /**
     * Constructor.
     */
    public HTTPRedirectDeflateDecoder() {
        parserPool = XMLObjectProviderRegistrySupport.getParserPool();
    }

    /** {@inheritDoc} */
    @Nonnull
    @NotEmpty
    public String getBindingURI() {
        return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
    }

    /**
     * Get an optional {@link BindingDescriptor} to inject into
     * {@link SAMLBindingContext} created.
     * 
     * @return binding descriptor
     */
    @Nullable
    public BindingDescriptor getBindingDescriptor() {
        return bindingDescriptor;
    }

    /**
     * Set an optional {@link BindingDescriptor} to inject into
     * {@link SAMLBindingContext} created.
     * 
     * @param descriptor a binding descriptor
     */
    public void setBindingDescriptor(@Nullable final BindingDescriptor descriptor) {
        bindingDescriptor = descriptor;
    }

    /**
     * Get the HTTPServletRequest used to retrieve the message to be decoded.
     * 
     * @return the HTTPServletRequest used to retrieve the message to be decoded
     */
    @Nonnull
    public HttpServletRequest getHttpServletRequest() {
        return httpServletRequest;
    }

    /**
     * Set the HTTPServletRequest used to retrieve the message to be decoded.
     * 
     * @param request the HTTPServletRequest used to retrieve the message to be
     *                decoded
     */
    public void setHttpServletRequest(@Nonnull final HttpServletRequest request) {
        httpServletRequest = request;
    }

    /** {@inheritDoc} */
    public void decode() throws MessageDecodingException {
        final MessageContext msgContext = new MessageContext();

        if (!"GET".equalsIgnoreCase(httpServletRequest.getMethod())) {
            throw new MessageDecodingException("This message decoder only supports the HTTP GET method");
        }

        final String samlEncoding = StringSupport.trimOrNull(httpServletRequest.getParameter("SAMLEncoding"));
        if (samlEncoding != null && !SAMLConstants.SAML2_BINDING_URL_ENCODING_DEFLATE_URI.equals(samlEncoding)) {
            throw new MessageDecodingException("Request indicated an unsupported SAMLEncoding: " + samlEncoding);
        }

        final String relayState = httpServletRequest.getParameter("RelayState");
        log.debug("Decoded RelayState: {}", StringEscapeUtils.escapeJava(relayState));
        SAMLBindingSupport.setRelayState(msgContext, relayState);

        final String samlMessageEncoded = !Strings.isNullOrEmpty(httpServletRequest.getParameter("SAMLRequest"))
                ? httpServletRequest.getParameter("SAMLRequest")
                : httpServletRequest.getParameter("SAMLResponse");

        if (samlMessageEncoded != null) {
            try (final InputStream samlMessageIns = decodeMessage(samlMessageEncoded)) {
                final SAMLObject samlMessage = (SAMLObject) unmarshallMessage(samlMessageIns);
                msgContext.setMessage(samlMessage);
                log.debug("Decoded SAML message");
            } catch (final IOException e) {
                throw new MessageDecodingException("InputStream exception decoding SAML message", e);
            }
        } else {
            throw new MessageDecodingException(
                    "No SAMLRequest or SAMLResponse query path parameter, invalid SAML 2 HTTP Redirect message");
        }

        populateBindingContext(msgContext);

        this.messageContext = msgContext;
    }

    /**
     * Helper method that deserializes and unmarshalls the message from the given
     * stream.
     * 
     * @param messageStream input stream containing the message
     * 
     * @return the inbound message
     * 
     * @throws MessageDecodingException thrown if there is a problem deserializing
     *                                  and unmarshalling the message
     */
    private XMLObject unmarshallMessage(final InputStream messageStream) throws MessageDecodingException {
        try {
            final XMLObject message = XMLObjectSupport.unmarshallFromInputStream(parserPool, messageStream);
            return message;
        } catch (final XMLParserException e) {
            log.error("Error unmarshalling message from input stream: {}", e.getMessage());
            throw new MessageDecodingException("Error unmarshalling message from input stream", e);
        } catch (final UnmarshallingException e) {
            log.error("Error unmarshalling message from input stream: {}", e.getMessage());
            throw new MessageDecodingException("Error unmarshalling message from input stream", e);
        }
    }

    /**
     * Base64 decodes the SAML message and then decompresses the message.
     * 
     * @param message Base64 encoded, DEFALTE compressed, SAML message
     * 
     * @return the SAML message
     * 
     * @throws MessageDecodingException thrown if the message can not be decoded
     */
    protected InputStream decodeMessage(final String message) throws MessageDecodingException {
        log.debug("Base64 decoding and inflating SAML message");

        try {
            final byte[] decodedBytes = Base64Support.decode(message);
            return new NoWrapAutoEndInflaterInputStream(new ByteArrayInputStream(decodedBytes));
        } catch (final Exception e) {
            log.error("Unable to Base64 decode and inflate SAML message: {}", e.getMessage());
            throw new MessageDecodingException("Unable to Base64 decode and inflate SAML message", e);
        }
    }

    /**
     * Populate the context which carries information specific to this binding.
     * 
     * @param messageContext the current message context
     */
    protected void populateBindingContext(final MessageContext messageContext) {
        final SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class, true);
        bindingContext.setBindingUri(getBindingURI());
        bindingContext.setBindingDescriptor(bindingDescriptor);
        bindingContext.setHasBindingSignature(
                !Strings.isNullOrEmpty(getHttpServletRequest().getParameter("Signature")));
        bindingContext.setIntendedDestinationEndpointURIRequired(SAMLBindingSupport.isMessageSigned(messageContext));
    }

    /**
     * A subclass of {@link InflaterInputStream} which defaults in a no-wrap
     * {@link Inflater} instance and
     * closes it when the stream is closed.
     */
    private class NoWrapAutoEndInflaterInputStream extends InflaterInputStream {

        /**
         * Creates a new input stream with a default no-wrap decompressor and buffer
         * size.
         *
         * @param is the input stream
         */
        public NoWrapAutoEndInflaterInputStream(final InputStream is) {
            super(is, new Inflater(true));
        }

        /** {@inheritDoc} */
        public void close() throws IOException {
            if (inf != null) {
                inf.end();
            }
            super.close();
        }

    }

    @Override
    public MessageContext getMessageContext() {
        return messageContext;
    }

    @Override
    public boolean isInitialized() {
        return isInitialized;
    }

    @Override
    public void initialize() throws ComponentInitializationException {
        if (httpServletRequest == null) {
            throw new ComponentInitializationException("HTTP Servlet request cannot be null");
        }
        if (parserPool == null) {
            throw new ComponentInitializationException("Parser pool cannot be null");
        }
        isInitialized = true;
    }

    @Override
    public boolean isDestroyed() {
        return isDestroyed;
    }

    @Override
    public void destroy() {
        parserPool = null;
        messageContext = null;
        isDestroyed = true;
    }

}

package idbus.oidc;

import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import idbus.oidc.camel.CamelMediationExchange;
import org.apache.camel.Consumer;
import org.apache.camel.Processor;
import org.apache.camel.Producer;
import org.apache.camel.impl.DefaultEndpoint;
import org.apache.camel.impl.DefaultMessage;
//import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
/*import org.atricore.idbus.capabilities.openidconnect.main.binding.OpenIDConnectBinding;
import org.atricore.idbus.capabilities.openidconnect.main.common.OpenIDConnectException;
import org.atricore.idbus.capabilities.openidconnect.main.common.producers.OpenIDConnectProducer;
import org.atricore.idbus.capabilities.openidconnect.main.proxy.OpenIDConnectProxyMediator;
import org.atricore.idbus.capabilities.sso.support.metadata.SSOMetadataConstants;
import org.atricore.idbus.common.sso._1_0.protocol.SPInitiatedAuthnRequestType;
import org.atricore.idbus.common.sso._1_0.protocol.SubjectAttributeType;
import org.atricore.idbus.kernel.main.federation.metadata.CircleOfTrustManager;
import org.atricore.idbus.kernel.main.federation.metadata.EndpointDescriptor;
import org.atricore.idbus.kernel.main.federation.metadata.EndpointDescriptorImpl;
import org.atricore.idbus.kernel.main.mediation.IdentityMediationException;
import org.atricore.idbus.kernel.main.mediation.camel.AbstractCamelEndpoint;
import org.atricore.idbus.kernel.main.mediation.camel.component.binding.CamelMediationExchange;
import org.atricore.idbus.kernel.main.mediation.camel.component.binding.CamelMediationMessage;
import org.atricore.idbus.kernel.main.mediation.channel.FederationChannel;
import org.atricore.idbus.kernel.main.mediation.channel.SPChannel;
import org.atricore.idbus.kernel.main.mediation.endpoint.IdentityMediationEndpoint;
import org.atricore.idbus.kernel.main.mediation.provider.FederatedProvider;
import org.atricore.idbus.kernel.main.mediation.provider.FederationService;
import org.atricore.idbus.kernel.main.util.UUIDGenerator;*/
//import org.codehaus.jackson.map.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Receives an OAuth2 authorization code and requests the proper access token (back-channel)
 * Then an authentication response is sent to the IdP proxy party
 */
public abstract class AuthzTokenConsumerProducer extends OpenIDConnectProducer {

    private static final Log logger = LogFactory.getLog(AuthzTokenConsumerProducer.class);

    protected static final String EMAIL_USER_ATTR_NAME = "email";
    protected static final String FIRST_NAME_USER_ATTR_NAME = "firstName";
    protected static final String LAST_NAME_USER_ATTR_NAME = "lastName";
    protected static final String COMMON_NAME_USER_ATTR_NAME = "commonName";
    protected static final String GENDER_USER_ATTR_NAME = "gender";
    protected static final String LANGUAGE_USER_ATTR_NAME = "language";
    protected static final String PICTURE_USER_ATTR_NAME = "picture";
    protected static final String PROFILE_LINK_USER_ATTR_NAME = "profileLink";
    protected static final String IS_VERIFIED_USER_ATTR_NAME = "isVerified";
    protected static final String BIRTHDAY_USER_ATTR_NAME = "birthday";

  //  protected UUIDGenerator uuidGenerator = new UUIDGenerator();

//    protected static final UUIDGenerator sessionUuidGenerator  = new UUIDGenerator(true);

   // protected ObjectMapper mapper = new ObjectMapper();

    public AuthzTokenConsumerProducer(/*AbstractCamelEndpoint<CamelMediationExchange> endpoint*/) throws Exception {
        super();
    }

   // @Override
    protected void doProcess(DefaultMessage /*CamelMediationMessage*/ exchange) throws Exception {
        //CamelMediationMessage in = (CamelMediationMessage) exchange.getIn();
        DefaultMessage in = (DefaultMessage) exchange.getExchange();
      //  if (in.getMessage().getContent() instanceof AuthorizationCodeResponseUrl) {
      if (in.getBody() instanceof AuthorizationCodeResponseUrl) {
            if (logger.isTraceEnabled())
                logger.trace("Processing AuthorizationCodeResponse");
            AuthorizationCodeResponseUrl authnResp = (AuthorizationCodeResponseUrl) in.getBody(); //in.getMessage().getContent();
            doProcessAuthzTokenResponse(/*exchange,*/ authnResp);
        } else {
            throw new SecurityException(""); // IdentityMediationException("Unknown message type " + in.getMessage().getContent());
        }

    }

    protected abstract void doProcessAuthzTokenResponse(/*CamelMediationExchange exchange,*/ AuthorizationCodeResponseUrl authnResp ) throws Exception;

    protected /*EndpointDescriptor*/ String resolveAccessTokenConsumerEndpoint(String svc) {

       /* String binding = OpenIDConnectBinding.OPENIDCONNECT_AUTHZ.toString();

        for (IdentityMediationEndpoint endpoint : channel.getEndpoints()) {
            if (endpoint.getType().equals(svc)) {
                if (endpoint.getBinding().equals(binding))
                    return new EndpointDescriptorImpl(channel.getLocation(), endpoint);
            }
        }*/

        logger.warn("No endpoint found for service/binding " +
                svc +  "/" /*+ binding*/);

        return null;
    }
/*

    protected String resolveSpProxyACS(SPInitiatedAuthnRequestType authnRequest) throws OpenIDConnectException {

        CircleOfTrustManager cotMgr = this.getFederatedProvider().getCotManager();
        OpenIDConnectProxyMediator mediator = (OpenIDConnectProxyMediator) channel.getIdentityMediator();
        FederatedProvider idp = cotMgr.lookupFederatedProviderByAlias(mediator.getIdpProxyAlias());

        SPChannel spChannel = null;
        for (FederationService svc : idp.getFederationServices()) {
            spChannel = resolveProxiedSPChannel(svc);
            if (spChannel != null) {
                break;
            }
        }

        if (spChannel == null)
            spChannel = resolveProxiedSPChannel(idp.getDefaultFederationService());

        if (spChannel == null) {
            throw new OpenIDConnectException("No SP channel is set as proxy for " + channel.getName());
        }

        for (IdentityMediationEndpoint e : spChannel.getEndpoints()) {
            if (e.getType().equals(SSOMetadataConstants.ProxyAssertionConsumerService_QName.toString())) {
                return spChannel.getLocation() + e.getLocation();
            }
        }

        throw new OpenIDConnectException("No endpoint found of type " + SSOMetadataConstants.ProxyAssertionConsumerService_QName.toString());

    }

    protected SPChannel resolveProxiedSPChannel(FederationService svc) {

        SPChannel spChannel = null;

        if (logger.isTraceEnabled())
            logger.trace("Looking SP Channels on service " + svc.getName());

        if (svc.getOverrideChannels() != null) {

            for (FederationChannel fc : svc.getOverrideChannels()) {
                spChannel = resolveProxiedSPChannel(fc);
                if (spChannel != null) {

                    if (logger.isDebugEnabled())
                        logger.debug("Found Default SP channel[" + spChannel.getName() + "] proxied to us ("+spChannel.getProxy().getName()+")");

                    return spChannel;
                }
            }
        }

        if (logger.isTraceEnabled())
            logger.trace("Defautl channel on service " + (svc.getChannel() != null ? svc.getChannel().getName() : "<null>"));

        if (svc.getChannel() != null) {

            spChannel = resolveProxiedSPChannel(svc.getChannel());

            if (spChannel != null) {
                if (logger.isDebugEnabled())
                    logger.debug("Found Default SP channel[" + spChannel.getName() + "] proxied to us ("+spChannel.getProxy().getName()+")");

                return spChannel;
            }

        }

        if (logger.isTraceEnabled())
            logger.trace("No SP channelfound proxied to us (" + channel.getName() + ")");

        return null;
    }

    protected SPChannel resolveProxiedSPChannel(FederationChannel fc) {

        if (logger.isTraceEnabled())
            logger.trace("Current channel " + fc.getName());

        if (fc instanceof SPChannel) {
            SPChannel c = (SPChannel) fc;

            if (c.getProxy() != null && c.getProxy().getName().equals(channel.getName())) {

                if (logger.isDebugEnabled())
                    logger.debug("Found SP channel[" + c.getName() + "] proxied to us (" + c.getProxy().getName() + ")");

                return c;
            }

        }

        return null;
    }

    protected void addUserAttribute(String name, String value, List<SubjectAttributeType> attrs) {
        if (StringUtils.isNotBlank(value)) {
            SubjectAttributeType userAttr = new SubjectAttributeType();
            userAttr.setName(name);
            userAttr.setValue(value);
            attrs.add(userAttr);
        }
    }

    protected String toJsonString(Object value) {
        if (value == null) {
            return null;
        }

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(1024);
            mapper.writeValue(baos, value);
            return new String(baos.toByteArray());
        } catch (IOException e) {
            return null;
        }
    }

    protected String listToJsonString(List list) {
        if (list == null || list.size() == 0) {
            return null;
        }
        return toJsonString(list);
    }

    protected Object fromJsonString(String value, Class objClass) {
        try {
            return mapper.readValue(new ByteArrayInputStream(value.getBytes()), objClass);
        } catch (IOException e) {
            logger.debug("Unable to convert JSON string to JAVA object [" + objClass.getName() + "]", e);
            return null;
        }
    }

    protected String toJavaName(String attrName) {
        // It handles only "_" characters
        String javaAttrName = attrName;
        int index;
        String nextChar;
        while ((index = javaAttrName.indexOf("_")) != -1) {
            if (index == 0) {
                javaAttrName = javaAttrName.substring(1);
            } else if (index == (javaAttrName.length() - 1)) {
                javaAttrName = javaAttrName.substring(0, index);
            } else {
                nextChar = javaAttrName.substring(index + 1, index + 2);
                if ("_".equals(nextChar)) {
                    javaAttrName = javaAttrName.substring(0, index) + javaAttrName.substring(index + 1);
                } else {
                    javaAttrName = javaAttrName.substring(0, index) + nextChar.toUpperCase() + javaAttrName.substring(index + 2);
                }
            }
        }
        return javaAttrName;
    }*/
}

package oidc.nimbus;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import oidc.otherexamples.OidcAuthenticationRequestStateUsageSample;
import oidc.util.nimbus.OidcConfig;
import org.slf4j.Logger;
import sun.security.util.Cache;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;

public class OidcCallbackVerifyStateNimbus {

    private Properties config;
    private Cache<String, Object> cache;
    private OIDCProviderMetadata providerMetadata;
    private URI callback;
    Logger logger;
    private IDTokenValidator idTokenValidator;

    public OidcCallbackVerifyStateNimbus(Properties config, Cache<String, Object> cache) {
        this.config = config;
        this.cache = cache;
    }

    private void processError(AuthenticationResponse response) {
            ErrorObject errorObject = response.toErrorResponse().getErrorObject();
            logger.error("Error response code"+errorObject.getHTTPStatusCode(), new String[0]);
        }



    // STEP 2

    @SuppressFBWarnings(value = {"SERVLET_HEADER"})
    public void callBackMissingCheckState(HttpServletRequest httpAuthorizationCallback) {
        try {
            AuthenticationResponse response;
            try {
                response = AuthenticationResponseParser.parse(new URI(httpAuthorizationCallback.getRequestURI()));
            } catch (ParseException | URISyntaxException e) {
                // Handle parse errors. Control flow must be broken here..
                throw new SecurityException("Failed to parse auth response");
            }
             // This block is STEP 2 in flow chart.
            if (response instanceof AuthenticationErrorResponse) {
                // process error
                throw new SecurityException("Failed to parse auth response");
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse();
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            // FIXME: security error, missing state check
            // Next step ...
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
            throw new SecurityException("Failed to parse auth response");
        }
    }

    @SuppressFBWarnings(value = {"SERVLET_HEADER"})
    public void callBackMissingCheckStatePassedParam(HttpServletRequest httpAuthorizationCallback) {
        try {
            AuthenticationResponse response;
            try {
                response = AuthenticationResponseParser.parse(new URI(httpAuthorizationCallback.getRequestURI()));
            } catch (ParseException | URISyntaxException e) {
                // Handle parse errors. Control flow must be broken here..
                throw new SecurityException("Failed to parse auth response");
            }
            // This block is STEP 2 in flow chart.
            if (response instanceof AuthenticationErrorResponse) {
                // process error
                processError(response);
                throw new SecurityException("Failed to parse auth response");
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse();
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            // FIXME: security error, missing state check
            stateMatcherHandleNoMatch(successResponse, oidcConfig.state);
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
            throw new SecurityException("Failed to parse auth response");
        }
    }

    @SuppressFBWarnings(value = {"SERVLET_HEADER"})
    public void callBackMissingCheckStatePassedParamForeign(HttpServletRequest httpAuthorizationCallback) {
        try {
            AuthenticationResponse response;
            try {
                response = AuthenticationResponseParser.parse(new URI(httpAuthorizationCallback.getRequestURI()));
            } catch (ParseException | URISyntaxException e) {
                // Handle parse errors. Control flow must be broken here..
                throw new SecurityException("Failed to parse auth response");
            }
            // This block is STEP 2 in flow chart.
            if (response instanceof AuthenticationErrorResponse) {
                // process error
                throw new SecurityException("Failed parse");
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse();
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            // FIXME: security error, missing state check
            // TODO: Control flow: The state must be checked between trigger AuthenticationResponse and this exit point. Maybe this is implicit with the existence...
            OidcAuthenticationRequestStateUsageSample.matcherHandleNoMatch(successResponse, oidcConfig.state);
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
            throw new SecurityException("Something went wrong during callback");
        }
    }


    // @Path("callback")
    // STEP 2
    @SuppressFBWarnings("SERVLET_HEADER")
    public void OK_callBackCheckState(HttpServletRequest httpAuthorizationCallback) {
        try {
            AuthenticationResponse
                    response;
            try { // This block is STEP 2 in flow chart.
                response = AuthenticationResponseParser.parse(new URI(httpAuthorizationCallback.getRequestURI())); // TODO:  Potential trigger AuthenticationResponse for state check
            } catch (ParseException | URISyntaxException e) {
                // Handle errors. Control flow must be broken here..
                throw new SecurityException("Failed parse");
            }
            if (response instanceof AuthenticationErrorResponse) {
                // process error
                throw new SecurityException("Failed parse");
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse(); // TODO: Potential trigger AuthenticationSuccessResponse for state check
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            State savedState = oidcConfig.state;
            State returnedState = successResponse.getState();
            if(!returnedState.equals(savedState)) {  // TODO: Green flag if we have triggered.
                throw new SecurityException("Failed parse"); // TODO second aspect: check must follow a broken control flow.
            }
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
        }
    }

    // Consider requiring a return after each catch block to ensure that no exit point leads to



    // Doesn't check state. Expect bug.
    private void stateMatcherHandleNoMatch(AuthenticationSuccessResponse successResponse, State state) {
        successResponse.toParameters();
    }



    private void stateMatcherHandle(AuthenticationSuccessResponse successResponse,State state) {
        if(!successResponse.getState().equals(state)) {
            // Unauthorized
            throw new SecurityException("EE");
        }
        successResponse.toParameters();
    }





}

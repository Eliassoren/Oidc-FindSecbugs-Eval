package oidc.googleapiclient;

import com.google.api.client.auth.oauth2.*;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import oidc.util.ForeignPassMethodUtil;
import oidc.util.googleapiclient.OidcConfig;
import sun.security.util.Cache;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.UUID;

public class OidcCallbackVerifyStateGoogle {
    /*
    * Use the authorization code flow to allow the end user to grant your application access to their protected data. The protocol for this flow is specified in the Authorization Code Grant specification.

This flow is implemented using AuthorizationCodeFlow. The steps are:

An end user logs in to your application. You need to associate that user with a user ID that is unique for your application.
Call AuthorizationCodeFlow.loadCredential(String), based on the user ID, to check if the user's credentials are already known. If so, you're done.
If not, call AuthorizationCodeFlow.newAuthorizationUrl() and direct the end user's browser to an authorization page where they can grant your application access to their protected data.
The web browser then redirects to the redirect URL with a "code" query parameter that can then be used to request an access token using AuthorizationCodeFlow.newTokenRequest(String).
Use AuthorizationCodeFlow.createAndStoreCredential(TokenResponse, String) to store and obtain a credential for accessing protected resources.
    * */

    private Properties config;
    private static final long DEFAULT_TIME_SKEW_SECONDS = 300;
    private Cache<String, Object> cache;
    private AuthorizationCodeFlow authorizationCodeFlow;

    private String redirectUri = "https://client.com/callback";



    private boolean verifyState(OidcConfig oidcConfig, String state) {
        // Other possible case, passing the whole url?
        return oidcConfig.state.equals(state);
    }

    private boolean verifyState(String state) {
        // Other possible case, passing the whole url?
        OidcConfig oidcConfig = new OidcConfig();
        return oidcConfig.state.equals(state);
    }
    // --------------------------- Good code ---------------------------------------------



    @SuppressFBWarnings("SERVLET_HEADER")
    public void OK_callbackCheckState(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                throw new RuntimeException("Error response");
            }
            if(oidcConfig.state.equals(responseUrl.getState())) {
                throw new RuntimeException("Error response");
            }
        } catch (Exception e) {
            // Error handling
        }
    }



    @SuppressFBWarnings("SERVLET_HEADER")
    public void OK_callbackCheckStatePassedToOther1(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                throw new RuntimeException("Error response");
            }
            if(!verifyState(oidcConfig, responseUrl.getState())) {
                throw new RuntimeException("Error response");
            }
            String authorizationCode = responseUrl.getCode();

        } catch (Exception e) {
            // Error handling
        }
    }
    @SuppressFBWarnings("SERVLET_HEADER")
    public void OK_callbackCheckStatePassedToOther2(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                throw new RuntimeException("Error response");
            }
            if(!verifyState(responseUrl.getState())) {
                throw new RuntimeException("Error response");
            }
            String authorizationCode = responseUrl.getCode();

        } catch (Exception e) {
            // Error handling
        }
    }



    // ------------------------------ Bad code expecting reports ---------------------------------------



    @SuppressFBWarnings("SERVLET_HEADER")
    public void callbackMissingCheckState(HttpServletRequest callbackRequest) {
        try {
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                throw new RuntimeException("Error response");
            }
            // FIXME: no state equals
        } catch (Exception e) {
            // Error handling
        }
    }

    private void passStateNoCheck(String state) {
        int a = state.compareTo("randomstrin");
    }

    @SuppressFBWarnings("SERVLET_HEADER")
    public void callbackMissingCheckStatePassedToOther(HttpServletRequest callbackRequest) {
        try {
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                throw new RuntimeException("Error response");
            }
            // BUG: no state equals
            passStateNoCheck(responseUrl.getState());
        } catch (Exception e) {
            // Error handling unauthorized
        }
    }

    @SuppressFBWarnings("SERVLET_HEADER")
    public void callbackMissingCheckStatePassedForeign(HttpServletRequest callbackRequest) {
        try {
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                //
                throw new RuntimeException("Error response");
            }
            // BUG: possibly no state equals. Passing to foreign method.
            ForeignPassMethodUtil.passStateNoCheck(responseUrl.getState());
        } catch (Exception e) {
            // Error handling
            // Unauthorized
        }
    }

    public Response validateTokens(IdTokenResponse tokenResponse, OidcConfig oidcConfig) throws IOException, GeneralSecurityException {
        String nonce = oidcConfig.nonce;
        // Validations...
        return Response.ok()
                .entity(tokenResponse)
                .build();
    }


}

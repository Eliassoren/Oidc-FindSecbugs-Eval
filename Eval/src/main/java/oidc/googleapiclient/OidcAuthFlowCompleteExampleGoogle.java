package oidc.googleapiclient;

import com.google.api.client.auth.oauth2.*;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.testing.json.MockJsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.nimbusds.oauth2.sdk.ParseException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import oidc.util.ForeignPassMethodUtil;
import oidc.util.googleapiclient.OidcConfig;
import sun.security.util.Cache;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

public class OidcAuthFlowCompleteExampleGoogle {
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
    private AuthorizationCodeFlow authorizationCodeFlow;
    private AuthorizationCodeRequestUrl requestUrl;
    private PublicKey keyFromDiscoveryDocument;
    private Cache<String, Object> cache;
    Map<String, Object> providerMetadata;
    private String redirectUri = "https://client.com/callback";
    SecureRandom secureRandom;


    private static JSONObject parseJson(String s) throws ParseException {
        Object o;
        try {
            o = new JSONParser(640).parse(s);
        } catch (net.minidev.json.parser.ParseException var2) {
            throw new ParseException("Invalid JSON: " + var2.getMessage(), var2);
        }

        if (o instanceof JSONObject) {
            return (JSONObject)o;
        } else {
            throw new ParseException("The JSON entity is not a JSON object");
        }
    }

    private Map<String, Object> discovery() {
        try {
            URI issuerURI = new URI("https://provider.example.com/");
            URL providerConfigurationURL = issuerURI.resolve("/.well-known/openid-configuration?").toURL();
            HttpsURLConnection connection = (HttpsURLConnection)providerConfigurationURL.openConnection();
            connection.setRequestMethod("GET");
            if(!connection.getURL().getProtocol().equals("https")) {
                throw new SecurityException("Discovery url not using https.");

            }
            if(connection.getResponseCode() != HttpsURLConnection.HTTP_OK) {
                throw new SecurityException("Discovery failed to respond with HTTP response OK.");
            }
            InputStream stream = connection.getInputStream();

            String providerInfo = "";
            try (Scanner s = new Scanner(stream)) {
                providerInfo = s.useDelimiter("\\A").next();
            }
            return parseJson(providerInfo);
        } catch (IOException | URISyntaxException | ParseException e ) {
            // Handle
        }
        throw new RuntimeException("Failed to perform discovery");
    }


    private String nonce() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return new String(Base64.getEncoder().encode(randomBytes));
    }

    private String state() {
        return nonce();
    }

    private boolean verifyState(OidcConfig config, String state) {
        // Other possible case, passing the whole url?
        return config.state.equals(state);
    }
    // --------------------------- Good code ---------------------------------------------

    // @Path("/login")
    @SuppressFBWarnings({"SERVLET_HEADER", "SERVLET_PARAMETER"})
    public Response OK_authenticationRequestAddState(HttpServletRequest request) {
        try {
            providerMetadata = discovery();
            String state =  nonce();
            String nonce =  state();
            UUID uuid = UUID.randomUUID();
            cache.put(uuid.toString(), new OidcConfig( state,
                    nonce,
                    uuid
            ));
            authorizationCodeFlow = new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
                    new NetHttpTransport(), new MockJsonFactory(),
                    new GenericUrl((String)providerMetadata.get("token_endpoint")), // "https://server.example.com/token"
                    new BasicAuthentication(config.getProperty("clientId"), config.getProperty("clientSecret")),
                    config.getProperty("clientId"),
                    (String)providerMetadata.get("authorization_endpoint")//"https://server.example.com/authorize"
            ).build();
            requestUrl = authorizationCodeFlow
                    .newAuthorizationUrl()
                    .setResponseTypes(Collections.singleton("code"))
                    .setScopes(Arrays.asList("openid", "email", "profile", "address"))
                    .setRedirectUri("https://client.com/callback")
                    .set("login_hint", request.getParameter("login_hint"))
                    .setState(state)
                    .set("nonce", nonce);
            return Response.seeOther(requestUrl.toURI()).header("appuuid", uuid).build();
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }


    @SuppressFBWarnings("SERVLET_HEADER")
    public Response OK_callbackCheckState(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Authorization failed with error: "+error).build();
            }
            if(oidcConfig.state.equals(responseUrl.getState())) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("The state does not match").build();
            }
            String authorizationCode = responseUrl.getCode();

            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            return validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }



    @SuppressFBWarnings("SERVLET_HEADER")
    public Response OK_callbackCheckStatePassedToOther(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Authorization failed with error: "+error).build();
            }

            if(!verifyState(oidcConfig, responseUrl.getState())) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("The state does not match").build();
            }

            String authorizationCode = responseUrl.getCode();
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            return validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }
    // ------------------------------ Bad code expecting reports ---------------------------------------

    // Doesn't add state param. Expect bug.
    // @Path("/login")
    @SuppressFBWarnings("SERVLET_PARAMETER")
    public Response exampleAuthenticationRequestForgetAddState(HttpServletRequest request, HttpServletResponse response) {
        try {
            // String state =  nonce();
            //String nonce =  state();
            //request.getSession().setAttribute("state", state);
            //  UUID userid = UUID.randomUUID();
            Map<String, Object> providerMetadata = discovery();
            authorizationCodeFlow = new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
                    new NetHttpTransport(), new MockJsonFactory(),
                    new GenericUrl(String.valueOf(providerMetadata.get("token_endpoint"))), //"https://server.example.com/token"
                    new BasicAuthentication(config.getProperty("clientId"), config.getProperty("clientSecret")),
                    config.getProperty("clientId"),
                    "https://server.example.com/authorize"
            ).setCredentialDataStore(
                    StoredCredential.getDefaultDataStore(
                            new FileDataStoreFactory(new File("datastoredir"))))
                    .build();
            requestUrl = authorizationCodeFlow
                    .newAuthorizationUrl()
                    .setResponseTypes(Collections.singleton("code"))
                    .setScopes(Arrays.asList("openid", "email", "profile", "address"))
                    .setRedirectUri("https://client.com/callback")
                    .set("login_hint", request.getParameter("login_hint"));
            // .setState(state)
            // .set("nonce", nonce);
            return Response.seeOther(requestUrl.toURI()).build();
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }



    // @Path("/login")
    @SuppressFBWarnings("SERVLET_PARAMETER")
    public Response authenticationRequestNoDiscovery(HttpServletRequest request) {
        try {
            String state =  nonce();
            String nonce =  state();
            UUID userid = UUID.randomUUID();
            authorizationCodeFlow = new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
                    new NetHttpTransport(), new MockJsonFactory(),
                    new GenericUrl("https://server.example.com/token"),
                    new BasicAuthentication(config.getProperty("clientId"), config.getProperty("clientSecret")),
                    config.getProperty("clientId"),
                    "https://server.example.com/authorize"
            ).build();
            requestUrl = authorizationCodeFlow
                    .newAuthorizationUrl()
                    .setResponseTypes(Collections.singleton("code"))
                    .setScopes(Arrays.asList("openid", "email", "profile", "address"))
                    .setRedirectUri("https://client.com/callback")
                    .set("login_hint", request.getParameter("login_hint"))
                    .setState(state)
                    .set("nonce", nonce);
            return Response.seeOther(requestUrl.toURI()).build();
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }
    /*Validation of an ID token requires several steps:
       - Verify that the Nonce in the  token request matches the issued nonce. X
       - Verify that the ID token is properly signed by the issuer. Google-issued tokens are signed using one of the certificates found at the URI specified in the jwks_uri metadata value of the Discovery document. X
       - Verify that the value of the iss claim in the ID token is equal to https://accounts.google.com or accounts.google.com.
       - Verify that the value of the aud claim in the ID token is equal to your app's client ID. X
       - Verify that the expiry time (exp claim) of the ID token has not passed. X
       - If you specified a hd parameter value in the request, verify that the ID token has a hd claim that matches an accepted G Suite hosted domain.*/



    @SuppressFBWarnings("SERVLET_HEADER")
    public Response callbackMissingCheckState(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Authorization failed with error: "+error).build();
            }
            // FIXME: no state equals
            String authorizationCode = responseUrl.getCode();
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            return validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    private void passStateNoCheck(String state) {
        int a = state.compareTo("randomstrin");
    }

    @SuppressFBWarnings("SERVLET_HEADER")
    public Response callbackMissingCheckStatePassedToOther(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Authorization failed with error: "+error).build();
            }
            // FIXME: no state equals
            passStateNoCheck(responseUrl.getState());
            String authorizationCode = responseUrl.getCode();
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            return validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @SuppressFBWarnings("SERVLET_HEADER")
    public Response callbackMissingCheckStatePassedForeign(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Authorization failed with error: "+error).build();
            }
            // FIXME: no state equals
            ForeignPassMethodUtil.passStateNoCheck(responseUrl.getState());
            String authorizationCode = responseUrl.getCode();
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP

            return validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    public Response validateTokens(IdTokenResponse tokenResponse, OidcConfig oidcConfig) throws IOException, GeneralSecurityException {

        IdToken idToken = tokenResponse.parseIdToken();
        if(!oidcConfig.nonce.equals(idToken.getPayload().getNonce())) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("The provided nonce did not match the one saved from the authorization request.")
                    .build();
        }
        if(!idToken.verifySignature(keyFromDiscoveryDocument)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("The jwt signature is not valid.")
                    .build();
        }
        if(!idToken.verifyAudience(Collections.singleton(config.getProperty("clientId")))) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("This request does not seem like it was meant for this audience.")
                    .build();
        }
        if(!idToken.verifyExpirationTime(Instant.now().toEpochMilli(), DEFAULT_TIME_SKEW_SECONDS)){
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Token expired.")
                    .build();
        }
        // .... other checks
        authorizationCodeFlow.createAndStoreCredential(tokenResponse, oidcConfig.appuuid.toString());
        return Response.ok()
                .entity(tokenResponse)
                .build();
    }


}


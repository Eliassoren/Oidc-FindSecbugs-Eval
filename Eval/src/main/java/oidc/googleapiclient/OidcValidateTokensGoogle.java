package oidc.googleapiclient;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.TokenRequest;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.http.GenericUrl;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import oidc.util.googleapiclient.OidcConfig;
import sun.security.util.Cache;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

public class OidcValidateTokensGoogle {


    private Properties config;
    private static final long DEFAULT_TIME_SKEW_SECONDS = 300;
    private AuthorizationCodeFlow authorizationCodeFlow;
    private AuthorizationCodeRequestUrl requestUrl;
    private PublicKey keyFromDiscoveryDocument;
    private Cache<String, Object> cache;
    Map<String, Object> providerMetadata;
    private String redirectUri = "https://client.com/callback";
    SecureRandom secureRandom;


    @SuppressFBWarnings("SERVLET_HEADER")
    public Response OK_validateTokensComplete(HttpServletRequest callbackRequest) {
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
            return OK_validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }
    public Response OK_tokenRequestVerifyMandatoryCallToOther(String authorizationCode, OidcConfig oidcConfig) {
        try {
            // After verified state and parse auth code..
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            return OK_validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    public Response tokenRequestGoogleTokenVerifierNoVerify(String authorizationCode, OidcConfig oidcConfig) {
        try {
            // After verified state and parse auth code..
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            IdTokenVerifier idTokenVerifier = new IdTokenVerifier(); // missing time

            // IdToken.parse(new Json(),  idTokenResponse.getIdToken());
            if(idTokenVerifier.verify(idTokenResponse.parseIdToken())) {
                // new knowledge: the parse call performs jwt check.
                // Fixme: verifier is missing nonce, iss, time, aud, jwt check
                authorizationCodeFlow.createAndStoreCredential(idTokenResponse, oidcConfig.appuuid.toString());
                return Response.ok()
                        .entity(idTokenResponse)
                        .build();
            }
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    public Response tokenRequestGoogleTokenVerifier(String authorizationCode, OidcConfig oidcConfig) {
        try {
            // After verified state and parse auth code..
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            IdTokenVerifier idTokenVerifier = new IdTokenVerifier.Builder()
                                                .setAudience(Collections.singleton(authorizationCodeFlow.getClientId()))
                                                .setIssuer(String.valueOf(providerMetadata.get("iss")))
                                                .build(); // missing time

           // IdToken.parse(new Json(),  idTokenResponse.getIdToken());
            if(idTokenVerifier.verify(idTokenResponse.parseIdToken())) {
                // new knowledge: the parse call performs jwt check.
                // Fixme: verifier is missing nonce and jwt check
                authorizationCodeFlow.createAndStoreCredential(idTokenResponse, oidcConfig.appuuid.toString());
                return Response.ok()
                        .entity(idTokenResponse)
                        .build();
            }
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    public Response tokenRequestNoValidation(String authorizationCode, OidcConfig oidcConfig) {
        try {
            // After verified state and parse auth code..
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setGrantType("code")
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
           // No verification of id token...
            authorizationCodeFlow.createAndStoreCredential(idTokenResponse, oidcConfig.appuuid.toString());
            return Response.ok()
                    .entity(idTokenResponse)
                    .build();

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
    public Response OK_validateTokens(IdTokenResponse tokenResponse, OidcConfig oidcConfig) {
        try {
            PublicKey publicKey = (PublicKey)providerMetadata.get("key"); // fix codeexample
            IdToken idToken = tokenResponse.parseIdToken(); // Parse
            if(!oidcConfig.nonce.equals(idToken.getPayload().getNonce())) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("The provided nonce did not match the one saved from the authorization request.")
                        .build();
            }
            if(!idToken.verifySignature(publicKey)){
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("The jwt signature is not valid.")
                        .build();
            }
            if(!idToken.verifyAudience(Collections.singleton(config.getProperty("clientId")))) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("This request does not seem like it was meant for this audience.")
                        .build();
            }
            if(!idToken.verifyTime(Instant.now().toEpochMilli(), DEFAULT_TIME_SKEW_SECONDS)){
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Token expired.")
                        .build();
            }
            if(!idToken.verifyIssuer(String.valueOf(providerMetadata.get("issuer")))) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("The expected issuer did not match.")
                        .build();
            }
            // .... other checks
            authorizationCodeFlow.createAndStoreCredential(tokenResponse, oidcConfig.appuuid.toString());

            return Response.ok()
                    .entity(tokenResponse)
                    .build();
        } catch (IOException | GeneralSecurityException | ClassCastException e) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }

}




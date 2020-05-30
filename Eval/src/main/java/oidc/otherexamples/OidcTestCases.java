

package oidc.otherexamples;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class OidcTestCases {

    static SecureRandom secureRandomGenerator;
    static AuthResource.Config config;
    static {

        try {
            secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG", "SUN");
            exampleAuthenticationRequest();
            exampleAuthorizationRequest();
            exampleTokenRequest();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
    }




    public static void exampleAuthenticationRequest() {
        try {
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getClientId());
            URI callback = new URI("https://client.com/callback");
            // Generate random state string and nonce for pairing the response to the request
            State state = new State();
            Nonce nonce = new Nonce();
            AuthenticationRequest req = new AuthenticationRequest(
                    new URI("https://c2id.com/login"),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            HTTPResponse httpResponse = req.toHTTPRequest().send(); // Step 3
            AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse); // Step 7
            if (response instanceof AuthenticationErrorResponse) {
                // process error
            }
            AuthenticationSuccessResponse successResponse =  response.toSuccessResponse();
            AuthorizationCode code = successResponse.getAuthorizationCode();
            // Don't forget to check the state
            if(!successResponse.getState().equals(state)) {
                // Unauthorized
            }
        } catch (URISyntaxException e) {
        } catch (IOException e) {
        } catch (ParseException e) {
        } catch (ClassCastException e) {
        }
    }

    public static void exampleAuthorizationRequest() {

        try {
            // The authorisation endpoint of the server
            URI authzEndpoint = new URI("https://c2id.com/authz");

            // The client identifier provisioned by the server
            ClientID clientID = new ClientID("123");

            // The requested scope values for the token
            Scope scope = new Scope("read", "write");

            // The client callback URI, typically pre-registered with the server
            URI callback = new URI("https://client.com/callback");

            // Generate random state string for pairing the response to the request
            State state = new State();

            // Build the request
            AuthorizationRequest request = new AuthorizationRequest.Builder(
                    new ResponseType(ResponseType.Value.CODE), clientID)
                    .scope(scope)
                    .state(state)
                    .redirectionURI(callback)
                    .endpointURI(authzEndpoint)
                    .build();

            // Use this URI to send the end-user's browser to the server
            URI requestURI = request.toURI();
        } catch (URISyntaxException e) {

        }
    }

    public static void exampleTokenRequest() {
        try {
            // Construct the code grant from the code obtained from the authz endpoint
            // and the original callback URI used at the authz endpoint
            AuthorizationCode code = new AuthorizationCode("xyz...");
            URI callback = new URI("https://client.com/callback");
            AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callback);

            // The credentials to authenticate the client at the token endpoint
            ClientID clientID = new ClientID("123");
            Secret clientSecret = new Secret("secret");
            ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

            // The token endpoint
            URI tokenEndpoint = new URI("https://c2id.com/token");

            // Make the token request
            TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

            TokenResponse response = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());

            if (! response.indicatesSuccess()) {
                // We got an error response...
                TokenErrorResponse errorResponse = response.toErrorResponse();
            }

            OIDCTokenResponse successResponse = (OIDCTokenResponse)response.toSuccessResponse();

            // Get the ID and access token, the server may also return a refresh token
            JWT idToken = successResponse.getOIDCTokens().getIDToken();
            AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
            RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
        } catch(URISyntaxException e) {

        } catch (IOException e) {

        } catch (ParseException e) {

        }

    }


}


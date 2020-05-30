package oidc.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import oidc.otherexamples.OidcAuthenticationRequestStateUsageSample;
import sun.security.util.Cache;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Objects;
import java.util.Properties;
import java.util.Scanner;
import java.util.UUID;

public class OidcAuthFlowCompleteExampleNimbus {

    private Properties config;
    private Cache<String, Object> cache;
    private OIDCProviderMetadata providerMetadata;
    private URI callback;

    public OidcAuthFlowCompleteExampleNimbus(Properties config, Cache<String, Object> cache) {
        this.config = config;
        this.cache = cache;
    }

    private void processError(AuthenticationResponse response) {
        ErrorObject errorObject = response.toErrorResponse().getErrorObject();

    }
    private IDTokenValidator idTokenValidator;

    private static class OidcConfig {
        public final State state;
        public final Nonce nonce;
        public final UUID appuuid;
        public OidcConfig(State state, Nonce nonce, UUID appuuid) {
            this.state = state;
            this.nonce = nonce;
            this.appuuid = appuuid;
        }
    }

    private OIDCProviderMetadata discovery() {
        try {
            URL providerConfigurationURL = new URI("https://provider.example.com/")
                    .resolve("/.well-known/openid-configuration?")
                    .toURL();
            HttpsURLConnection connection = (HttpsURLConnection)providerConfigurationURL.openConnection();
            if(connection.getResponseCode() != HttpsURLConnection.HTTP_OK) {
                throw new SecurityException("Discovery failed to respond with HTTP response code OK.");
            }
            InputStream stream = connection.getInputStream();
            // Read all data from URL
            String providerInfo;
            try (Scanner s = new Scanner(stream)) {
                providerInfo = s.useDelimiter("\\A").next();
            }
            return OIDCProviderMetadata.parse(providerInfo);
        } catch (ParseException | IOException | URISyntaxException e ) {
            // Handle
        }
        throw new RuntimeException("Failed to perform discovery");
    }

    // Doesn't store param. Expect bug.
    public Response authenticationRequestForgetStoreStateAndNonce(HttpServletRequest request) {
        try {
            providerMetadata = discovery();
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getProperty("client_id"));
            callback = new URI("https://client.com/callback");
            // Generate state string and nonce to mitigate CSRF
            State state =  new State();
            Nonce nonce = new Nonce();
            // UUID uuid = UUID.randomUUID();

            // cache.put(uuid.toString(), new OidcConfig(state, nonce, uuid));
            AuthenticationRequest req = new AuthenticationRequest(
                    providerMetadata.getAuthorizationEndpointURI(),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            return Response.seeOther(req.toURI()).build();
        } catch (URISyntaxException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    // STEP 2

    @SuppressFBWarnings(value = {"SERVLET_HEADER"})
    public Response callBackMissingCheckState(HttpServletRequest httpAuthorizationCallback) {
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
                return Response.status(Response.Status.UNAUTHORIZED).entity("Error during authorization code flow").build();
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse();
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            // FIXME: security error, missing state check
            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();
            return OK_tokenRequestValidateIdToken(oidcConfig, authorizationCode);
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @SuppressFBWarnings(value = {"SERVLET_HEADER"})
    public Response callBackMissingCheckStatePassedParam(HttpServletRequest httpAuthorizationCallback) {
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
                return Response.status(Response.Status.UNAUTHORIZED).entity("Error during authorization code flow").build();
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse();
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            // FIXME: security error, missing state check
            stateMatcherHandleNoMatch(successResponse, oidcConfig.state);
            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();
            return OK_tokenRequestValidateIdToken(oidcConfig, authorizationCode);
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @SuppressFBWarnings(value = {"SERVLET_HEADER"})
    public Response callBackMissingCheckStatePassedParamForeign(HttpServletRequest httpAuthorizationCallback) {
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
                return Response.status(Response.Status.UNAUTHORIZED).entity("Error during authorization code flow").build();
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse();
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            // FIXME: security error, missing state check
            OidcAuthenticationRequestStateUsageSample.matcherHandleNoMatch(successResponse, oidcConfig.state);
            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();
            return OK_tokenRequestValidateIdToken(oidcConfig, authorizationCode);
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    // @Path("/login")
    // Step 1
    @SuppressFBWarnings("SERVLET_PARAMETER")
    public Response OK_authenticationRequestAddState(HttpServletRequest request) {
        try {
            providerMetadata = discovery();
            State state =  new State();
            Nonce nonce = new Nonce();
            UUID uuid = UUID.randomUUID();
            cache.put(uuid.toString(), new OidcConfig(state, nonce, uuid));
            AuthenticationRequest req = new AuthenticationRequest.Builder(
                    new AuthenticationRequest(
                            providerMetadata.getAuthorizationEndpointURI(),
                            new ResponseType("code"),
                            Scope.parse("openid email profile address"),
                            new ClientID(config.getProperty("client_id")),
                            new URI("https://client.com/callback"),
                            state,
                            nonce)
            ).loginHint(request.getParameter("login_hint")).build();
            return Response.seeOther(req.toURI()).header("appuuid", uuid).build();
        } catch (URISyntaxException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    // @Path("callback")
    // STEP 2
    @SuppressFBWarnings("SERVLET_HEADER")
    public Response OK_callBackCheckState(HttpServletRequest httpAuthorizationCallback) {
        try {
            AuthenticationResponse
                    response;
            try { // This block is STEP 2 in flow chart.
                response = AuthenticationResponseParser.parse(new URI(httpAuthorizationCallback.getRequestURI())); // TODO:  Potential trigger AuthenticationResponse for state check
            } catch (ParseException | URISyntaxException e) {
                // Handle errors. Control flow must be broken here..
                return Response.status(Response.Status.BAD_REQUEST).build();
            }
            if (response instanceof AuthenticationErrorResponse) {
                // process error
                processError(response);
                return Response.status(Response.Status.BAD_REQUEST).entity("Error during authorization code flow").build();
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse(); // TODO: Potential trigger AuthenticationSuccessResponse for state check
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            State savedState = oidcConfig.state;
            State returnedState = successResponse.getState();
            if(!returnedState.equals(savedState)) {  // TODO: Green flag if we have triggered.
                return Response.status(Response.Status.UNAUTHORIZED).entity("State does not match").build(); // TODO second aspect: check must follow a broken control flow.
            }
            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();
            return OK_tokenRequestValidateIdToken(oidcConfig, authorizationCode);
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    // STEP 3 in flow chart
    public Response OK_tokenRequestValidateIdToken(OidcConfig oidcConfig, AuthorizationCode authorizationCode) {
        // Make the token request
        ClientID clientID = new ClientID(config.getProperty("client_id"));
        Secret clientSecret = new Secret(config.getProperty("client_secret"));
        TokenRequest tokenRequest = new TokenRequest(providerMetadata.getTokenEndpointURI(),
                new ClientSecretBasic(clientID, clientSecret),
                new AuthorizationCodeGrant(authorizationCode, callback));
        TokenResponse tokenResponse = null;
        try {
            tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send()); // TODO: Control flow: The state must be checked between trigger AuthenticationResponse and this exit point
            idTokenValidator = new IDTokenValidator(providerMetadata.getIssuer(),
                    clientID,
                    JWSAlgorithm.RS256,
                    providerMetadata.getJWKSetURI().toURL());
            if (!tokenResponse.indicatesSuccess()) {  // TODO: trigger for error handling and break control flow
                // We got an error response...
                TokenErrorResponse errorResponse = Objects.requireNonNull(tokenResponse).toErrorResponse();
                // Handle error response
                return Response.status(Response.Status.BAD_REQUEST).entity("Failed: "+errorResponse.getErrorObject().getCode()).build(); // TODO: Expect a return / break of control flow if there's an error response
            }
        } catch (IOException | ParseException e) {
            // Handle exceptions
            Response.status(Response.Status.BAD_REQUEST).build();
        }
        try {
            OIDCTokenResponse successTokenResponse = (OIDCTokenResponse) Objects.requireNonNull(tokenResponse).toSuccessResponse();
            Nonce savedNonce = oidcConfig.nonce;
            idTokenValidator.validate(successTokenResponse.getOIDCTokens().getIDToken(), savedNonce);
            return Response
                    .ok(successTokenResponse.toJSONObject())
                    .build();
        } catch (JOSEException | BadJOSEException e) {
            // Error handling and break flow
            return Response.status(Response.Status.BAD_REQUEST).build();
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

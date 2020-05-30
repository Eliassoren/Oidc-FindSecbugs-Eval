package oidc.otherexamples;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Properties;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;

@Path("/auth")
public class AuthResource {

   public enum Keys {
        CLIENT_ID("client_id"),
        CLIENT_ID_ADMIN("client_id_admin"),
        CLIENT_SECRET("client_secret"),
        CLIENT_SECRET_ADMIN("client_secret_admin");

        private final String key;
        Keys(String key) {this.key = key;}

        public String getKey() {
            return key;
        }
    }

    public static class Config {
        private Properties propertiesConfig = new Properties();

        private Config() {
            String propertiesFileName = "config.properties";
            try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(propertiesFileName)) {
                if(inputStream == null) {
                    throw new FileNotFoundException("Config property file was not found in the classpath");
                }
                propertiesConfig.load(inputStream);
            } catch (Exception e) {
                // Log errors
            }
        }

        public String getValue(Keys key) {
            return propertiesConfig.getProperty(key.getKey());
        }

        public String getClientId() {
            return getValue(Keys.CLIENT_ID);
        }

        public String getClientSecret() {
            return getValue(Keys.CLIENT_SECRET);
        }

        public String getAdminClientId() {
            return getValue(Keys.CLIENT_ID_ADMIN);
        }

        public String getAdminClientSecret() {
            return getValue(Keys.CLIENT_SECRET_ADMIN);
        }
    }

    private final Config config;

    public AuthResource(Config config) {
        this.config = config;
    }

    @Path("login")
    @POST
    public Response login(@Context HttpHeaders headers, Map<String, String> body) {
        if(!body.containsKey("username") || !body.containsKey("password")) {
            throw new WebApplicationException("Missing username or password");
        }
        try {
            String username = body.get("username");
            Secret password = new Secret(body.get("password"));
            AuthorizationGrant passwordGrant =
                    new ResourceOwnerPasswordCredentialsGrant(username, password); // FIXME: password grant bad practice
            HTTPResponse httpResponse = getHttpResponse(passwordGrant, getUserType(body));
            password.erase(); // FIXME bug; insecure practice. Should be in finally block. Bad control flow.
            handleErrorResponses(httpResponse);

            OIDCTokenResponse response = OIDCTokenResponse.parse(httpResponse);
            // FIXME bug: where is the token validation?
            return getResponse(response);
        } catch (Exception e) {
            if(e instanceof ParseException) {
                throw new WebApplicationException("Error while parsing access token", e);
            }
            throw new WebApplicationException("Error getting access token", e);
        }
    }

    public void exampleAuthenticationRequest() {
        try {
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getClientId());
            URI callbackURI = new URI("https://client.com/callback");
            // Generate random state string and nonce for pairing the response to the request
            State state = new State();
            Nonce nonce = new Nonce();
            AuthenticationRequest req = new AuthenticationRequest(
                    new URI("https://c2id.com/login"),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callbackURI,
                    state,
                null);
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

    @Path("refresh")
    @POST
    public Response refresh(@Context HttpHeaders headers, Map<String, String> body) {
        try {
            if(!body.containsKey("refreshToken")) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Refreshtoken was not found").build();
            }
            AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(new RefreshToken(body.get("refreshToken")));

            HTTPResponse httpResponse = getHttpResponse(refreshTokenGrant, getUserType(body));
            JSONObject responseBody = httpResponse.getContentAsJSONObject();
            int statusCode = httpResponse.getStatusCode();
            if(statusCode == 401 || statusCode == 403 // FIXME bug: blacklist approach
                    || statusCode == 400 && "invalid_grant".equals(responseBody.get("error"))) {
                throw new NotAuthorizedException(
                        statusCode,
                        "Unsuccessful login"
                );
            }
            OIDCTokenResponse response = OIDCTokenResponse.parse(httpResponse);
            return getResponse(response);
        } catch (Exception e) {
            throw new RuntimeException("Error getting access token", e);
        }
    }

    private Response getResponse(OIDCTokenResponse response) {
        OIDCTokenResponse successResponse = response.toSuccessResponse();

        OIDCTokens tokens = successResponse.getOIDCTokens();
        AccessToken accessToken = tokens.getAccessToken();
        RefreshToken refreshToken = tokens.getRefreshToken();

        return Response.ok()
                .entity(new OpenIdTokens(
                        tokens.getIDTokenString(),
                        accessToken != null ? accessToken.getValue() : null,
                        refreshToken != null ? refreshToken.getValue() : null))
                .build();
    }

    private HTTPResponse getHttpResponse(AuthorizationGrant passwordGrant, UserType userType) throws URISyntaxException, IOException {
        ClientAuthentication clientAuth = getClientAuthentication(userType);

        Scope scope = new Scope("profile", "openidconnect");

        URI tokenEndpoint = new URI(userType == UserType.ADMIN ?
                                         "https://organization.com/api/admintoken":
                                         "https://organization.com/api/token");

        TokenRequest request =
                new TokenRequest(
                        tokenEndpoint,
                        clientAuth,
                        passwordGrant,
                        scope,
                        null,
                        singletonMap("auth_chain", singletonList("oauth2chain")));

        HTTPRequest httpRequest = request.toHTTPRequest();

        httpRequest.setHeader("applicationguid", "ID");//getTransaction().getId());

        return httpRequest.send();
    }

    public enum UserType {
        USER,
        ADMIN
    }

    public static class OpenIdTokens {
        public final String idToken;
        public final String accessToken;
        public final String refreshToken;

        public OpenIdTokens(String idToken,
                            String accessToken,
                            String refreshToken) {
            this.idToken = idToken;
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }

    private ClientAuthentication getClientAuthentication(UserType userType) {
        if(userType == UserType.USER) {
            ClientID clientID = new ClientID(config.getClientId());
            Secret clientSecret = new Secret(config.getClientSecret());
            return new ClientSecretBasic(clientID, clientSecret);
        } else { // Admin
            ClientID clientID = new ClientID(config.getAdminClientId());
            Secret clientSecret = new Secret(config.getAdminClientSecret());
            return new ClientSecretBasic(clientID, clientSecret);
        }

    }

    private void handleErrorResponses(HTTPResponse httpResponse) throws ParseException {
            JSONObject responseBody = httpResponse.getContentAsJSONObject();
            String errorDescription = (String)responseBody.get("error_description");
            int statusCode = httpResponse.getStatusCode();
            if(statusCode == 401 || statusCode == 403 // FIXME bug: blacklist approach
            || statusCode == 400 && "invalid_grant".equals(responseBody.get("error"))) {
                throw new NotAuthorizedException(
                        statusCode,
                        "Unsuccessful login"
                );
            }

    }

    private UserType getUserType(Map<String, String> body) {
        String userType = body.get("user_type");
        if (userType == null || userType.equals("customer")) {
            return UserType.USER;
        } else if (userType.equals("admin")) {
            return UserType.ADMIN;
        } else {
            throw new WebApplicationException("Wrong user type");
        }
    }
}

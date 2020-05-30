package oidc.nimbus;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import oidc.util.nimbus.OidcConfig;
import sun.security.util.Cache;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Properties;
import java.util.UUID;

public class OidcAuthRequestAddStateAndNonce {
    private Properties config;
    private Cache<String, Object> cache;
    private OIDCProviderMetadata providerMetadata;
    private URI callback;

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
            try (java.util.Scanner s = new java.util.Scanner(stream)) {
                providerInfo = s.useDelimiter("\\A").next();
            }
            return OIDCProviderMetadata.parse(providerInfo);
        } catch (ParseException | IOException | URISyntaxException e ) {
            // Handle
        }
        throw new RuntimeException("Failed to perform discovery");
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
}

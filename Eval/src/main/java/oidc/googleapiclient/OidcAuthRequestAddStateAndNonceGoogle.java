package oidc.googleapiclient;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.testing.json.MockJsonFactory;
import com.nimbusds.oauth2.sdk.ParseException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import oidc.util.googleapiclient.OidcConfig;
import sun.security.util.Cache;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.*;

public class OidcAuthRequestAddStateAndNonceGoogle {
    // @Path("/login")
    private Properties config;

    private AuthorizationCodeFlow authorizationCodeFlow;
    private AuthorizationCodeRequestUrl requestUrl;
    private PublicKey keyFromDiscoveryDocument;
    private Cache<String, Object> cache;
    Map<String, Object> providerMetadata;
    SecureRandom secureRandom;


    private String nonce() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return new String(Base64.getEncoder().encode(randomBytes));
    }

    private String state() {
        return nonce();
    }

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

}

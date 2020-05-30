package oidc.otherexamples;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import net.minidev.json.JSONArray;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Arrays.asList;
import static java.util.Collections.emptySet;
import static java.util.Objects.isNull;
import static java.util.stream.Collectors.toSet;

@Provider
public class AuthenticationFilter implements ContainerRequestFilter {
    private boolean authEnabled = true; // Replaced config var
    private final List<IDTokenValidator> idTokenValidators;
   // private static final Logger log = LoggerFactory.getLogger(AuthenticationFilter.class);
    private final PermissionService permissionService;

    public AuthenticationFilter(PermissionService permissionService) throws MalformedURLException {
        this.permissionService = permissionService;
        idTokenValidators = asList(userTokenValidator(), adminTokenValidator());
    }


    @Override
    public void filter(ContainerRequestContext requestContext) {
        if(!authEnabled) { // config.authEnabled() TODO: dobbelsjekk original
            requestContext.setSecurityContext(SecurityContext.unauthenticated());
            return;
        }

        String authHeader = requestContext.getHeaderString("Authorization");

        if(isNull(authHeader)) {
            requestContext.setSecurityContext(SecurityContext.unauthenticated());
            return;
        }
        String jwtToken = authHeader.replaceFirst("Bearer ", "");

        Optional<IDTokenClaimsSet> decodedJWT = decodeJWT(jwtToken);
        if (decodedJWT.isPresent()){
            IDTokenClaimsSet jwt = decodedJWT.get();
            requestContext.setSecurityContext(fromJWT(jwt));

        } else {
            requestContext
                    .setSecurityContext(SecurityContext.unauthenticated());
            requestContext
                    .abortWith(Response.status(Response.Status.UNAUTHORIZED).build());

        }
    }

    private IDTokenValidator userTokenValidator() throws MalformedURLException {
        String baseUrl = "https://organization.com/user";
        Issuer iss = new Issuer(baseUrl);
        ClientID clientID = new ClientID("OauthClientIdSample"); // config.getOAuthClientId()
        JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
        URL jwkSetURL = new URL("https://authentication.org.com/jwk");
        return new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);
    }

    private IDTokenValidator adminTokenValidator() throws MalformedURLException {
        String baseUrl =  "https://organization.com/admin";// config.getOpenAMBaseUrlServiceAccount();
        Issuer iss = new Issuer(baseUrl);
        ClientID clientID = new ClientID("OauthAdminClientId");//config.getOAuthServiceaccountClientId());
        JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
        URL jwkSetURL = new URL("https://authentication.org.com/admin/jwk");//config.getOpenamJWKUrlServiceAccount() );
        return new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL);
    }


    private javax.ws.rs.core.SecurityContext fromJWT(IDTokenClaimsSet jwt) {
        String username = jwt.getClaim("uid", String.class);
        return new SecurityContext(
                username,
                getOrganizationroles(jwt),
                permissionService.permissionsForUser(username)
        );
    }

    private Set<String> getOrganizationroles(IDTokenClaimsSet jwt) {
        JSONArray orgroles = jwt.getClaim("orgroles", JSONArray.class);
        if(orgroles == null) return emptySet();
        return orgroles
                .stream()
                .map(String.class::cast)
                .collect(toSet());
    }

    private Optional<IDTokenClaimsSet> decodeJWT(String jwtToken) {
        for (IDTokenValidator idTokenValidator : idTokenValidators) {
            try {
                JWT idToken = JWTParser.parse(jwtToken);
                IDTokenClaimsSet claimsSet = idTokenValidator.validate(idToken, null);
                return Optional.of(claimsSet);
            } catch (Exception exception){
              //  log.warn(jwtToken, exception);
            }
        }
        return Optional.empty();
    }

}

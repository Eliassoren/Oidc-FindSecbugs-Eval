package oidc.nimbus.badpractice;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.auth.Secret;

import java.util.Map;

public class OidcPasswordGrant {

    public void authenticate(Map<String, String> body) {
            String username = body.get("username");
            Secret password = new Secret(body.get("password"));
            AuthorizationGrant passwordGrant =
                    new ResourceOwnerPasswordCredentialsGrant(username, password);
            tokenRequest(passwordGrant);
    }

    private void tokenRequest(AuthorizationGrant passwordGrant) {
        // do stuff
    }
}

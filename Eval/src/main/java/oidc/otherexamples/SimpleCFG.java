package oidc.otherexamples;

import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import oidc.util.googleapiclient.OidcConfig;

import javax.ws.rs.core.Response;
import java.security.PublicKey;

public class SimpleCFG {
    PublicKey publicKey;
    public int simpleCFGAnalyzed1() {
        if(a()) {
            return 1;
        }
        return 2;
    }

    public int simpleCFGAnalyzed2() {
        if(!a()) {
            return 1;
        }
        if(!b()) {
            return 2;
        }

        return 3;
    }

    public Response validateTokens(IdTokenResponse tokenResponse, OidcConfig oidcConfig) {
        try {
            IdToken idToken = tokenResponse.parseIdToken(); // Parse
            if (!oidcConfig.nonce.equals(idToken.getPayload().getNonce())) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .build();
            }
            if(!idToken.verifySignature(publicKey)){
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("The jwt signature is not valid.")
                        .build();
            }
            return Response.ok().build();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean a() {
        // do stuff
        return true;
    }

    private boolean b() {
        // do stuff
        return true;
    }
}


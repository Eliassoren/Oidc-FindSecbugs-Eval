package oidc.util.nimbus;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.util.UUID;

public class OidcConfig {
    public final State state;
    public final Nonce nonce;
    public final UUID appuuid;
    public OidcConfig(State state, Nonce nonce, UUID appuuid) {
        this.state = state;
        this.nonce = nonce;
        this.appuuid = appuuid;
    }
    public OidcConfig() {
        this.state = new State();
        this.nonce = new Nonce();
        this.appuuid = UUID.randomUUID();
    }
}

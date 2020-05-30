package oidc.util.googleapiclient;

import java.util.UUID;

public class OidcConfig {
    public final String state;
    public final String nonce;
    public final UUID appuuid;
    public OidcConfig(String state, String nonce, UUID appuuid) {
        this.state = state;
        this.nonce = nonce;
        this.appuuid = appuuid;
    }
    public OidcConfig() {
        this.state = "state";
        this.nonce = "nonce";
        this.appuuid = UUID.randomUUID();
    }
}

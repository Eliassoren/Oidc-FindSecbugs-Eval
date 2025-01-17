package firebase.boilerplate;/*
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.google.common.collect.ImmutableMap;

import java.util.Map;

import static com.google.common.base.Preconditions.checkArgument;


public final class FirebaseToken {

  private final Map<String, Object> claims;

  public FirebaseToken(Map<String, Object> claims) {
    checkArgument(claims != null && claims.containsKey("sub"),
        "Claims map must at least contain sub");
    this.claims = ImmutableMap.copyOf(claims);
  }

  /** Returns the Uid for the this token. */
  public String getUid() {
    return (String) claims.get("sub");
  }

  /** Returns the Issuer for the this token. */
  public String getIssuer() {
    return (String) claims.get("iss");
  }

  /** Returns the user's display name. */
  public String getName() {
    return (String) claims.get("name");
  }

  /** Returns the Uri string of the user's profile photo. */
  public String getPicture() {
    return (String) claims.get("picture");
  }

  /** 
   * Returns the e-mail address for this user, or {@code null} if it's unavailable.
   */
  public String getEmail() {
    return (String) claims.get("email");
  }

  /** 
   * Indicates if the email address returned by {@link #getEmail()} has been verified as good.
   */
  public boolean isEmailVerified() {
    Object emailVerified = claims.get("email_verified");
    return emailVerified != null && (Boolean) emailVerified;
  }

  /** Returns a map of all of the claims on this token. */
  public Map<String, Object> getClaims() {
    return this.claims;
  }
}

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

import firebase.authinternal.FirebaseTokenFactory;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.util.Clock;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;

import firebase.filetobeanalyzed.FirebaseTokenUtils;
import firebase.internal.CallableOperation;
import firebase.internal.FirebaseService;
import firebase.internal.NonNull;
import firebase.internal.Nullable;


import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.google.common.base.Preconditions.*;

/**
 * This class is the entry point for all server-side Firebase Authentication actions.
 *
 * then use it to perform a variety of authentication-related operations, including generating
 * custom tokens for use by client-side code, verifying Firebase ID Tokens received from clients, or
 * creating new firebase.boilerplate.FirebaseApp instances that are scoped to a particular authentication UID.
 */
public class FirebaseAuth {

  private static final String SERVICE_ID = FirebaseAuth.class.getName();

  private static final String ERROR_CUSTOM_TOKEN = "ERROR_CUSTOM_TOKEN";

  private final Object lock = new Object();
  private final AtomicBoolean destroyed = new AtomicBoolean(false);

  private final FirebaseApp firebaseApp;
  private final Supplier<FirebaseTokenFactory> tokenFactory;
  private final Supplier<? extends FirebaseTokenVerifier> idTokenVerifier;
  private final Supplier<? extends FirebaseTokenVerifier> cookieVerifier;
  private final Supplier<? extends FirebaseUserManager> userManager;
  private final JsonFactory jsonFactory;

  private FirebaseAuth(Builder builder) {
    this.firebaseApp = checkNotNull(builder.firebaseApp);
    this.tokenFactory = threadSafeMemoize(builder.tokenFactory);
    this.idTokenVerifier = threadSafeMemoize(builder.idTokenVerifier);
    this.cookieVerifier = threadSafeMemoize(builder.cookieVerifier);
    this.userManager = threadSafeMemoize(builder.userManager);
    this.jsonFactory = firebaseApp.getOptions().getJsonFactory();
  }

  /**
   * Gets the firebase.boilerplate.FirebaseAuth instance for the default {@link FirebaseApp}.
   *
   * @return The firebase.boilerplate.FirebaseAuth instance for the default {@link FirebaseApp}.
   */
  public static FirebaseAuth getInstance() {
    return FirebaseAuth.getInstance(FirebaseApp.getInstance());
  }

  /**
   * Gets an instance of firebase.boilerplate.FirebaseAuth for a specific {@link FirebaseApp}.
   *
   * @param app The {@link FirebaseApp} to get a firebase.boilerplate.FirebaseAuth instance for.
   * @return A firebase.boilerplate.FirebaseAuth instance.
   */
  public static synchronized FirebaseAuth getInstance(FirebaseApp app) {
    FirebaseAuthService service = ImplFirebaseTrampolines.getService(app, SERVICE_ID,
        FirebaseAuthService.class);
    if (service == null) {
      service = ImplFirebaseTrampolines.addService(app, new FirebaseAuthService(app));
    }
    return service.getInstance();
  }

  /**
   * Creates a new Firebase session cookie from the given ID token and options. The returned JWT
   * can be set as a server-side session cookie with a custom cookie policy.
   *
   * @param idToken The Firebase ID token to exchange for a session cookie.
   * @param options Additional options required to create the cookie.
   * @return A Firebase session cookie string.
   * @throws IllegalArgumentException If the ID token is null or empty, or if options is null.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while generating the session cookie.
   */
  public String createSessionCookie(
      @NonNull String idToken, @NonNull SessionCookieOptions options) throws ExportedUserRecord.FirebaseAuthException {
    return createSessionCookieOp(idToken, options).call();
  }


  private CallableOperation<String, ExportedUserRecord.FirebaseAuthException> createSessionCookieOp(
      final String idToken, final SessionCookieOptions options) {
    checkNotDestroyed();
    checkArgument(!Strings.isNullOrEmpty(idToken), "idToken must not be null or empty");
    checkNotNull(options, "options must not be null");
    final FirebaseUserManager userManager = getUserManager();
    return new CallableOperation<String, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      protected String execute() throws ExportedUserRecord.FirebaseAuthException {
        return userManager.createSessionCookie(idToken, options);
      }
    };
  }

  /**
   * Parses and verifies a Firebase session cookie.
   *
   * <p>If verified successfully, returns a parsed version of the cookie from which the UID and the
   * other claims can be read. If the cookie is invalid, throws a {@link ExportedUserRecord.FirebaseAuthException}.
   *
   * <p>This method does not check whether the cookie has been revoked. See
   * {@link #verifySessionCookie(String, boolean)}.
   *
   * @param cookie A Firebase session cookie string to verify and parse.
   * @return A {@link FirebaseToken} representing the verified and decoded cookie.
   */
  public FirebaseToken verifySessionCookie(String cookie) throws ExportedUserRecord.FirebaseAuthException {
    return verifySessionCookie(cookie, false);
  }

  /**
   * Parses and verifies a Firebase session cookie.
   *
   * <p>If {@code checkRevoked} is true, additionally verifies that the cookie has not been
   * revoked.
   *
   * <p>If verified successfully, returns a parsed version of the cookie from which the UID and the
   * other claims can be read. If the cookie is invalid or has been revoked while
   * {@code checkRevoked} is true, throws a {@link ExportedUserRecord.FirebaseAuthException}.
   *
   * @param cookie A Firebase session cookie string to verify and parse.
   * @param checkRevoked A boolean indicating whether to check if the cookie was explicitly
   *     revoked.
   * @return A {@link FirebaseToken} representing the verified and decoded cookie.
   */
  public FirebaseToken verifySessionCookie(
      String cookie, boolean checkRevoked) throws ExportedUserRecord.FirebaseAuthException {
    return verifySessionCookieOp(cookie, checkRevoked).call();
  }


  private CallableOperation<FirebaseToken, ExportedUserRecord.FirebaseAuthException> verifySessionCookieOp(
      final String cookie, final boolean checkRevoked) {
    checkNotDestroyed();
    checkArgument(!Strings.isNullOrEmpty(cookie), "Session cookie must not be null or empty");
    final FirebaseTokenVerifier sessionCookieVerifier = getSessionCookieVerifier(checkRevoked);
    return new CallableOperation<FirebaseToken, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      public FirebaseToken execute() throws ExportedUserRecord.FirebaseAuthException {
        return sessionCookieVerifier.verifyToken(cookie);
      }
    };
  }

  @VisibleForTesting
  FirebaseTokenVerifier getSessionCookieVerifier(boolean checkRevoked) {
    FirebaseTokenVerifier verifier = cookieVerifier.get();
    if (checkRevoked) {
     FirebaseUserManager userManager = getUserManager();
      verifier = RevocationCheckDecorator.decorateSessionCookieVerifier(verifier, userManager);
    }
    return verifier;
  }

  /**
   * Creates a Firebase custom token for the given UID. This token can then be sent back to a client
   * application to be used with the
   * <a href="/docs/auth/admin/create-custom-tokens#sign_in_using_custom_tokens_on_clients">signInWithCustomToken</a>
   * authentication API.
   *
   * call this method.
   *
   * @param uid The UID to store in the token. This identifies the user to other Firebase services
   *     (Realtime Database, Firebase Auth, etc.). Should be less than 128 characters.
   * @return A Firebase custom token string.
   * @throws IllegalArgumentException If the specified uid is null or empty, or if the app has not
   *     been initialized with service account credentials.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while generating the custom token.
   */
  public String createCustomToken(@NonNull String uid) throws ExportedUserRecord.FirebaseAuthException {
    return createCustomToken(uid, null);
  }

  /**
   * Creates a Firebase custom token for the given UID, containing the specified additional
   * claims. This token can then be sent back to a client application to be used with the
   * <a href="/docs/auth/admin/create-custom-tokens#sign_in_using_custom_tokens_on_clients">signInWithCustomToken</a>
   * authentication API.
   *
   * <p>This method attempts to generate a token using:
   * <ol>
   *   <li>the private key of {@link FirebaseApp}'s service account credentials, if provided at
   *   initialization.
   *   <li>the <a href="https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signBlob">IAM service</a>
   *   if a service account email was specified via
   *   {@linkFirebaseOptions.Builder#setServiceAccountId(String)}.
   *   <li>the <a href="https://cloud.google.com/appengine/docs/standard/java/appidentity/">App Identity
   *   service</a> if the code is deployed in the Google App Engine standard environment.
   *   <li>the <a href="https://cloud.google.com/compute/docs/storing-retrieving-metadata">
   *   local Metadata server</a> if the code is deployed in a different GCP-managed environment
   *   like Google Compute Engine.
   * </ol>
   *
   * <p>This method throws an exception when all the above fail.
   *
   * @param uid The UID to store in the token. This identifies the user to other Firebase services
   *     (Realtime Database, Firebase Auth, etc.). Should be less than 128 characters.
   * @param developerClaims Additional claims to be stored in the token (and made available to
   *     security rules in Database, Storage, etc.). These must be able to be serialized to JSON
   *     (e.g. contain only Maps, Arrays, Strings, Booleans, Numbers, etc.)
   * @return A Firebase custom token string.
   * @throws IllegalArgumentException If the specified uid is null or empty.
   * @throws IllegalStateException If the SDK fails to discover a viable approach for signing
   *     tokens.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while generating the custom token.
   */
  public String createCustomToken(@NonNull String uid,
      @Nullable Map<String, Object> developerClaims) throws ExportedUserRecord.FirebaseAuthException {
    return createCustomTokenOp(uid, developerClaims).call();
  }



  private CallableOperation<String, ExportedUserRecord.FirebaseAuthException> createCustomTokenOp(
      final String uid, final Map<String, Object> developerClaims) {
    checkNotDestroyed();
    checkArgument(!Strings.isNullOrEmpty(uid), "uid must not be null or empty");
    final FirebaseTokenFactory tokenFactory = this.tokenFactory.get();
    return new CallableOperation<String, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      public String execute() throws ExportedUserRecord.FirebaseAuthException {
        try {
          return tokenFactory.createSignedCustomAuthTokenForUser(uid, developerClaims);
        } catch (IOException e) {
          throw new ExportedUserRecord.FirebaseAuthException(ERROR_CUSTOM_TOKEN,
              "Failed to generate a custom token", e);
        }
      }
    };
  }

  /**
   * Parses and verifies a Firebase ID Token.
   *
   * <p>A Firebase application can identify itself to a trusted backend server by sending its
   * Firebase ID Token (accessible via the {@code getToken} API in the Firebase Authentication
   * client) with its requests. The backend server can then use the {@code verifyIdToken()} method
   * to verify that the token is valid. This method ensures that the token is correctly signed,
   * has not expired, and it was issued to the Firebase project associated with this
   * {@linkFirebaseAuth} instance.
   *
   * <p>This method does not check whether a token has been revoked. Use
   * {@link #verifyIdToken(String, boolean)} to perform an additional revocation check.
   *
   * @param token A Firebase ID token string to parse and verify.
   * @return A {@link FirebaseToken} representing the verified and decoded token.
   *     instance does not have a project ID associated with it.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while parsing or validating the token.
   */
  public FirebaseToken verifyIdToken(@NonNull String token) throws ExportedUserRecord.FirebaseAuthException {
    return verifyIdToken(token, false);
  }

  /**
   * Parses and verifies a Firebase ID Token.
   *
   * <p>A Firebase application can identify itself to a trusted backend server by sending its
   * Firebase ID Token (accessible via the {@code getToken} API in the Firebase Authentication
   * client) with its requests. The backend server can then use the {@code verifyIdToken()} method
   * to verify that the token is valid. This method ensures that the token is correctly signed,
   * has not expired, and it was issued to the Firebase project associated with this
   * {@linkFirebaseAuth} instance.
   *
   * <p>If {@code checkRevoked} is set to true, this method performs an additional check to see
   * if the ID token has been revoked since it was issues. This requires making an additional
   * remote API call.
   *
   * @param token A Firebase ID token string to parse and verify.
   * @param checkRevoked A boolean denoting whether to check if the tokens were revoked.
   * @return A {@link FirebaseToken} representing the verified and decoded token.
   *     instance does not have a project ID associated with it.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while parsing or validating the token.
   */
  public FirebaseToken verifyIdToken(
      @NonNull String token, boolean checkRevoked) throws ExportedUserRecord.FirebaseAuthException {
    return verifyIdTokenOp(token, checkRevoked).call();
  }

  /**
   * Similar to {@link #verifyIdToken(String)} but performs the operation asynchronously.
   *
   * @param token A Firebase ID Token to verify and parse.
   * @return An {@code firebase.boilerplate.ApiFuture} which will complete successfully with the parsed token, or
   *     unsuccessfully with a {@link ExportedUserRecord.FirebaseAuthException}.
   *     instance does not have a project ID associated with it.
   */
  public ApiFuture<FirebaseToken> verifyIdTokenAsync(@NonNull String token) {
    return verifyIdTokenAsync(token, false);
  }

  /**
   * Similar to {@link #verifyIdToken(String, boolean)} but performs the operation asynchronously.
   *
   * @param token A Firebase ID Token to verify and parse.
   * @param checkRevoked A boolean denoting whether to check if the tokens were revoked.
   * @return An {@code firebase.boilerplate.ApiFuture} which will complete successfully with the parsed token, or
   *     unsuccessfully with a {@link ExportedUserRecord.FirebaseAuthException}.
   * @throws IllegalArgumentException If the token is null, empty, or if the {@link FirebaseApp}
   *     instance does not have a project ID associated with it.
   */
  public ApiFuture<FirebaseToken> verifyIdTokenAsync(@NonNull String token, boolean checkRevoked) {
    return verifyIdTokenOp(token, checkRevoked).callAsync(firebaseApp);
  }

  private CallableOperation<FirebaseToken, ExportedUserRecord.FirebaseAuthException> verifyIdTokenOp(
      final String token, final boolean checkRevoked) {
    checkNotDestroyed();
    checkArgument(!Strings.isNullOrEmpty(token), "ID token must not be null or empty");
    final FirebaseTokenVerifier verifier = getIdTokenVerifier(checkRevoked);
    return new CallableOperation<FirebaseToken, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      protected FirebaseToken execute() throws ExportedUserRecord.FirebaseAuthException {
        return verifier.verifyToken(token);
      }
    };
  }

  @VisibleForTesting
  FirebaseTokenVerifier getIdTokenVerifier(boolean checkRevoked) {
    FirebaseTokenVerifier verifier = idTokenVerifier.get();
    if (checkRevoked) {
     FirebaseUserManager userManager = getUserManager();
      verifier = RevocationCheckDecorator.decorateIdTokenVerifier(verifier, userManager);
    }
    return verifier;
  }




  /**
   * Gets the user data corresponding to the specified user email.
   *
   * @param email A user email address string.
   * @return A {@link UserRecord} instance.
   * @throws IllegalArgumentException If the email is null or empty.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while retrieving user data.
   */
  public UserRecord getUserByEmail(@NonNull String email) throws ExportedUserRecord.FirebaseAuthException {
    return getUserByEmailOp(email).call();
  }

  private CallableOperation<UserRecord, ExportedUserRecord.FirebaseAuthException> getUserByEmailOp(
      final String email) {
    checkNotDestroyed();
    checkArgument(!Strings.isNullOrEmpty(email), "email must not be null or empty");
    final FirebaseUserManager userManager = getUserManager();
    return new CallableOperation<UserRecord, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      protected UserRecord execute() throws ExportedUserRecord.FirebaseAuthException {
        return userManager.getUserByEmail(email);
      }
    };
  }

  /**
   * Gets the user data corresponding to the specified user phone number.
   *
   * @param phoneNumber A user phone number string.
   * @return A a {@link UserRecord} instance.
   * @throws IllegalArgumentException If the phone number is null or empty.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while retrieving user data.
   */
  public UserRecord getUserByPhoneNumber(@NonNull String phoneNumber) throws ExportedUserRecord.FirebaseAuthException {
    return getUserByPhoneNumberOp(phoneNumber).call();
  }


  private CallableOperation<UserRecord, ExportedUserRecord.FirebaseAuthException> getUserByPhoneNumberOp(
      final String phoneNumber) {
    checkNotDestroyed();
    checkArgument(!Strings.isNullOrEmpty(phoneNumber), "phone number must not be null or empty");
    final FirebaseUserManager userManager = getUserManager();
    return new CallableOperation<UserRecord, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      protected UserRecord execute() throws ExportedUserRecord.FirebaseAuthException {
        return userManager.getUserByPhoneNumber(phoneNumber);
      }
    };
  }

  /**
   * Gets the user data corresponding to the specified identifiers.
   *
   * <p>There are no ordering guarantees; in particular, the nth entry in the users result list is
   * not guaranteed to correspond to the nth entry in the input parameters list.
   *
   * <p>A maximum of 100 identifiers may be specified. If more than 100 identifiers are
   * supplied, this method throws an {@link IllegalArgumentException}.
   *
   * @param identifiers The identifiers used to indicate which user records should be returned. Must
   *     have 100 or fewer entries.
   * @return The corresponding user records.
   * @throws IllegalArgumentException If any of the identifiers are invalid or if more than 100
   *     identifiers are specified.
   * @throws NullPointerException If the identifiers parameter is null.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while retrieving user data.
   */
  public GetUsersResult getUsers(@NonNull Collection<UserIdentifier> identifiers)
      throws ExportedUserRecord.FirebaseAuthException {
    return getUsersOp(identifiers).call();
  }


  private CallableOperation<  GetUsersResult, ExportedUserRecord.FirebaseAuthException> getUsersOp(
      @NonNull final Collection<UserIdentifier> identifiers) {
    checkNotDestroyed();
    checkNotNull(identifiers, "identifiers must not be null");
    checkArgument(identifiers.size() <= FirebaseUserManager.MAX_GET_ACCOUNTS_BATCH_SIZE,
        "identifiers parameter must have <= " + FirebaseUserManager.MAX_GET_ACCOUNTS_BATCH_SIZE
        + " entries.");

    final FirebaseUserManager userManager = getUserManager();
    return new CallableOperation<  GetUsersResult, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      protected GetUsersResult execute() throws ExportedUserRecord.FirebaseAuthException {
        Set<UserRecord> users = userManager.getAccountInfo(identifiers);
        Set<UserIdentifier> notFound = new HashSet<>();
        for (UserIdentifier id : identifiers) {
          if (!isUserFound(id, users)) {
            notFound.add(id);
          }
        }
        return new GetUsersResult(users, notFound);
      }
    };
  }

  private boolean isUserFound(UserIdentifier id, Collection<UserRecord> userRecords) {
    for (UserRecord userRecord : userRecords) {
      if (id.matches(userRecord)) {
        return true;
      }
    }
    return false;
  }










  /**
   * Deletes the user identified by the specified user ID.
   *
   * @param uid A user ID string.
   * @throws IllegalArgumentException If the user ID string is null or empty.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while deleting the user.
   */
  public void deleteUser(@NonNull String uid) throws ExportedUserRecord.FirebaseAuthException {
    deleteUserOp(uid).call();
  }



  private CallableOperation<Void, ExportedUserRecord.FirebaseAuthException> deleteUserOp(final String uid) {
    checkNotDestroyed();
    checkArgument(!Strings.isNullOrEmpty(uid), "uid must not be null or empty");
    final FirebaseUserManager userManager = getUserManager();
    return new CallableOperation<Void, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      protected Void execute() throws ExportedUserRecord.FirebaseAuthException {
        userManager.deleteUser(uid);
        return null;
      }
    };
  }


  /**
   * Imports the provided list of users into Firebase Auth. At most 1000 users can be imported at a
   * time. This operation is optimized for bulk imports and will ignore checks on identifier
   * uniqueness which could result in duplications.
   *
   * @param users A non-empty list of users to be imported. Length must not exceed 1000.
   * @param options a {@link UserImportOptions} instance or null. Required when importing users
   *     with passwords.
   * @return A {@link UserImportResult} instance.
   * @throws IllegalArgumentException If the users list is null, empty or has more than 1000
   *     elements. Or if at least one user specifies a password, and options is null.
   * @throws ExportedUserRecord.FirebaseAuthException If an error occurs while importing users.
   */
  public UserImportResult importUsers(List<ImportUserRecord> users,
      @Nullable UserImportOptions options) throws ExportedUserRecord.FirebaseAuthException {
    return importUsersOp(users, options).call();
  }



  private CallableOperation<UserImportResult, ExportedUserRecord.FirebaseAuthException> importUsersOp(
      final List<ImportUserRecord> users, final UserImportOptions options) {
    checkNotDestroyed();
    final FirebaseUserManager.UserImportRequest request = new FirebaseUserManager.UserImportRequest(users, options, jsonFactory);
    final FirebaseUserManager userManager = getUserManager();
    return new CallableOperation<UserImportResult, ExportedUserRecord.FirebaseAuthException>() {
      @Override
      protected UserImportResult execute() throws ExportedUserRecord.FirebaseAuthException {
        return userManager.importUsers(request);
      }
    };
  }





  @VisibleForTesting
  FirebaseUserManager getUserManager() {
    return this.userManager.get();
  }



  private <T> Supplier<T> threadSafeMemoize(final Supplier<T> supplier) {
    return Suppliers.memoize(new Supplier<T>() {
      @Override
      public T get() {
        checkNotNull(supplier);
        synchronized (lock) {
          checkNotDestroyed();
          return supplier.get();
        }
      }
    });
  }

  private void checkNotDestroyed() {
    synchronized (lock) {
      checkState(!destroyed.get(), "firebase.boilerplate.FirebaseAuth instance is no longer alive. This happens when "
          + "the parent firebase.boilerplate.FirebaseApp instance has been deleted.");
    }
  }

  private void destroy() {
    synchronized (lock) {
      destroyed.set(true);
    }
  }

  private static FirebaseAuth fromApp(final FirebaseApp app) {
    return FirebaseAuth.builder()
        .setFirebaseApp(app)
        .setTokenFactory(new Supplier<FirebaseTokenFactory>() {
          @Override
          public FirebaseTokenFactory get() {
            return FirebaseTokenUtils.createTokenFactory(app, Clock.SYSTEM);
          }
        })
        .setIdTokenVerifier(new Supplier<FirebaseTokenVerifier>() {
          @Override
          public FirebaseTokenVerifier get() {
            return FirebaseTokenUtils.createIdTokenVerifier(app, Clock.SYSTEM);
          }
        })
        .setCookieVerifier(new Supplier<FirebaseTokenVerifier>() {
          @Override
          public FirebaseTokenVerifier get() {
            return FirebaseTokenUtils.createSessionCookieVerifier(app, Clock.SYSTEM);
          }
        })
        .setUserManager(new Supplier<  FirebaseUserManager>() {
          @Override
          public FirebaseUserManager get() {
            return new FirebaseUserManager(app);
          }
        })
        .build();
  }

  @VisibleForTesting
  static Builder builder() {
    return new Builder();
  }

  static class Builder {
    private FirebaseApp firebaseApp;
    private Supplier<FirebaseTokenFactory> tokenFactory;
    private Supplier<? extends FirebaseTokenVerifier> idTokenVerifier;
    private Supplier<? extends FirebaseTokenVerifier> cookieVerifier;
    private Supplier<FirebaseUserManager> userManager;

    private Builder() { }

    Builder setFirebaseApp(FirebaseApp firebaseApp) {
      this.firebaseApp = firebaseApp;
      return this;
    }

    Builder setTokenFactory(Supplier<FirebaseTokenFactory> tokenFactory) {
      this.tokenFactory = tokenFactory;
      return this;
    }

    Builder setIdTokenVerifier(Supplier<? extends FirebaseTokenVerifier> idTokenVerifier) {
      this.idTokenVerifier = idTokenVerifier;
      return this;
    }

    Builder setCookieVerifier(Supplier<? extends FirebaseTokenVerifier> cookieVerifier) {
      this.cookieVerifier = cookieVerifier;
      return this;
    }

    Builder setUserManager(Supplier<  FirebaseUserManager> userManager) {
      this.userManager = userManager;
      return this;
    }

    FirebaseAuth build() {
      return new FirebaseAuth(this);
    }
  }

  private static class FirebaseAuthService extends FirebaseService<FirebaseAuth> {

    FirebaseAuthService(FirebaseApp app) {
      super(SERVICE_ID, FirebaseAuth.fromApp(app));
    }

    @Override
    public void destroy() {
      instance.destroy();
    }
  }
}

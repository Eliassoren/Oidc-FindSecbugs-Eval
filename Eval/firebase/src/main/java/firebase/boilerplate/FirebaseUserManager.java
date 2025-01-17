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

import firebase.authinternal.GetAccountInfoRequest;
import firebase.authinternal.GetAccountInfoResponse;
import com.google.api.client.http.*;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.util.Key;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import firebase.authinternal.HttpErrorResponse;
import firebase.authinternal.UploadAccountResponse;
import firebase.internal.ApiClientUtils;
import firebase.internal.NonNull;
import firebase.internal.Nullable;
import firebase.internal.SdkUtils;

import java.io.IOException;
import java.util.*;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * firebase.boilerplate.FirebaseUserManager provides methods for interacting with the Google Identity Toolkit via its
 * REST API. This class does not hold any mutable state, and is thread safe.
 *
 * @see <a href="https://developers.google.com/identity/toolkit/web/reference/relyingparty">
 *   Google Identity Toolkit</a>
 */
class FirebaseUserManager {

  static final String USER_NOT_FOUND_ERROR = "user-not-found";
  static final String INTERNAL_ERROR = "firebase.internal-error";

  // Map of server-side error codes to SDK error codes.
  // SDK error codes defined at: https://firebase.google.com/docs/auth/admin/errors
  private static final Map<String, String> ERROR_CODES = ImmutableMap.<String, String>builder()
      .put("CLAIMS_TOO_LARGE", "claims-too-large")
      .put("CONFIGURATION_NOT_FOUND", "project-not-found")
      .put("INSUFFICIENT_PERMISSION", "insufficient-permission")
      .put("DUPLICATE_EMAIL", "email-already-exists")
      .put("DUPLICATE_LOCAL_ID", "uid-already-exists")
      .put("EMAIL_EXISTS", "email-already-exists")
      .put("INVALID_CLAIMS", "invalid-claims")
      .put("INVALID_EMAIL", "invalid-email")
      .put("INVALID_PAGE_SELECTION", "invalid-page-token")
      .put("INVALID_PHONE_NUMBER", "invalid-phone-number")
      .put("PHONE_NUMBER_EXISTS", "phone-number-already-exists")
      .put("PROJECT_NOT_FOUND", "project-not-found")
      .put("USER_NOT_FOUND", USER_NOT_FOUND_ERROR)
      .put("WEAK_PASSWORD", "invalid-password")
      .put("UNAUTHORIZED_DOMAIN", "unauthorized-continue-uri")
      .put("INVALID_DYNAMIC_LINK_DOMAIN", "invalid-dynamic-link-domain")
      .build();

  static final int MAX_GET_ACCOUNTS_BATCH_SIZE = 100;
  static final int MAX_DELETE_ACCOUNTS_BATCH_SIZE = 1000;
  static final int MAX_LIST_USERS_RESULTS = 1000;
  static final int MAX_IMPORT_USERS = 1000;

  static final List<String> RESERVED_CLAIMS = ImmutableList.of(
      "amr", "at_hash", "aud", "auth_time", "azp", "cnf", "c_hash", "exp", "iat",
      "iss", "jti", "nbf", "nonce", "sub", "firebase");

  private static final String ID_TOOLKIT_URL =
      "https://identitytoolkit.googleapis.com/v1/projects/%s";
  private static final String CLIENT_VERSION_HEADER = "X-Client-Version";

  private final String baseUrl;
  private final JsonFactory jsonFactory;
  private final HttpRequestFactory requestFactory;
  private final String clientVersion = "Java/Admin/" + SdkUtils.getVersion();

  private HttpResponseInterceptor interceptor;

  /**
   * Creates a new firebase.boilerplate.FirebaseUserManager instance.
   *
   * @param app A non-null {@link FirebaseApp}.
   */
  FirebaseUserManager(@NonNull FirebaseApp app) {
    this(app, null);
  }

  FirebaseUserManager(@NonNull FirebaseApp app, @Nullable HttpRequestFactory requestFactory) {
    checkNotNull(app, "firebase.boilerplate.FirebaseApp must not be null");
    String projectId = ImplFirebaseTrampolines.getProjectId(app);
    checkArgument(!Strings.isNullOrEmpty(projectId),
        "Project ID is required to access the auth service. Use a service account credential or "
            + "set the project ID explicitly via firebase.boilerplate.FirebaseOptions. Alternatively you can also "
            + "set the project ID via the GOOGLE_CLOUD_PROJECT environment variable.");
    this.baseUrl = String.format(ID_TOOLKIT_URL, projectId);
    this.jsonFactory = app.getOptions().getJsonFactory();

    if (requestFactory == null) {
      requestFactory = ApiClientUtils.newAuthorizedRequestFactory(app);
    }

    this.requestFactory = requestFactory;
  }

  @VisibleForTesting
  void setInterceptor(HttpResponseInterceptor interceptor) {
    this.interceptor = interceptor;
  }

  UserRecord getUserById(String uid) throws ExportedUserRecord.FirebaseAuthException {
    final Map<String, Object> payload = ImmutableMap.<String, Object>of(
        "localId", ImmutableList.of(uid));
    GetAccountInfoResponse response = post(
        "/accounts:lookup", payload, GetAccountInfoResponse.class);
    if (response == null || response.getUsers() == null || response.getUsers().isEmpty()) {
      throw new ExportedUserRecord.FirebaseAuthException(USER_NOT_FOUND_ERROR,
          "No user record found for the provided user ID: " + uid);
    }
    return new UserRecord(response.getUsers().get(0), jsonFactory);
  }

  UserRecord getUserByEmail(String email) throws ExportedUserRecord.FirebaseAuthException {
    final Map<String, Object> payload = ImmutableMap.<String, Object>of(
        "email", ImmutableList.of(email));
    GetAccountInfoResponse response = post(
        "/accounts:lookup", payload, GetAccountInfoResponse.class);
    if (response == null || response.getUsers() == null || response.getUsers().isEmpty()) {
      throw new ExportedUserRecord.FirebaseAuthException(USER_NOT_FOUND_ERROR,
          "No user record found for the provided email: " + email);
    }
    return new UserRecord(response.getUsers().get(0), jsonFactory);
  }

  UserRecord getUserByPhoneNumber(String phoneNumber) throws ExportedUserRecord.FirebaseAuthException {
    final Map<String, Object> payload = ImmutableMap.<String, Object>of(
        "phoneNumber", ImmutableList.of(phoneNumber));
    GetAccountInfoResponse response = post(
        "/accounts:lookup", payload, GetAccountInfoResponse.class);
    if (response == null || response.getUsers() == null || response.getUsers().isEmpty()) {
      throw new ExportedUserRecord.FirebaseAuthException(USER_NOT_FOUND_ERROR,
          "No user record found for the provided phone number: " + phoneNumber);
    }
    return new UserRecord(response.getUsers().get(0), jsonFactory);
  }

  Set<UserRecord> getAccountInfo(@NonNull Collection<UserIdentifier> identifiers)
      throws ExportedUserRecord.FirebaseAuthException {
    if (identifiers.isEmpty()) {
      return new HashSet<UserRecord>();
    }

    GetAccountInfoRequest payload = new GetAccountInfoRequest();
    for (UserIdentifier id : identifiers) {
      id.populate(payload);
    }

    GetAccountInfoResponse response = post(
        "/accounts:lookup", payload, GetAccountInfoResponse.class);

    if (response == null) {
      throw new ExportedUserRecord.FirebaseAuthException(INTERNAL_ERROR, "Failed to parse server response");
    }

    Set<UserRecord> results = new HashSet<>();
    if (response.getUsers() != null) {
      for (GetAccountInfoResponse.User user : response.getUsers()) {
        results.add(new UserRecord(user, jsonFactory));
      }
    }
    return results;
  }

  String createUser(UserRecord.CreateRequest request) throws ExportedUserRecord.FirebaseAuthException {
    GenericJson response = post(
        "/accounts", request.getProperties(), GenericJson.class);
    if (response != null) {
      String uid = (String) response.get("localId");
      if (!Strings.isNullOrEmpty(uid)) {
        return uid;
      }
    }
    throw new ExportedUserRecord.FirebaseAuthException(INTERNAL_ERROR, "Failed to create new user");
  }

  void updateUser(UserRecord.UpdateRequest request, JsonFactory jsonFactory) throws ExportedUserRecord.FirebaseAuthException {
    GenericJson response = post(
        "/accounts:update", request.getProperties(jsonFactory), GenericJson.class);
    if (response == null || !request.getUid().equals(response.get("localId"))) {
      throw new ExportedUserRecord.FirebaseAuthException(INTERNAL_ERROR, "Failed to update user: " + request.getUid());
    }
  }

  void deleteUser(String uid) throws ExportedUserRecord.FirebaseAuthException {
    final Map<String, Object> payload = ImmutableMap.<String, Object>of("localId", uid);
    GenericJson response = post(
        "/accounts:delete", payload, GenericJson.class);
    if (response == null || !response.containsKey("kind")) {
      throw new ExportedUserRecord.FirebaseAuthException(INTERNAL_ERROR, "Failed to delete user: " + uid);
    }
  }



  UserImportResult importUsers(UserImportRequest request) throws ExportedUserRecord.FirebaseAuthException {
    checkNotNull(request);
    UploadAccountResponse response = post(
            "/accounts:batchCreate", request, UploadAccountResponse.class);
    if (response == null) {
      throw new ExportedUserRecord.FirebaseAuthException(INTERNAL_ERROR, "Failed to import users.");
    }
    return new UserImportResult(request.getUsersCount(), response);
  }

  String createSessionCookie(String idToken,
      SessionCookieOptions options) throws ExportedUserRecord.FirebaseAuthException {
    final Map<String, Object> payload = ImmutableMap.<String, Object>of(
        "idToken", idToken, "validDuration", options.getExpiresInSeconds());
    GenericJson response = post(":createSessionCookie", payload, GenericJson.class);
    if (response != null) {
      String cookie = (String) response.get("sessionCookie");
      if (!Strings.isNullOrEmpty(cookie)) {
        return cookie;
      }
    }
    throw new ExportedUserRecord.FirebaseAuthException(INTERNAL_ERROR, "Failed to create session cookie");
  }



  private <T> T post(String path, Object content, Class<T> clazz) throws ExportedUserRecord.FirebaseAuthException {
    checkArgument(!Strings.isNullOrEmpty(path), "path must not be null or empty");
    checkNotNull(content, "content must not be null for POST requests");
    GenericUrl url = new GenericUrl(baseUrl + path);
    return sendRequest("POST", url, content, clazz);
  }

  private <T> T sendRequest(
          String method, GenericUrl url,
          @Nullable Object content, Class<T> clazz) throws ExportedUserRecord.FirebaseAuthException {

    checkArgument(!Strings.isNullOrEmpty(method), "method must not be null or empty");
    checkNotNull(url, "url must not be null");
    checkNotNull(clazz, "response class must not be null");
    HttpResponse response = null;
    try {
      HttpContent httpContent = content != null ? new JsonHttpContent(jsonFactory, content) : null;
      HttpRequest request = requestFactory.buildRequest(method, url, httpContent);
      request.setParser(new JsonObjectParser(jsonFactory));
      request.getHeaders().set(CLIENT_VERSION_HEADER, clientVersion);
      request.setResponseInterceptor(interceptor);
      response = request.execute();
      return response.parseAs(clazz);
    } catch (HttpResponseException e) {
      // Server responded with an HTTP error
      handleHttpError(e);
      return null;
    } catch (IOException e) {
      // All other IO errors (Connection refused, reset, parse error etc.)
      throw new ExportedUserRecord.FirebaseAuthException(
          INTERNAL_ERROR, "Error while calling user management backend service", e);
    } finally {
      if (response != null) {
        try {
          response.disconnect();
        } catch (IOException ignored) {
          // Ignored
        }
      }
    }
  }

  private void handleHttpError(HttpResponseException e) throws ExportedUserRecord.FirebaseAuthException {
    try {
      HttpErrorResponse response = jsonFactory.fromString(e.getContent(), HttpErrorResponse.class);
      String code = ERROR_CODES.get(response.getErrorCode());
      if (code != null) {
        throw new ExportedUserRecord.FirebaseAuthException(code, "User management service responded with an error", e);
      }
    } catch (IOException ignored) {
      // Ignored
    }
    String msg = String.format(
        "Unexpected HTTP response with status: %d; body: %s", e.getStatusCode(), e.getContent());
    throw new ExportedUserRecord.FirebaseAuthException(INTERNAL_ERROR, msg, e);
  }

  static class UserImportRequest extends GenericJson {

    @Key("users")
    private final List<Map<String, Object>> users;

    UserImportRequest(List<ImportUserRecord> users, UserImportOptions options,
        JsonFactory jsonFactory) {
      checkArgument(users != null && !users.isEmpty(), "users must not be null or empty");
      checkArgument(users.size() <= FirebaseUserManager.MAX_IMPORT_USERS,
          "users list must not contain more than %s items", FirebaseUserManager.MAX_IMPORT_USERS);

      boolean hasPassword = false;
      ImmutableList.Builder<Map<String, Object>> usersBuilder = ImmutableList.builder();
      for (ImportUserRecord user : users) {
        if (user.hasPassword()) {
          hasPassword = true;
        }
        usersBuilder.add(user.getProperties(jsonFactory));
      }
      this.users = usersBuilder.build();

      if (hasPassword) {
        checkArgument(options != null && options.getHash() != null,
            "firebase.boilerplate.UserImportHash option is required when at least one user has a password. Provide "
                + "a firebase.boilerplate.UserImportHash via firebase.boilerplate.UserImportOptions.withHash().");
        this.putAll(options.getProperties());
      }
    }

    int getUsersCount() {
      return users.size();
    }
  }

  enum EmailLinkType {
    VERIFY_EMAIL,
    EMAIL_SIGNIN,
    PASSWORD_RESET,
  }
}

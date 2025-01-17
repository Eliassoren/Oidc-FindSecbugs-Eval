package firebase.boilerplate;/*
 * Copyright 2020 Google Inc.
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
import firebase.internal.NonNull;

/**
 * Used for looking up an account by phone number.
 *
 * @see {firebase.boilerplate.FirebaseAuth#getUsers}
 */
public final class PhoneIdentifier extends UserIdentifier {
  private final String phoneNumber;

  public PhoneIdentifier(@NonNull String phoneNumber) {
    UserRecord.checkPhoneNumber(phoneNumber);
    this.phoneNumber = phoneNumber;
  }

  @Override
  public String toString() {
    return "firebase.boilerplate.PhoneIdentifier(" + phoneNumber + ")";
  }

  @Override
  void populate(@NonNull GetAccountInfoRequest payload) {
    payload.addPhoneNumber(phoneNumber);
  }

  @Override
  boolean matches(@NonNull UserRecord userRecord) {
    return phoneNumber.equals(userRecord.getPhoneNumber());
  }
}

/*
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

package firebase.authinternal;

import com.google.api.client.util.Key;
import com.google.common.base.Strings;

/**
 * JSON data binding for JSON error messages sent by Google identity toolkit service.
 */
public class HttpErrorResponse {

  @Key("error")
  private Error error;

  public String getErrorCode() {
    if (error != null) {
      if (!Strings.isNullOrEmpty(error.getCode())) {
        return error.getCode();
      }
    }
    return "unknown";
  }

  public static class Error {

    @Key("message")
    private String code;

    public String getCode() {
      return code;
    }
  }

}

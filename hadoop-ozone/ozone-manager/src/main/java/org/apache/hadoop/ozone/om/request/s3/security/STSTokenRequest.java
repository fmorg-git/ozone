/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.ozone.om.request.s3.security;

import java.util.List;

/**
 * Request object for creating STS tokens.
 */
public class STSTokenRequest {
  private final String originalAccessKeyId;
  private final String roleArn;
  private final String roleSessionName;
  private final String tempAccessKeyId;
  private final int durationSeconds;
  private final List<String> permissions;

  public STSTokenRequest(String originalAccessKeyId,
                         String roleArn,
                         String roleSessionName,
                         String tempAccessKeyId,
                         int durationSeconds,
                         List<String> permissions) {
    this.originalAccessKeyId = originalAccessKeyId;
    this.roleArn = roleArn;
    this.roleSessionName = roleSessionName;
    this.tempAccessKeyId = tempAccessKeyId;
    this.durationSeconds = durationSeconds;
    this.permissions = permissions;
  }

  public String getOriginalAccessKeyId() {
    return originalAccessKeyId;
  }

  public String getRoleArn() {
    return roleArn;
  }

  public String getRoleSessionName() {
    return roleSessionName;
  }

  public String getTempAccessKeyId() {
    return tempAccessKeyId;
  }

  public int getDurationSeconds() {
    return durationSeconds;
  }

  public List<String> getPermissions() {
    return permissions;
  }
}

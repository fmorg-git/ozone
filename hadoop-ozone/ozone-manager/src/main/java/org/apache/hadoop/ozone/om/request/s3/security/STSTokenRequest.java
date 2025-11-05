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

/**
 * Request object for creating STS tokens.
 */
public class STSTokenRequest {
  private final String originalAccessKeyId;
  private final String roleArn;
  private final String tempAccessKeyId;
  private final int durationSeconds;
  private final String secretAccessKey;
  private final String sessionPolicy;

  public STSTokenRequest(String originalAccessKeyId,
                         String roleArn,
                         String tempAccessKeyId,
                         int durationSeconds,
                         String secretAccessKey,
                         String sessionPolicy) {
    this.originalAccessKeyId = originalAccessKeyId;
    this.roleArn = roleArn;
    this.tempAccessKeyId = tempAccessKeyId;
    this.durationSeconds = durationSeconds;
    this.secretAccessKey = secretAccessKey;
    this.sessionPolicy = sessionPolicy;
  }

  public String getOriginalAccessKeyId() {
    return originalAccessKeyId;
  }

  public String getRoleArn() {
    return roleArn;
  }

  public String getTempAccessKeyId() {
    return tempAccessKeyId;
  }

  public int getDurationSeconds() {
    return durationSeconds;
  }

  public String getSecretAccessKey() {
    return secretAccessKey;
  }

  public String getSessionPolicy() {
    return sessionPolicy;
  }
}

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

package org.apache.hadoop.ozone.security;

import java.io.IOException;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.request.s3.security.STSTokenRequest;
import org.apache.hadoop.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for managing STS binary tokens.
 * Creates base64 encoded binary tokens using STSTokenSecretManager.
 */
public final class STSTokenManager {
  private static final Logger LOG = LoggerFactory.getLogger(STSTokenManager.class);

  private STSTokenManager() { }

  /**
   * Creates a base64 encoded binary token for STS AssumeRole operation.
   * Uses the new STSTokenSecretManager for consistent token architecture.
   *
   * @param request Token creation request with role information
   * @param ozoneManager OzoneManager instance to access token signing services
   * @return Base64 encoded signed token string
   * @throws IOException if token creation fails
   */
  public static String createSTSToken(STSTokenRequest request,
                                      OzoneManager ozoneManager)
      throws IOException {
    
    if (!ozoneManager.isSecurityEnabled()) {
      throw new IOException("STS tokens require security to be enabled");
    }

    final STSTokenSecretManager stsSecretManager = ozoneManager.getSTSTokenSecretManager();
    if (stsSecretManager == null) {
      throw new IOException("STS token secret manager not initialized");
    }
    
    LOG.info("[FM] Creating STS token for originalAccessKeyId: {}, tempAccessKeyId: {}, " +
        "roleArn: {}, roleSessionName: {}, durationSeconds: {}",
        request.getOriginalAccessKeyId(),
        request.getTempAccessKeyId(),
        request.getRoleArn(),
        request.getRoleSessionName(),
        request.getDurationSeconds()
    );

    // Generate the token using the secret manager
    final Token<STSTokenIdentifier> token = stsSecretManager.generateToken(request);

    // Return standard Hadoop token encoding
    return token.encodeToUrlString();
  }
}

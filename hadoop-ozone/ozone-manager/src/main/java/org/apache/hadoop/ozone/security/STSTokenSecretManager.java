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
import java.time.Instant;
import org.apache.hadoop.hdds.annotation.InterfaceAudience;
import org.apache.hadoop.hdds.annotation.InterfaceStability;
import org.apache.hadoop.hdds.security.symmetric.SecretKeySignerClient;
import org.apache.hadoop.hdds.security.token.ShortLivedTokenSecretManager;
import org.apache.hadoop.ozone.om.request.s3.security.STSTokenRequest;
import org.apache.hadoop.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Secret manager for STS (Security Token Service) tokens.
 * This class extends ShortLivedTokenSecretManager to provide
 * STS token creation using the standard Ozone token architecture.
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
public class STSTokenSecretManager extends ShortLivedTokenSecretManager<STSTokenIdentifier> {
  
  private static final Logger LOG = LoggerFactory.getLogger(STSTokenSecretManager.class);

  private static final long TOKEN_MAX_LIFETIME = 43200 * 1000L; // 12 hours in milliseconds

  /**
   * Create a new STS token secret manager.
   *
   * @param secretKeyClient client for accessing secret keys from SCM
   */
  public STSTokenSecretManager(SecretKeySignerClient secretKeyClient) {
    super(TOKEN_MAX_LIFETIME, secretKeyClient);
  }

  /**
   * Create a new STS token identifier.
   *
   * @param tempAccessKeyId     the temporary access key ID
   * @param originalAccessKeyId the original long-lived access key ID
   * @param roleArn             the ARN of the assumed role
   * @param roleSessionName     the session name for the role
   * @param durationSeconds     how long the token should be valid for
   * @return new STSTokenIdentifier
   */
  public STSTokenIdentifier createIdentifier(String tempAccessKeyId,
                                             String originalAccessKeyId,
                                             String roleArn,
                                             String roleSessionName,
                                             int durationSeconds) {
    final Instant expiration = Instant.now().plusSeconds(durationSeconds);
    return new STSTokenIdentifier(tempAccessKeyId,
        originalAccessKeyId,
        roleArn,
        roleSessionName,
        expiration
    );
  }

  /**
   * Generate an STS token for the specified parameters.
   *
   * @param tempAccessKeyId     the temporary access key ID
   * @param originalAccessKeyId the original long-lived access key ID
   * @param roleArn             the ARN of the assumed role
   * @param roleSessionName     the session name for the role
   * @param durationSeconds     how long the token should be valid for
   * @return signed STS token
   */
  public Token<STSTokenIdentifier> generateToken(String tempAccessKeyId,
                                                 String originalAccessKeyId,
                                                 String roleArn,
                                                 String roleSessionName,
                                                 int durationSeconds) {

    final STSTokenIdentifier identifier = createIdentifier(tempAccessKeyId,
        originalAccessKeyId,
        roleArn,
        roleSessionName,
        durationSeconds
    );
    
    LOG.info("[FM] Generated STS token -> tempAccessKeyId: {}, originalAccessKeyId: {}, " +
          "roleArn: {}, roleSessionName: {}, expiration: {}",
          tempAccessKeyId, originalAccessKeyId, roleArn, roleSessionName, 
          identifier.getExpiry());
    
    return generateToken(identifier);
  }

  /**
   * Generate an STS token from a request object.
   * This method provides compatibility with existing STSTokenManager usage.
   *
   * @param request the STS token request
   * @return signed STS token
   */
  public Token<STSTokenIdentifier> generateToken(STSTokenRequest request) {
    return generateToken(
        request.getTempAccessKeyId(),
        request.getOriginalAccessKeyId(),
        request.getRoleArn(),
        request.getRoleSessionName(),
        request.getDurationSeconds()
    );
  }

  /**
   * Create an STS token and return it as an encoded string.
   * This method maintains compatibility with the existing STSTokenManager interface.
   *
   * @param request the STS token request
   * @return base64 encoded token string
   */
  public String createSTSTokenString(STSTokenRequest request) throws IOException {
    Token<STSTokenIdentifier> token = generateToken(request);
    return token.encodeToUrlString();
  }
}

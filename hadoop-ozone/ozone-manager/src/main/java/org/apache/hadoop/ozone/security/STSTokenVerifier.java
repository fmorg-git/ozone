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
import org.apache.hadoop.hdds.security.symmetric.ManagedSecretKey;
import org.apache.hadoop.hdds.security.symmetric.SecretKeyVerifierClient;
import org.apache.hadoop.security.token.SecretManager;
import org.apache.hadoop.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifier for STS tokens using the ShortLivedTokenVerifier architecture.
 * This class provides stateless verification of STS tokens using the
 * shared secret key infrastructure.
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
public class STSTokenVerifier {
  
  private static final Logger LOG = LoggerFactory.getLogger(STSTokenVerifier.class);

  private final SecretKeyVerifierClient secretKeyClient;

  public STSTokenVerifier(SecretKeyVerifierClient secretKeyClient) {
    this.secretKeyClient = secretKeyClient;
  }

  /**
   * Verify an STS token.
   *
   * @param token the token to verify
   * @throws SecretManager.InvalidToken if the token is invalid
   */
  public void verifyToken(Token<STSTokenIdentifier> token)
      throws SecretManager.InvalidToken {
    
    STSTokenIdentifier tokenId;
    try {
      tokenId = STSTokenIdentifier.readProtoBuf(token.getIdentifier());
    } catch (IOException ex) {
      throw new SecretManager.InvalidToken("Failed to decode STS token: " + ex.getMessage());
    }

    // Check expiration
    if (tokenId.isExpired(Instant.now())) {
      throw new SecretManager.InvalidToken("STS token expired at " + tokenId.getExpiry());
    }

    // Verify token signature
    verifyTokenPassword(tokenId, token.getPassword());

    LOG.info("[FM] Token signature successfully verified");

  }

  /**
   * Verify an encoded STS token string.
   *
   * @param encodedToken the base64 encoded token string
   * @throws SecretManager.InvalidToken if the token is invalid
   */
  public void verifyToken(String encodedToken)
      throws SecretManager.InvalidToken {
    
    Token<STSTokenIdentifier> token = new Token<>();
    try {
      token.decodeFromUrlString(encodedToken);
    } catch (IOException e) {
      throw new SecretManager.InvalidToken("Failed to decode STS token string: " +
          e.getMessage()
      );
    }

    verifyToken(token);
  }

  private void verifyTokenPassword(STSTokenIdentifier tokenId, byte[] password)
      throws SecretManager.InvalidToken {

    if (tokenId.getSecretKeyId() == null) {
      throw new SecretManager.InvalidToken("STS token missing secret key ID");
    }

    ManagedSecretKey secretKey;
    try {
      secretKey = secretKeyClient.getSecretKey(tokenId.getSecretKeyId());
    } catch (Exception e) {
      throw new SecretManager.InvalidToken("Failed to retrieve secret key: " + e.getMessage());
    }

    if (secretKey == null) {
      throw new SecretManager.InvalidToken("Secret key not found for STS token: " + 
          tokenId.getSecretKeyId());
    }

    if (secretKey.isExpired()) {
      throw new SecretManager.InvalidToken("Token cannot be verified due to " +
          "expired secret key " + tokenId.getSecretKeyId());
    }

    if (!secretKey.isValidSignature(tokenId, password)) {
      throw new SecretManager.InvalidToken("Invalid STS token signature");
    }
  }
}

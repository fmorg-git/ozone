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
import java.util.UUID;
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
public class  STSTokenVerifier {
  
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
  public void verifyToken(Token<STSTokenIdentifier> token) throws SecretManager.InvalidToken {


    if (!token.getKind().equals(STSTokenIdentifier.KIND_NAME)) {
      throw new SecretManager.InvalidToken("Invalid token");
    }

    if (!STSTokenIdentifier.STS_SERVICE.equals(token.getService().toString())) {
      throw new SecretManager.InvalidToken("Invalid token service");
    }

    final STSTokenIdentifier tokenId;
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
   * @param encodedToken                the base64 encoded token string
   * @throws SecretManager.InvalidToken if the token is invalid
   */
  public void verifyToken(String encodedToken) throws SecretManager.InvalidToken {
    
    final Token<STSTokenIdentifier> token = decodeTokenFromString(encodedToken);
    verifyToken(token);
  }

  /**
   * Decode token without validation nor decryption - useful for inspection only.
   *
   * @param encodedToken    the base64 encoded token string
   * @return                the decoded token identifier (with secretAccessKey still encrypted)
   * @throws SecretManager.InvalidToken if the token cannot be decoded
   */
  public static STSTokenIdentifier decodeTokenIntoTokenIdentifier(String encodedToken)
      throws SecretManager.InvalidToken {
    final Token<STSTokenIdentifier> token = decodeTokenFromString(encodedToken);
    try {
      return STSTokenIdentifier.readProtoBuf(token.getIdentifier());
    } catch (IOException ex) {
      throw new SecretManager.InvalidToken("Failed to decode token: " + ex.getMessage());
    }
  }

  /**
   * Extract original access key ID from token without validation.
   *
   * @param encodedToken      the base64 encoded token string
   * @return                  the original access key id
   * @throws SecretManager.InvalidToken if the token cannot be decoded
   */
  public static String extractOriginalAccessKeyId(String encodedToken) throws SecretManager.InvalidToken {
    return decodeTokenIntoTokenIdentifier(encodedToken).getOriginalAccessKeyId();
  }

  /**
   * Decode and decrypt token.  Requires secret key access for decryption.
   *
   * @param encodedToken      the base64 encoded token string
   * @return                  the decoded and decrypted token identifier
   * @throws SecretManager.InvalidToken if the token is invalid or cannot be decrypted
   */
  public STSTokenIdentifier decodeAndDecryptTokenIntoTokenIdentifier(String encodedToken)
      throws SecretManager.InvalidToken {
    final Token<STSTokenIdentifier> token = decodeTokenFromString(encodedToken);
    
    try {
      final STSTokenIdentifier tokenId = STSTokenIdentifier.readProtoBuf(token.getIdentifier());
      final ManagedSecretKey secretKey = getValidatedSecretKey(tokenId.getSecretKeyId());
      
      return STSTokenIdentifier.readProtoBuf(token.getIdentifier(), 
          secretKey.getSecretKey().getEncoded());
    } catch (IOException ex) {
      throw new SecretManager.InvalidToken("Failed to decrypt STS token: " + ex.getMessage());
    }
  }

  private static Token<STSTokenIdentifier> decodeTokenFromString(String encodedToken) 
      throws SecretManager.InvalidToken {
    final Token<STSTokenIdentifier> token = new Token<>();
    try {
      token.decodeFromUrlString(encodedToken);
      return token;
    } catch (IOException e) {
      throw new SecretManager.InvalidToken("Failed to decode STS token string: " + 
          e.getMessage());
    }
  }

  private void verifyTokenPassword(STSTokenIdentifier tokenId, byte[] password)
      throws SecretManager.InvalidToken {

    final ManagedSecretKey secretKey = getValidatedSecretKey(tokenId.getSecretKeyId());

    if (!secretKey.isValidSignature(tokenId, password)) {
      throw new SecretManager.InvalidToken("Invalid STS token signature");
    }
  }

  private ManagedSecretKey getValidatedSecretKey(UUID secretKeyId)
      throws SecretManager.InvalidToken {
    if (secretKeyId == null) {
      throw new SecretManager.InvalidToken("STS token missing secret key ID");
    }

    final ManagedSecretKey secretKey;
    try {
      secretKey = secretKeyClient.getSecretKey(secretKeyId);
    } catch (Exception e) {
      throw new SecretManager.InvalidToken("Failed to retrieve secret key: " + e.getMessage());
    }

    if (secretKey == null) {
      throw new SecretManager.InvalidToken("Secret key not found for STS token: " + secretKeyId);
    }

    if (secretKey.isExpired()) {
      throw new SecretManager.InvalidToken("Token cannot be verified due to " +
          "expired secret key " + secretKeyId);
    }

    return secretKey;
  }
}


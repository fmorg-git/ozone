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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.hadoop.hdds.security.symmetric.ManagedSecretKey;
import org.apache.hadoop.hdds.security.symmetric.SecretKeySignerClient;
import org.apache.hadoop.ozone.om.request.s3.security.STSTokenRequest;
import org.apache.hadoop.security.token.Token;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test for STSTokenSecretManager.
 */
public class TestSTSTokenSecretManager {

  private STSTokenSecretManager secretManager;
  private SecretKeySignerClient mockSecretKeyClient;

  @BeforeEach
  public void setUp() throws Exception {
    mockSecretKeyClient = mock(SecretKeySignerClient.class);
    final ManagedSecretKey mockSecretKey = mock(ManagedSecretKey.class);
    
    // Create a real SecretKey for testing
    final KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
    keyGenerator.init(256);
    final SecretKey secretKey = keyGenerator.generateKey();
    
    final UUID keyId = UUID.randomUUID();
    when(mockSecretKey.getId()).thenReturn(keyId);
    when(mockSecretKey.getSecretKey()).thenReturn(secretKey);
    when(mockSecretKey.sign(any(STSTokenIdentifier.class)))
        .thenReturn("mock-signature".getBytes(StandardCharsets.UTF_8));
    when(mockSecretKeyClient.getCurrentSecretKey()).thenReturn(mockSecretKey);

    secretManager = new STSTokenSecretManager(mockSecretKeyClient);
  }

  @Test
  public void testCreateIdentifier() {
    final String tempAccessKeyId = "temp-access-key";
    final String originalAccessKeyId = "original-access-key";
    final String roleArn = "arn:aws:iam::123456789012:role/test-role";
    final int durationSeconds = 4000;
    final String secretAccessKey = "test-secret-access-key";
    final String sessionPolicy = "test-session-policy";

    final STSTokenIdentifier identifier = secretManager.createIdentifier(tempAccessKeyId,
        originalAccessKeyId,
        roleArn,
        durationSeconds,
        secretAccessKey,
        sessionPolicy
    );

    assertNotNull(identifier);
    assertEquals(tempAccessKeyId, identifier.getTempAccessKeyId());
    assertEquals(originalAccessKeyId, identifier.getOriginalAccessKeyId());
    assertEquals(roleArn, identifier.getRoleArn());
    assertFalse(identifier.isExpired(Instant.now()));
    assertEquals(secretAccessKey, identifier.getSecretAccessKey());
  }

  @Test
  public void testGenerateToken() {
    final String tempAccessKeyId = "temp-access-key";
    final String originalAccessKeyId = "original-access-key";
    final String roleArn = "arn:aws:iam::123456789012:role/test-role";
    final int durationSeconds = 4000;
    final String secretAccessKey = "test-secret-access-key";
    final String sessionPolicy = "test-session-policy";

    final Token<STSTokenIdentifier> token = secretManager.generateToken(tempAccessKeyId,
        originalAccessKeyId,
        roleArn,
        durationSeconds,
        secretAccessKey,
        sessionPolicy
    );

    assertNotNull(token);
    assertNotNull(token.getIdentifier());
    assertNotNull(token.getPassword());
    assertEquals("STSToken", token.getKind().toString());
  }

  @Test
  public void testGenerateTokenFromRequest() throws IOException {
    final STSTokenRequest request = new STSTokenRequest(
            "original-access-key",
            "arn:aws:iam::123456789012:role/test-role",
        "temp-access-key",
            3600,
        "test-secret-access-key",
        "test-session-policy");

    final Token<STSTokenIdentifier> token = secretManager.generateToken(request);

    assertNotNull(token);
    final String tokenString = secretManager.createSTSTokenString(request);
    assertNotNull(tokenString);
    assertFalse(tokenString.isEmpty());
  }

  @Test
  public void testTokenExpiration() throws InterruptedException {
    // Create manager with very short lifetime (1 second)
    final STSTokenSecretManager shortLivedManager = new STSTokenSecretManager(mockSecretKeyClient);

    final STSTokenIdentifier identifier = shortLivedManager.createIdentifier(
        "tempAccessKeyId",
        "originalAccessKeyId",
        "roleArn",
        1,
        "test-secret-access-key",
        "test-session-policy"
    );

    // Should not be expired immediately
    assertFalse(identifier.isExpired(Instant.now()));
    
    // Wait a bit and check again
    Thread.sleep(1300L);
    assertTrue(identifier.isExpired(Instant.now()));
  }
}

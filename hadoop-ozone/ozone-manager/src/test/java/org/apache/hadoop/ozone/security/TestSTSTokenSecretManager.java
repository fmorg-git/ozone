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
import java.util.Collections;
import java.util.UUID;
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
  public void setUp() {
    mockSecretKeyClient = mock(SecretKeySignerClient.class);
    final ManagedSecretKey mockSecretKey = mock(ManagedSecretKey.class);
    
    UUID keyId = UUID.randomUUID();
    when(mockSecretKey.getId()).thenReturn(keyId);
    when(mockSecretKey.sign(any(STSTokenIdentifier.class))).thenReturn("mock-signature".getBytes(StandardCharsets.UTF_8));
    when(mockSecretKeyClient.getCurrentSecretKey()).thenReturn(mockSecretKey);
    
    // 1 hour lifetime
    secretManager = new STSTokenSecretManager(mockSecretKeyClient);
  }

  @Test
  public void testCreateIdentifier() {
    String tempAccessKeyId = "temp-access-key";
    String originalAccessKeyId = "original-access-key";
    String roleArn = "arn:aws:iam::123456789012:role/test-role";
    String roleSessionName = "test-session";
    final int durationSeconds = 4000;

    STSTokenIdentifier identifier = secretManager.createIdentifier(tempAccessKeyId,
        originalAccessKeyId,
        roleArn,
        roleSessionName,
        durationSeconds
    );

    assertNotNull(identifier);
    assertEquals(tempAccessKeyId, identifier.getTempAccessKeyId());
    assertEquals(originalAccessKeyId, identifier.getOriginalAccessKeyId());
    assertEquals(roleArn, identifier.getRoleArn());
    assertEquals(roleSessionName, identifier.getRoleSessionName());
    assertFalse(identifier.isExpired(Instant.now()));
  }

  @Test
  public void testGenerateToken() {
    String tempAccessKeyId = "temp-access-key";
    String originalAccessKeyId = "original-access-key";
    String roleArn = "arn:aws:iam::123456789012:role/test-role";
    String roleSessionName = "test-session";
    int durationSeconds = 4000;

    Token<STSTokenIdentifier> token = secretManager.generateToken(tempAccessKeyId,
        originalAccessKeyId,
        roleArn,
        roleSessionName,
        durationSeconds
    );

    assertNotNull(token);
    assertNotNull(token.getIdentifier());
    assertNotNull(token.getPassword());
    assertEquals("STSToken", token.getKind().toString());
  }

  @Test
  public void testGenerateTokenFromRequest() throws IOException {
    STSTokenRequest request = new STSTokenRequest(
            "original-access-key",
            "arn:aws:iam::123456789012:role/test-role",
            "test-session",
            "temp-access-key",
            3600,
              Collections.singletonList("s3:GetObject")
        );

    Token<STSTokenIdentifier> token = secretManager.generateToken(request);

    assertNotNull(token);
    String tokenString = secretManager.createSTSTokenString(request);
    assertNotNull(tokenString);
    assertFalse(tokenString.isEmpty());
  }

  @Test
  public void testTokenExpiration() throws InterruptedException {
    // Create manager with very short lifetime (1 second)
    STSTokenSecretManager shortLivedManager = new STSTokenSecretManager(mockSecretKeyClient);

    STSTokenIdentifier identifier = shortLivedManager.createIdentifier(
        "tempAccessKeyId",
        "originalAccessKeyId",
        "roleArn",
        "roleSessionName",
        1
    );

    // Should not be expired immediately
    assertFalse(identifier.isExpired(Instant.now()));
    
    // Wait a bit and check again
    Thread.sleep(1300L);
    assertTrue(identifier.isExpired(Instant.now()));
  }
}

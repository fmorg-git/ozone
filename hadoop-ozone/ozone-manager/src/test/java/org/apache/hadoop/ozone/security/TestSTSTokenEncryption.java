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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.hadoop.ozone.security.STSTokenEncryption.STSTokenEncryptionException;
import org.junit.jupiter.api.Test;

/**
 * Test class for STS token encryption functionality.
 */
public class TestSTSTokenEncryption {

  @Test
  public void testEncryptDecryptRoundTrip() throws Exception {
    // Generate a test secret key (simulating ManagedSecretKey)
    final KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
    keyGen.init(256);
    final SecretKey testKey = keyGen.generateKey();
    final byte[] keyBytes = testKey.getEncoded();

    final String originalSecret = "mySecretAccessKey123456";
    
    // Encrypt the secret
    final String encrypted = STSTokenEncryption.encrypt(originalSecret, keyBytes);
    assertNotNull(encrypted);
    assertNotEquals(originalSecret, encrypted);
    
    // Decrypt the secret
    final String decrypted = STSTokenEncryption.decrypt(encrypted, keyBytes);
    assertEquals(originalSecret, decrypted);
  }
  
  @Test
  public void testSTSTokenIdentifierEncryption() throws Exception {
    // Generate a test secret key
    final KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
    keyGen.init(256);
    final SecretKey testKey = keyGen.generateKey();
    final byte[] keyBytes = testKey.getEncoded();

    final String tempAccessKeyId = "ASIA123TEMPKEY";
    final String originalAccessKeyId = "AKIA123ORIGINAL";
    final String roleArn = "arn:aws:iam::123456789012:role/TestRole";
    final String secretAccessKey = "mySecretAccessKey123456";
    // Use millisecond precision to match serialization format
    final Instant expiry = Instant.ofEpochMilli(Instant.now().plusSeconds(3600).toEpochMilli());
    
    // Create token identifier with encryption
    final STSTokenIdentifier tokenId = new STSTokenIdentifier(
        tempAccessKeyId,
        originalAccessKeyId, 
        roleArn,
        expiry,
        secretAccessKey,
        keyBytes
    );
    
    // Convert to protobuf (should encrypt sensitive fields)
    final byte[] protobufBytes = tokenId.toProtoBuf().toByteArray();
    
    // Create new token identifier from protobuf with decryption key
    final STSTokenIdentifier decodedTokenId = STSTokenIdentifier.readProtoBuf(protobufBytes, keyBytes);
    
    // Verify all fields are correctly decrypted
    assertEquals(tempAccessKeyId, decodedTokenId.getTempAccessKeyId());
    assertEquals(originalAccessKeyId, decodedTokenId.getOriginalAccessKeyId());
    assertEquals(roleArn, decodedTokenId.getRoleArn());
    assertEquals(secretAccessKey, decodedTokenId.getSecretAccessKey());
    assertEquals(expiry, decodedTokenId.getExpiry());
  }
  
  @Test
  public void testDecryptionWithWrongKey() throws Exception {
    // Generate two different keys
    final KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
    keyGen.init(256);
    final SecretKey key1 = keyGen.generateKey();
    final SecretKey key2 = keyGen.generateKey();

    final String originalSecret = "mySecretAccessKey123456";
    
    // Encrypt with key1
    final String encrypted = STSTokenEncryption.encrypt(originalSecret, key1.getEncoded());

    // Try to decrypt with key2 - should fail
    assertThrows(STSTokenEncryptionException.class, () ->
        STSTokenEncryption.decrypt(encrypted, key2.getEncoded()));
  }
}

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

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.hadoop.hdds.annotation.InterfaceAudience;
import org.apache.hadoop.hdds.annotation.InterfaceStability;

/**
 * Utility class for encrypting and decrypting sensitive data in STS tokens.
 * Uses HKDF to derive an AES encryption key from the SCM ManagedSecretKey,
 * then uses AES-GCM for authenticated encryption.
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
public final class STSTokenEncryption {
  
  // HKDF parameters
  private static final String HKDF_HMAC_ALGORITHM = "HmacSHA256";
  private static final byte[] HKDF_INFO = "STS-TOKEN-ENCRYPTION".getBytes(StandardCharsets.UTF_8);
  private static final byte[] HKDF_SALT = "OZONE-STS-SALT-V1".getBytes(StandardCharsets.UTF_8);
  private static final int AES_KEY_LENGTH = 32; // 256 bits
  
  // AES-GCM parameters
  private static final String AES_ALGORITHM = "AES";
  private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int GCM_IV_LENGTH = 12; // 96 bits
  private static final int GCM_TAG_LENGTH = 16; // 128 bits
  
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  
  private STSTokenEncryption() {

  }
  
  /**
   * Encrypt sensitive data using AES-GCM with a key derived from the secret key via HKDF.
   * 
   * @param plaintext         the sensitive data to encrypt
   * @param secretKeyBytes    the secret key bytes from ManagedSecretKey
   * @return base64-encoded encrypted data with IV prepended
   * @throws STSTokenEncryptionException if encryption fails
   */
  public static String encrypt(String plaintext, byte[] secretKeyBytes) throws STSTokenEncryptionException {
    // Don't encrypt null/empty strings
    if (plaintext == null || plaintext.isEmpty()) {
      return plaintext;
    }
    
    try {
      // Derive AES key using HKDF
      final byte[] aesKey = hkdfExpand(hkdfExtract(secretKeyBytes));
      
      // Initialize AES-GCM cipher
      final Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
      
      // Generate random IV
      final byte[] iv = new byte[GCM_IV_LENGTH];
      SECURE_RANDOM.nextBytes(iv);

      final GCMParameterSpec gcmParams = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
      final SecretKeySpec keySpec = new SecretKeySpec(aesKey, AES_ALGORITHM);
      
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParams);
      
      // Encrypt the plaintext
      final byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
      
      // Prepend IV to ciphertext and encode as base64
      final byte[] result = new byte[iv.length + ciphertext.length];
      System.arraycopy(iv, 0, result, 0, iv.length);
      System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
      
      return Base64.getEncoder().encodeToString(result);
      
    } catch (Exception e) {
      throw new STSTokenEncryptionException("Failed to encrypt sensitive data", e);
    }
  }
  
  /**
   * Decrypt sensitive data using AES-GCM with a key derived from the secret key via HKDF.
   * 
   * @param encryptedData         base64-encoded encrypted data with IV prepended
   * @param secretKeyBytes        the secret key bytes from ManagedSecretKey
   * @return decrypted plaintext
   * @throws STSTokenEncryptionException if decryption fails
   */
  public static String decrypt(String encryptedData,
                               byte[] secretKeyBytes) throws STSTokenEncryptionException {
    // Don't decrypt null/empty strings
    if (encryptedData == null || encryptedData.isEmpty()) {
      return encryptedData;
    }
    
    try {
      // Decode base64
      final byte[] data = Base64.getDecoder().decode(encryptedData);
      
      if (data.length < GCM_IV_LENGTH) {
        throw new STSTokenEncryptionException("Invalid encrypted data: too short");
      }
      
      // Extract IV and ciphertext
      final byte[] iv = new byte[GCM_IV_LENGTH];
      final byte[] ciphertext = new byte[data.length - GCM_IV_LENGTH];
      System.arraycopy(data, 0, iv, 0, GCM_IV_LENGTH);
      System.arraycopy(data, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
      
      // Derive AES key using HKDF
      final byte[] aesKey = hkdfExpand(hkdfExtract(secretKeyBytes));
      
      // Initialize AES-GCM cipher
      final Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
      final GCMParameterSpec gcmParams = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
      final SecretKeySpec keySpec = new SecretKeySpec(aesKey, AES_ALGORITHM);
      
      cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParams);
      
      // Decrypt the ciphertext
      final byte[] plaintext = cipher.doFinal(ciphertext);
      
      return new String(plaintext, StandardCharsets.UTF_8);
      
    } catch (Exception e) {
      throw new STSTokenEncryptionException("Failed to decrypt sensitive data", e);
    }
  }
  
  /**
   * HKDF Extract step: PRK = HMAC-Hash(salt, IKM).
   *
   * @param ikm the input keying material (master key)
   * @return the pseudo-random key (PRK)
   */
  private static byte[] hkdfExtract(byte[] ikm) throws NoSuchAlgorithmException, InvalidKeyException {
    final Mac mac = Mac.getInstance(HKDF_HMAC_ALGORITHM);
    mac.init(new SecretKeySpec(STSTokenEncryption.HKDF_SALT, HKDF_HMAC_ALGORITHM));
    return mac.doFinal(ikm);
  }
  
  /**
   * HKDF Expand step: OKM = HMAC-Hash(PRK, info | counter).
   *
   * @param prk the pseudo-random key from extract step
   * @return the output keying material (OKM)
   */
  private static byte[] hkdfExpand(byte[] prk) throws NoSuchAlgorithmException, InvalidKeyException {
    final Mac mac = Mac.getInstance(HKDF_HMAC_ALGORITHM);
    mac.init(new SecretKeySpec(prk, HKDF_HMAC_ALGORITHM));

    final int hashLength = mac.getMacLength();
    final int iterations = (int) Math.ceil((double) STSTokenEncryption.AES_KEY_LENGTH / hashLength);

    final byte[] result = new byte[STSTokenEncryption.AES_KEY_LENGTH];
    byte[] previous = new byte[0];
    
    for (int i = 1; i <= iterations; i++) {
      mac.reset();
      mac.update(previous);
      mac.update(STSTokenEncryption.HKDF_INFO);
      mac.update((byte) i);
      
      previous = mac.doFinal();
      
      int copyLength = Math.min(previous.length, STSTokenEncryption.AES_KEY_LENGTH - (i - 1) * hashLength);
      System.arraycopy(previous, 0, result, (i - 1) * hashLength, copyLength);
    }
    
    return result;
  }
  
  /**
   * Exception thrown when encryption/decryption operations fail.
   */
  public static class STSTokenEncryptionException extends Exception {
    public STSTokenEncryptionException(String message) {
      super(message);
    }
    
    public STSTokenEncryptionException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}

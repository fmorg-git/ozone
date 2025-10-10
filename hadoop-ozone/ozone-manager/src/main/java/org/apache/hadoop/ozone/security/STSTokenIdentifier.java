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

import com.google.common.base.Preconditions;
import java.io.ByteArrayInputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutput;
import java.io.IOException;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import org.apache.hadoop.hdds.annotation.InterfaceAudience;
import org.apache.hadoop.hdds.annotation.InterfaceStability;
import org.apache.hadoop.hdds.security.token.ShortLivedTokenIdentifier;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMTokenProto;
import org.apache.hadoop.ozone.security.STSTokenEncryption.STSTokenEncryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Token identifier for STS (Security Token Service) tokens.
 * This class extends ShortLivedTokenIdentifier to align STS tokens
 * with the standard Ozone token architecture.
 * Sensitive fields are encrypted using AES-GCM with keys derived via HKDF.
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
public class STSTokenIdentifier extends ShortLivedTokenIdentifier {

  private static final Logger LOG = LoggerFactory.getLogger(STSTokenIdentifier.class);

  public static final Text KIND_NAME = new Text("STSToken");
  
  // STS-specific fields
  private String roleArn;
  private String originalAccessKeyId;
  private String secretAccessKey;
  
  // Encryption key derived from ManagedSecretKey for this token
  private transient byte[] encryptionKey;

  // Cache the encrypted representation of sensitive fields to make
  // serialization idempotent across multiple calls within the same instance.
  // ShortLivedTokenSecretManager makes two serialization calls in generateToken() method:
  // 1) in the call to secretKey.sign() in the createPassword() method
  // 2) in the call to tokenIdentifier.getBytes() for the Token constructor
  // These two calls would produce different encrypted values because of the random initialization vector,
  // so we cache for idempotency.
  private transient String cachedEncryptedSecretAccessKey;
  
  // Service name for STS tokens
  public static final String STS_SERVICE = "STS";

  /**
   * Create an empty STS token identifier.
   */
  private STSTokenIdentifier() {
    super();
  }
  
  /**
   * Create a new STS token identifier with encryption support.
   *
   * @param tempAccessKeyId     the temporary access key ID (owner)
   * @param originalAccessKeyId the original long-lived access key ID that created this token
   * @param roleArn             the ARN of the assumed role
   * @param expiry              the token expiration time
   * @param secretAccessKey     the secret access key associated with the temporary access key ID
   * @param encryptionKey       the key bytes for encrypting sensitive fields
   */
  public STSTokenIdentifier(String tempAccessKeyId,
                            String originalAccessKeyId,
                            String roleArn,
                            Instant expiry,
                            String secretAccessKey,
                            byte[] encryptionKey) {
    super(tempAccessKeyId, expiry);
    this.originalAccessKeyId = originalAccessKeyId;
    this.roleArn = roleArn;
    this.secretAccessKey = secretAccessKey;
    this.encryptionKey = encryptionKey != null ? encryptionKey.clone() : null;
  }

  @Override
  public Text getKind() {
    return KIND_NAME;
  }

  @Override
  public String getService() {
    return STS_SERVICE;
  }

  @Override
  public void readFromByteArray(byte[] bytes) throws IOException {
    final DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
    readFields(in);
  }

  @Override
  public void write(DataOutput out) throws IOException {
    out.write(toProtoBuf().toByteArray());
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    final OMTokenProto token = OMTokenProto.parseFrom((DataInputStream) in);
    fromProtoBuf(token);
  }

  /**
   * Convert this identifier to protobuf format.
   * Sensitive fields are encrypted before serialization.
   */
  public OMTokenProto toProtoBuf() {
    final OMTokenProto.Builder builder = OMTokenProto.newBuilder()
        .setType(OMTokenProto.Type.S3_STS_TOKEN)
        .setMaxDate(getExpiry().toEpochMilli())
        .setOwner(getOwnerId() != null ? getOwnerId() : "")
        .setAccessKeyId(getOwnerId() != null ? getOwnerId() : "")
        .setOriginalAccessKeyId(originalAccessKeyId)
        .setRoleArn(roleArn != null ? roleArn : "")
        .setSecretAccessKey(getOrEncryptSecretAccessKey());

    if (getSecretKeyId() != null) {
      builder.setSecretKeyId(getSecretKeyId().toString());
    }

    return builder.build();
  }

  /**
   * Initialize this identifier from protobuf.
   * Sensitive fields are decrypted after deserialization.
   */
  public void fromProtoBuf(OMTokenProto token) {
    Preconditions.checkArgument(token.getType() == OMTokenProto.Type.S3_STS_TOKEN,
        "Invalid token type for STSTokenIdentifier");
    
    setOwnerId(token.getOwner());
    setExpiry(Instant.ofEpochMilli(token.getMaxDate()));
    
    if (token.hasOriginalAccessKeyId()) {
      this.originalAccessKeyId = token.getOriginalAccessKeyId();
    }
    if (token.hasRoleArn()) {
      this.roleArn = token.getRoleArn();
    }
    if (token.hasSecretAccessKey()) {
      // Preserve the exact ciphertext we received so subsequent serializations
      // reproduce identical bytes without re-encrypting with a new IV.
      this.cachedEncryptedSecretAccessKey = token.getSecretAccessKey();
      this.secretAccessKey = decryptSensitiveField(token.getSecretAccessKey());
    } else {
      this.cachedEncryptedSecretAccessKey = null;
    }
    
    if (token.hasSecretKeyId()) {
      try {
        setSecretKeyId(UUID.fromString(token.getSecretKeyId()));
      } catch (IllegalArgumentException e) {
        // Handle invalid UUID format gracefully
        throw new IllegalArgumentException("Invalid secretKeyId format in STS token: " + 
            token.getSecretKeyId(), e);
      }
    }
  }

  /**
   * Create STSTokenIdentifier from protobuf bytes.
   */
  public static STSTokenIdentifier readProtoBuf(byte[] identifier) throws IOException {
    final DataInputStream in = new DataInputStream(new ByteArrayInputStream(identifier));
    final OMTokenProto token = OMTokenProto.parseFrom(in);
    final STSTokenIdentifier stsIdentifier = new STSTokenIdentifier();
    stsIdentifier.fromProtoBuf(token);
    return stsIdentifier;
  }
  
  /**
   * Create STSTokenIdentifier from protobuf bytes with encryption key.
   */
  public static STSTokenIdentifier readProtoBuf(byte[] identifier, byte[] encryptionKey) throws IOException {
    final DataInputStream in = new DataInputStream(new ByteArrayInputStream(identifier));
    final OMTokenProto token = OMTokenProto.parseFrom(in);
    final STSTokenIdentifier stsIdentifier = new STSTokenIdentifier();
    stsIdentifier.encryptionKey = encryptionKey;
    stsIdentifier.fromProtoBuf(token);
    return stsIdentifier;
  }
  
  /**
   * Encrypt a sensitive field using the configured encryption key.
   */
  private String encryptSensitiveField(String value) {
    if (value == null || value.isEmpty() || encryptionKey == null) {
      return value != null ? value : "";
    }
    
    try {
      return STSTokenEncryption.encrypt(value, encryptionKey);
    } catch (STSTokenEncryptionException e) {
      LOG.error("Failed to encrypt sensitive field in STS token", e);
      throw new RuntimeException("Token encryption failed", e);
    }
  }
  
  /**
   * Decrypt a sensitive field using the configured encryption key.
   */
  private String decryptSensitiveField(String encryptedValue) {
    if (encryptedValue == null || encryptedValue.isEmpty() || encryptionKey == null) {
      return encryptedValue != null ? encryptedValue : "";
    }

    try {
      return STSTokenEncryption.decrypt(encryptedValue, encryptionKey);
    } catch (STSTokenEncryptionException e) {
      LOG.error("Failed to decrypt sensitive field in STS token", e);
      throw new RuntimeException("Token decryption failed", e);
    }
  }

  /**
   * Return cached ciphertext for secretAccessKey if available, otherwise
   * encrypt once and cache the result to ensure subsequent serializations
   * are byte-identical.
   */
  private String getOrEncryptSecretAccessKey() {
    if (cachedEncryptedSecretAccessKey != null) {
      return cachedEncryptedSecretAccessKey;
    }
    final String encrypted = encryptSensitiveField(secretAccessKey);
    cachedEncryptedSecretAccessKey = encrypted;
    return encrypted;
  }
  
  public String getRoleArn() {
    return roleArn;
  }

  public String getSecretAccessKey() {
    return secretAccessKey;
  }

  public String getOriginalAccessKeyId() {
    return originalAccessKeyId;
  }

  /**
   * Get the temporary access key ID (same as owner).
   */
  public String getTempAccessKeyId() {
    return getOwnerId();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }

    final STSTokenIdentifier that = (STSTokenIdentifier) o;
    return Objects.equals(roleArn, that.roleArn) &&
        Objects.equals(secretAccessKey, that.secretAccessKey) &&
        Objects.equals(originalAccessKeyId, that.originalAccessKeyId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(),
        roleArn,
        secretAccessKey,
        originalAccessKeyId
    );
  }

  @Override
  public String toString() {
    return "STSTokenIdentifier{" +
        "tempAccessKeyId=" + getOwnerId() +
        ", originalAccessKeyId=" + originalAccessKeyId +
        ", roleArn=" + roleArn +
        ", expiry=" + getExpiry() +
        ", secretKeyId=" + getSecretKeyId() +
        '}';
  }
}

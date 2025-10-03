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

/**
 * Token identifier for STS (Security Token Service) tokens.
 * This class extends ShortLivedTokenIdentifier to align STS tokens
 * with the standard Ozone token architecture.
 */
@InterfaceAudience.Private
@InterfaceStability.Unstable
public class STSTokenIdentifier extends ShortLivedTokenIdentifier {

  public static final Text KIND_NAME = new Text("STSToken");
  
  // STS-specific fields
  private String roleArn;
  private String roleSessionName;
  private String originalAccessKeyId;
  
  // Service name for STS tokens
  private static final String STS_SERVICE = "STS";

  /**
   * Create an empty STS token identifier.
   */
  private STSTokenIdentifier() {
    super();
  }

  /**
   * Create a new STS token identifier.
   *
   * @param tempAccessKeyId the temporary access key ID (owner)
   * @param originalAccessKeyId the original long-lived access key ID
   * @param roleArn the ARN of the assumed role
   * @param roleSessionName the session name for the role
   * @param expiry the token expiration time
   */
  public STSTokenIdentifier(String tempAccessKeyId,
                            String originalAccessKeyId,
                            String roleArn,
                            String roleSessionName,
                            Instant expiry) {
    super(tempAccessKeyId, expiry);
    this.originalAccessKeyId = originalAccessKeyId;
    this.roleArn = roleArn;
    this.roleSessionName = roleSessionName;
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
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
    readFields(in);
  }

  @Override
  public void write(DataOutput out) throws IOException {
    out.write(toProtoBuf().toByteArray());
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    OMTokenProto token = OMTokenProto.parseFrom((DataInputStream) in);
    fromProtoBuf(token);
  }

  /**
   * Convert this identifier to protobuf format.
   */
  public OMTokenProto toProtoBuf() {
    OMTokenProto.Builder builder = OMTokenProto.newBuilder()
        .setType(OMTokenProto.Type.S3_STS_TOKEN)
        .setMaxDate(getExpiry().toEpochMilli())
        .setOwner(getOwnerId() != null ? getOwnerId() : "")
        .setAccessKeyId(getOwnerId() != null ? getOwnerId() : "")
        .setOriginalAccessKeyId(originalAccessKeyId != null ? originalAccessKeyId : "")
        .setRoleArn(roleArn != null ? roleArn : "")
        .setRoleSessionName(roleSessionName != null ? roleSessionName : "");

    if (getSecretKeyId() != null) {
      builder.setSecretKeyId(getSecretKeyId().toString());
    }

    return builder.build();
  }

  /**
   * Initialize this identifier from protobuf.
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
    if (token.hasRoleSessionName()) {
      this.roleSessionName = token.getRoleSessionName();
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
    DataInputStream in = new DataInputStream(new ByteArrayInputStream(identifier));
    OMTokenProto token = OMTokenProto.parseFrom(in);
    STSTokenIdentifier stsIdentifier = new STSTokenIdentifier();
    stsIdentifier.fromProtoBuf(token);
    return stsIdentifier;
  }

  // Getters and setters for STS-specific fields
  
  public String getRoleArn() {
    return roleArn;
  }

  public void setRoleArn(String roleArn) {
    this.roleArn = roleArn;
  }

  public String getRoleSessionName() {
    return roleSessionName;
  }

  public void setRoleSessionName(String roleSessionName) {
    this.roleSessionName = roleSessionName;
  }

  public String getOriginalAccessKeyId() {
    return originalAccessKeyId;
  }

  public void setOriginalAccessKeyId(String originalAccessKeyId) {
    this.originalAccessKeyId = originalAccessKeyId;
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

    STSTokenIdentifier that = (STSTokenIdentifier) o;
    return Objects.equals(roleArn, that.roleArn) &&
        Objects.equals(roleSessionName, that.roleSessionName) &&
        Objects.equals(originalAccessKeyId, that.originalAccessKeyId);
  }

  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(),
        roleArn,
        roleSessionName,
        originalAccessKeyId
    );
  }

  @Override
  public String toString() {
    return "STSTokenIdentifier{" +
        "tempAccessKeyId=" + getOwnerId() +
        ", originalAccessKeyId=" + originalAccessKeyId +
        ", roleArn=" + roleArn +
        ", roleSessionName=" + roleSessionName +
        ", expiry=" + getExpiry() +
        ", secretKeyId=" + getSecretKeyId() +
        '}';
  }
}

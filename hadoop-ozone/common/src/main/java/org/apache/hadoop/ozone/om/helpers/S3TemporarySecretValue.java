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

package org.apache.hadoop.ozone.om.helpers;

import java.util.Objects;
import net.jcip.annotations.Immutable;
import org.apache.hadoop.hdds.utils.db.Codec;
import org.apache.hadoop.hdds.utils.db.DelegatedCodec;
import org.apache.hadoop.hdds.utils.db.Proto2Codec;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos;

/**
 * S3TemporarySecret to be saved in database.
 */
@Immutable
public class S3TemporarySecretValue {

  private static final Codec<S3TemporarySecretValue> CODEC = new DelegatedCodec<>(
      Proto2Codec.get(OzoneManagerProtocolProtos.S3TemporarySecret.getDefaultInstance()),
      S3TemporarySecretValue::fromProtobuf,
      S3TemporarySecretValue::getProtobuf,
      S3TemporarySecretValue.class
  );

  private final String accessKeyId;
  private final String secretAccessKey;
  private final String sessionToken;
  private final long expirationEpochSeconds;
  private final String roleArn;
  private final String roleSessionName;
  private final boolean isDeleted;
  private final long transactionLogIndex;

  public static Codec<S3TemporarySecretValue> getCodec() {
    return CODEC;
  }

  public static S3TemporarySecretValue of(String accessKeyId,
                                          String secretAccessKey,
                                          String sessionToken,
                                          long expirationEpochSeconds,
                                          String roleArn,
                                          String roleSessionName) {
    return of(
        accessKeyId,
        secretAccessKey,
        sessionToken,
        expirationEpochSeconds,
        roleArn,
        roleSessionName,
        0L
    );
  }

  public static S3TemporarySecretValue of(String accessKeyId,
                                          String secretAccessKey,
                                          String sessionToken,
                                          long expirationEpochSeconds,
                                          String roleArn,
                                          String roleSessionName,
                                          long transactionLogIndex) {
    return S3TemporarySecretValueBuilder.newBuilder()
        .setAccessKeyId(accessKeyId)
        .setSecretAccessKey(secretAccessKey)
        .setSessionToken(sessionToken)
        .setExpirationEpochSeconds(expirationEpochSeconds)
        .setRoleArn(roleArn)
        .setRoleSessionName(roleSessionName)
        .setIsDeleted(false)
        .setTransactionLogIndex(transactionLogIndex)
        .build();
  }

  public S3TemporarySecretValue deleted() {
    return S3TemporarySecretValueBuilder.newBuilder()
        .setAccessKeyId(accessKeyId)
        .setIsDeleted(true)
        .setTransactionLogIndex(transactionLogIndex)
        .build();
  }

  private S3TemporarySecretValue(String accessKeyId,
                                 String secretAccessKey,
                                 String sessionToken,
                                 long expirationEpochSeconds,
                                 String roleArn,
                                 String roleSessionName,
                                 boolean isDeleted,
                                 long transactionLogIndex) {
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.sessionToken = sessionToken;
    this.expirationEpochSeconds = expirationEpochSeconds;
    this.roleArn = roleArn;
    this.roleSessionName = roleSessionName;
    this.isDeleted = isDeleted;
    this.transactionLogIndex = transactionLogIndex;
  }

  public String getAccessKeyId() {
    return accessKeyId;
  }

  public String getSecretAccessKey() {
    return secretAccessKey;
  }

  public String getSessionToken() {
    return sessionToken;
  }

  public long getExpirationEpochSeconds() {
    return expirationEpochSeconds;
  }

  public String getRoleArn() {
    return roleArn;
  }

  public String getRoleSessionName() {
    return roleSessionName;
  }

  public boolean isDeleted() {
    return isDeleted;
  }

  public long getTransactionLogIndex() {
    return transactionLogIndex;
  }

  public static S3TemporarySecretValue fromProtobuf(OzoneManagerProtocolProtos.S3TemporarySecret s3TemporarySecret) {
    return S3TemporarySecretValueBuilder.newBuilder()
        .setAccessKeyId(s3TemporarySecret.getAccessKeyId())
        .setSecretAccessKey(s3TemporarySecret.getSecretAccessKey())
        .setSessionToken(s3TemporarySecret.getSessionToken())
        .setExpirationEpochSeconds(s3TemporarySecret.getExpirationEpochSeconds())
        .setRoleArn(s3TemporarySecret.getRoleArn())
        .setRoleSessionName(s3TemporarySecret.getRoleSessionName())
        .build();
  }

  public OzoneManagerProtocolProtos.S3TemporarySecret getProtobuf() {
    return OzoneManagerProtocolProtos.S3TemporarySecret.newBuilder()
        .setAccessKeyId(this.getAccessKeyId())
        .setSecretAccessKey(this.getSecretAccessKey())
        .setSessionToken(this.getSessionToken())
        .setExpirationEpochSeconds(this.getExpirationEpochSeconds())
        .setRoleArn(this.getRoleArn())
        .setRoleSessionName(this.getRoleSessionName())
        .build();
  }

  @Override
  public boolean equals(final Object o) {
    if (o == null || getClass() != o.getClass()) return false;
    final S3TemporarySecretValue that = (S3TemporarySecretValue) o;
    return expirationEpochSeconds == that.expirationEpochSeconds &&
        isDeleted == that.isDeleted &&
        transactionLogIndex == that.transactionLogIndex &&
        Objects.equals(accessKeyId, that.accessKeyId) &&
        Objects.equals(secretAccessKey, that.secretAccessKey) &&
        Objects.equals(sessionToken, that.sessionToken) &&
        Objects.equals(roleArn, that.roleArn) &&
        Objects.equals(roleSessionName, that.roleSessionName);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        accessKeyId,
        secretAccessKey,
        sessionToken,
        expirationEpochSeconds,
        roleArn,
        roleSessionName,
        isDeleted,
        transactionLogIndex
    );
  }


  public static final class S3TemporarySecretValueBuilder {
    private String accessKeyId;
    private String secretAccessKey;
    private String sessionToken;
    private long expirationEpochSeconds;
    private String roleArn;
    private String roleSessionName;
    private boolean isDeleted;
    private long transactionLogIndex;

    private S3TemporarySecretValueBuilder() {
    }

    public static S3TemporarySecretValueBuilder newBuilder() {
      return new S3TemporarySecretValueBuilder();
    }

    public S3TemporarySecretValueBuilder setAccessKeyId(String accessKeyId) {
      this.accessKeyId = accessKeyId;
      return this;
    }

    public S3TemporarySecretValueBuilder setSecretAccessKey(String secretAccessKey) {
      this.secretAccessKey = secretAccessKey;
      return this;
    }

    public S3TemporarySecretValueBuilder setSessionToken(String sessionToken) {
      this.sessionToken = sessionToken;
      return this;
    }

    public S3TemporarySecretValueBuilder setExpirationEpochSeconds(long expirationEpochSeconds) {
      this.expirationEpochSeconds = expirationEpochSeconds;
      return this;
    }

    public S3TemporarySecretValueBuilder setRoleArn(String roleArn) {
      this.roleArn = roleArn;
      return this;
    }

    public S3TemporarySecretValueBuilder setRoleSessionName(String roleSessionName) {
      this.roleSessionName = roleSessionName;
      return this;
    }

    public S3TemporarySecretValueBuilder setIsDeleted(boolean isDeleted) {
      this.isDeleted = isDeleted;
      return this;
    }

    public S3TemporarySecretValueBuilder setTransactionLogIndex(long transactionLogIndex) {
      this.transactionLogIndex = transactionLogIndex;
      return this;
    }

    public S3TemporarySecretValue build() {
      return new S3TemporarySecretValue(
          accessKeyId,
          secretAccessKey,
          sessionToken,
          expirationEpochSeconds,
          roleArn,
          roleSessionName,
          isDeleted,
          transactionLogIndex
      );
    }
  }
}


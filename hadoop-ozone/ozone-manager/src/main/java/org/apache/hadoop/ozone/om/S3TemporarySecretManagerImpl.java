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

package org.apache.hadoop.ozone.om;

import static org.apache.hadoop.hdds.security.exception.OzoneSecurityException.ResultCodes.S3_TEMPORARY_SECRET_NOT_FOUND;

import com.google.common.base.Preconditions;
import java.io.IOException;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.hdds.security.exception.OzoneSecurityException;
import org.apache.hadoop.ozone.om.helpers.S3TemporarySecretValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * S3 Temporary Secret Manager.
 */
public class S3TemporarySecretManagerImpl implements S3TemporarySecretManager {
  private static final Logger LOG = LoggerFactory.getLogger(S3TemporarySecretManagerImpl.class);

  private final S3TemporarySecretStore secretStore;
  private final S3TemporarySecretCache secretCache;

  /**
   * Constructs S3TemporarySecretManager.
   * @param secretStore  S3 temporary secret store.
   * @param secretCache  S3 temporary secret cache.
   */
  public S3TemporarySecretManagerImpl(S3TemporarySecretStore secretStore,
                                      S3TemporarySecretCache secretCache) {
    this.secretStore = secretStore;
    this.secretCache = secretCache;
  }

  @Override
  public S3TemporarySecretValue getTemporarySecret(String accessKeyId) throws IOException {
    Preconditions.checkArgument(StringUtils.isNotBlank(accessKeyId),
        "accessKeyId cannot be null or empty.");
    S3TemporarySecretValue cacheValue = secretCache.get(accessKeyId);
    if (cacheValue != null) {
      if (cacheValue.isDeleted()) {
        // The cache entry is marked as deleted which means the user has
        // purposely deleted the secret. Hence, we do not have to check the DB.
        return null;
      }
      return cacheValue;
    }
    S3TemporarySecretValue result = secretStore.getTemporarySecret(accessKeyId);
    if (result != null) {
      updateCache(accessKeyId, result);
    }
    return result;
  }

  @Override
  public String getTemporarySecretString(String accessKeyId) throws IOException {
    Preconditions.checkArgument(StringUtils.isNotBlank(accessKeyId),
        "accessKeyId cannot be null or empty.");
    LOG.trace("Getting temporary secret for accessKeyId: {}", accessKeyId);

    S3TemporarySecretValue cacheValue = secretCache.get(accessKeyId);
    if (cacheValue != null) {
      return cacheValue.getSecretAccessKey();
    }
    S3TemporarySecretValue s3TempSecret = secretStore.getTemporarySecret(accessKeyId);
    if (s3TempSecret == null) {
      throw new OzoneSecurityException(
          "Temporary secret not found for accessKeyId: " + accessKeyId,
          S3_TEMPORARY_SECRET_NOT_FOUND);
    }
    updateCache(accessKeyId, s3TempSecret);
    return s3TempSecret.getSecretAccessKey();
  }

  @Override
  public void storeTemporarySecret(String accessKeyId, S3TemporarySecretValue temporarySecretValue)
      throws IOException {
    secretStore.storeTemporarySecret(accessKeyId, temporarySecretValue);
    updateCache(accessKeyId, temporarySecretValue);
    if (LOG.isTraceEnabled()) {
      LOG.trace("Secret for accessKeyId:{} stored", accessKeyId);
    }
  }

  @Override
  public void revokeTemporarySecret(String accessKeyId) throws IOException {
    secretStore.revokeTemporarySecret(accessKeyId);
    invalidateCacheEntry(accessKeyId);
  }

  @Override
  public void clearS3TemporaryCache(List<Long> flushedTransactionIds) {
    clearCache(flushedTransactionIds);
  }

  @Override
  public <T> T doUnderLock(String lockId, S3TemporarySecretFunction<T> action)
      throws IOException {
    throw new UnsupportedOperationException(
        "Lock on locked secret manager is not supported.");
  }

  @Override
  public S3TemporarySecretCache cache() {
    return secretCache;
  }

  @Override
  public S3TempSecretBatcher batcher() {
    return secretStore.s3TemporarySecretBatcher();
  }

  @Override
  public void updateCache(String accessKeyId, S3TemporarySecretValue temporarySecretValue) {
    S3TemporarySecretManager.super.updateCache(accessKeyId, temporarySecretValue);
  }
}

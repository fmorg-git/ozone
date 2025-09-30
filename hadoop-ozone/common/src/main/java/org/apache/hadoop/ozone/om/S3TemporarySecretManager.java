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

import java.io.IOException;
import java.util.List;
import org.apache.hadoop.ozone.om.helpers.S3TemporarySecretValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Interface to manage s3 temporary secrets.
 */
public interface S3TemporarySecretManager {
  Logger LOG = LoggerFactory.getLogger(S3TemporarySecretManager.class);

  /**
   * API to get s3 temporary secret value for given access key id.
   * @param accessKeyId s3 access key id.
   * @return associated s3 temporary secret or null if secret doesn't exist.
   * @throws IOException if error occurs while retrieving the secret
   */
  S3TemporarySecretValue getTemporarySecret(String accessKeyId) throws IOException;

  /**
   * API to get s3 temporary secret for given accessKeyId.
   * @param accessKeyId s3 access key id.
   * @return associated s3 temporary secret or null if secret doesn't exist.
   * @throws IOException if error occurs while retrieving the secret
   */
  String getTemporarySecretString(String accessKeyId) throws IOException;

  /**
   * Store provided s3 temporary secret and associate it with access key id.
   * @param accessKeyId s3 access key id.
   * @param temporarySecretValue s3 temporary secret value.
   * @throws IOException if error occurs while storing the temporary secret.
   */
  void storeTemporarySecret(String accessKeyId, S3TemporarySecretValue temporarySecretValue)
      throws IOException;

  /**
   * Revoke s3 temporary secret which associated with provided access key id.
   * @param accessKeyId s3 access key id.
   * @throws IOException if error occurs while revoking the temporary secret.
   */
  void revokeTemporarySecret(String accessKeyId) throws IOException;

  /**
   * Clear s3 temporary secret cache when double buffer is flushed to the DB.
   */
  void clearS3TemporaryCache(List<Long> epochs);

  /**
   * Apply provided action under write lock.
   * @param lockId lock identifier.
   * @param action custom action.
   * @param <T> type of action result.
   * @return action result.
   * @throws IOException in case the action failed.
   */
  <T> T doUnderLock(String lockId, S3TemporarySecretFunction<T> action)
      throws IOException;

  /**
   * Default implementation of secret check method.
   * @param accessKeyId s3 access key id.
   * @return true if an associated s3 temporary secret exists for given {@code accessKeyId},
   * false if not.
   */
  default boolean hasS3TemporarySecret(String accessKeyId) throws IOException {
    return getTemporarySecret(accessKeyId) != null;
  }

  S3TemporarySecretBatcher batcher();

  default boolean isBatchSupported() {
    return batcher() != null;
  }

  /**
   * Direct temporary secret cache accessor.
   * @return s3 temporary secret cache.
   */
  S3TemporarySecretCache cache();

  default void updateCache(String accessKeyId, S3TemporarySecretValue temporarySecretValue) {
    final S3TemporarySecretCache cache = cache();
    if (cache != null) {
      LOG.info("Updating temporary secret cache for accessKeyId: {}.", accessKeyId);
      cache.put(accessKeyId, temporarySecretValue);
    }
  }

  default void invalidateCacheEntry(String id) {
    final S3TemporarySecretCache cache = cache();
    if (cache != null) {
      cache.invalidate(id);
    }
  }

  default void clearCache(List<Long> flushedTransactionIds) {
    final S3TemporarySecretCache cache = cache();
    if (cache != null) {
      cache.clearCache(flushedTransactionIds);
    }
  }

}

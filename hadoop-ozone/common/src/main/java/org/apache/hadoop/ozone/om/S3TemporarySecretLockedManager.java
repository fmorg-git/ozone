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

import static org.apache.hadoop.ozone.om.lock.OzoneManagerLock.LeveledResource.S3_TEMPORARY_SECRET_LOCK;

import java.io.IOException;
import java.util.List;
import org.apache.hadoop.ozone.om.helpers.S3TemporarySecretValue;
import org.apache.hadoop.ozone.om.lock.IOzoneManagerLock;

/**
 * Wrapper with lock logic of {@link S3TemporarySecretManager}.
 */
public class S3TemporarySecretLockedManager implements S3TemporarySecretManager {
  private final S3TemporarySecretManager temporarySecretManager;
  private final IOzoneManagerLock lock;

  public S3TemporarySecretLockedManager(S3TemporarySecretManager temporarySecretManager,
                                        IOzoneManagerLock lock) {
    this.temporarySecretManager = temporarySecretManager;
    this.lock = lock;
  }

  @Override
  public S3TemporarySecretValue getTemporarySecret(String accessKeyId) throws IOException {
    lock.acquireWriteLock(S3_TEMPORARY_SECRET_LOCK, accessKeyId);
    try {
      return temporarySecretManager.getTemporarySecret(accessKeyId);
    } finally {
      lock.releaseWriteLock(S3_TEMPORARY_SECRET_LOCK, accessKeyId);
    }
  }

  @Override
  public String getTemporarySecretString(String accessKeyId) throws IOException {
    lock.acquireReadLock(S3_TEMPORARY_SECRET_LOCK, accessKeyId);
    try {
      return temporarySecretManager.getTemporarySecretString(accessKeyId);
    } finally {
      lock.releaseReadLock(S3_TEMPORARY_SECRET_LOCK, accessKeyId);
    }
  }

  @Override
  public void storeTemporarySecret(String accessKeyId, S3TemporarySecretValue temporarySecretValue)
      throws IOException {
    lock.acquireWriteLock(S3_TEMPORARY_SECRET_LOCK, accessKeyId);
    try {
      temporarySecretManager.storeTemporarySecret(accessKeyId, temporarySecretValue);
    } finally {
      lock.releaseWriteLock(S3_TEMPORARY_SECRET_LOCK, accessKeyId);
    }
  }

  @Override
  public void revokeTemporarySecret(String accessKeyId) throws IOException {
    lock.acquireWriteLock(S3_TEMPORARY_SECRET_LOCK, accessKeyId);
    try {
      temporarySecretManager.revokeTemporarySecret(accessKeyId);
    } finally {
      lock.releaseWriteLock(S3_TEMPORARY_SECRET_LOCK, accessKeyId);
    }
  }

  @Override
  public void clearS3TemporaryCache(List<Long> epochs) {
    lock.acquireWriteLock(S3_TEMPORARY_SECRET_LOCK, "cache");
    try {
      temporarySecretManager.clearCache(epochs);
    } finally {
      lock.releaseWriteLock(S3_TEMPORARY_SECRET_LOCK, "cache");
    }
  }

  @Override
  public <T> T doUnderLock(String lockId, S3TemporarySecretFunction<T> action)
      throws IOException {
    lock.acquireWriteLock(S3_TEMPORARY_SECRET_LOCK, lockId);
    try {
      return action.accept(temporarySecretManager);
    } finally {
      lock.releaseWriteLock(S3_TEMPORARY_SECRET_LOCK, lockId);
    }
  }

  @Override
  public S3TempSecretBatcher batcher() {
    return temporarySecretManager.batcher();
  }

  @Override
  public S3TemporarySecretCache cache() {
    return temporarySecretManager.cache();
  }
}

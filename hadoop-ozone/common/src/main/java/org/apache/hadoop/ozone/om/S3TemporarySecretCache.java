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

import java.util.List;
import org.apache.hadoop.ozone.om.helpers.S3TemporarySecretValue;

/**
 * Cache layer of S3 temporary secrets.
 */
public interface S3TemporarySecretCache {
  /**
   * Put temporary secret value to cache.
   * @param accessKeyId temporary secret value identifier.
   * @param temporarySecretValue temporary secret value.
   */
  void put(String accessKeyId, S3TemporarySecretValue temporarySecretValue);

  /**
   * Invalidate temporary secret value with provided secret identifier.
   * @param accessKeyId temporary secret identifier.
   */
  void invalidate(String accessKeyId);

  /**
   * Clears the cache, removing all entries, this is called when the
   * doubleBuffer is flushed to the DB.
   */
  void clearCache(List<Long> transactionIds);

  /**
   * Get value from cache.
   * @param accessKeyId temporary secret value identifier.
   * @return Temporary Secret value or {@code null} if value doesn't exist.
   */
  S3TemporarySecretValue get(String accessKeyId);
}

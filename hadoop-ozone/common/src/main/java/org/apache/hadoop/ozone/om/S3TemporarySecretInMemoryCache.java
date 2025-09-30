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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.hadoop.ozone.om.helpers.S3TemporarySecretValue;

/**
 * S3 temporary secret cache implementation based on in-memory cache.
 */
public class S3TemporarySecretInMemoryCache implements S3TemporarySecretCache {
  private final Cache<String, S3TemporarySecretValue> cache;

  public S3TemporarySecretInMemoryCache() {
    cache = CacheBuilder.newBuilder()
        .build();
  }

  @Override
  public void put(String id, S3TemporarySecretValue secretValue) {
    cache.put(id, secretValue);
  }

  @Override
  public void invalidate(String id) {
    cache.asMap().computeIfPresent(id, (k, secret) -> secret.deleted());
  }

  @Override
  public void clearCache(List<Long> flushedTransactionIds) {
    // Create a map to store transactionLogIndex-to-cacheKey mappings
    Map<Long, String> transactionIdToCacheKeys = new HashMap<>();

    Set<String> cacheKeys = cache.asMap().keySet();
    for (String cacheKey : cacheKeys) {
      S3TemporarySecretValue tempSecretValue = cache.getIfPresent(cacheKey);
      if (tempSecretValue != null) {
        transactionIdToCacheKeys.put(tempSecretValue.getTransactionLogIndex(),
            cacheKey);
      }
    }

    for (Long transactionId : flushedTransactionIds) {
      String cacheKey = transactionIdToCacheKeys.get(transactionId);
      if (cacheKey != null) {
        cache.invalidate(cacheKey);
      }
    }
  }

  @Override
  public S3TemporarySecretValue get(String id) {
    return cache.getIfPresent(id);
  }
}

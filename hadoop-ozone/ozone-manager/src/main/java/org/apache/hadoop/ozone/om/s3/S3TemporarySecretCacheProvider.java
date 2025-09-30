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

package org.apache.hadoop.ozone.om.s3;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.ozone.om.S3TemporarySecretCache;
import org.apache.hadoop.ozone.om.S3TemporarySecretInMemoryCache;

/**
 * Provider of {@link S3TemporarySecretCache}.
 */
public interface S3TemporarySecretCacheProvider {
  /**
   * In-memory cache implementation.
   */
  S3TemporarySecretCacheProvider IN_MEMORY = conf -> new S3TemporarySecretInMemoryCache();

  /**
   * Returns S3 temporary secret cache instance constructed by provided
   * configuration.
   *
   * @param conf {@link Configuration} of Ozone.
   * @return S3 temporary secret cache instance.
   */
  S3TemporarySecretCache get(Configuration conf);

}

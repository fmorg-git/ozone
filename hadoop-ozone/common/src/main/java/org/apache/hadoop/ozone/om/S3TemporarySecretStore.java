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
import org.apache.hadoop.ozone.om.helpers.S3TemporarySecretValue;

/**
 * S3 temporary secret store interface.
 */
public interface S3TemporarySecretStore {

  /**
   * Store provided s3 temporary secret with associated access key id.
   * @param accessKeyId access key id.
   * @param temporarySecret s3 temporary secret.
   * @throws IOException if error occurs while storing the temporary secret.
   */
  void storeTemporarySecret(String accessKeyId, S3TemporarySecretValue temporarySecret)
      throws IOException;

  /**
   * Get s3 temporary secret associated with provided access key id.
   * @param accessKeyId access key id.
   * @return s3 temporary secret value or null if s3 temporary secret not founded.
   * @throws IOException if error occurs while getting the temporary secret.
   */
  S3TemporarySecretValue getTemporarySecret(String accessKeyId) throws IOException;

  /**
   * Revoke s3 temporary secret associated with provided access key id.
   * @param accessKeyId access key id.
   * @throws IOException if error occurs while revoking the temporary secret.
   */
  void revokeTemporarySecret(String accessKeyId) throws IOException;

  /**
   * @return s3 temporary batcher instance, null if batch operation isn't supported.
   */
  S3TempSecretBatcher s3TemporarySecretBatcher();
}

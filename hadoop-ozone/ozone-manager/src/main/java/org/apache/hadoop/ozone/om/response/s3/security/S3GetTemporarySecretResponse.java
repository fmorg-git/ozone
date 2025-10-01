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

package org.apache.hadoop.ozone.om.response.s3.security;

import static org.apache.hadoop.ozone.om.codec.OMDBDefinition.S3_TEMPORARY_SECRET_TABLE;

import com.google.common.annotations.VisibleForTesting;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.IOException;
import org.apache.hadoop.hdds.utils.db.BatchOperation;
import org.apache.hadoop.ozone.om.OMMetadataManager;
import org.apache.hadoop.ozone.om.S3TemporarySecretManager;
import org.apache.hadoop.ozone.om.helpers.S3TemporarySecretValue;
import org.apache.hadoop.ozone.om.response.CleanupTableInfo;
import org.apache.hadoop.ozone.om.response.OMClientResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMResponse;

/**
 * Response for S3GetTemporarySecret request.
 */
@CleanupTableInfo(cleanupTables = {S3_TEMPORARY_SECRET_TABLE})
public class S3GetTemporarySecretResponse extends OMClientResponse {

  private final S3TemporarySecretValue s3TemporarySecretValue;
  private final S3TemporarySecretManager s3TemporarySecretManager;

  public S3GetTemporarySecretResponse(@Nullable S3TemporarySecretValue s3TemporarySecretValue,
                                      @Nonnull S3TemporarySecretManager temporarySecretManager,
                                      @Nonnull OMResponse omResponse) {
    super(omResponse);
    this.s3TemporarySecretManager = temporarySecretManager;
    this.s3TemporarySecretValue = s3TemporarySecretValue;
  }

  @Override
  public void addToDBBatch(OMMetadataManager omMetadataManager,
                           BatchOperation batchOperation) throws IOException {

    boolean isOk
        = getOMResponse().getStatus() == OzoneManagerProtocolProtos.Status.OK;
    if (s3TemporarySecretValue != null && isOk) {
      if (s3TemporarySecretManager.isBatchSupported()) {
        s3TemporarySecretManager.batcher()
            .addWithBatch(batchOperation, s3TemporarySecretValue.getAccessKeyId(), s3TemporarySecretValue);
      } // else - the secret has already been stored in S3GetTemporarySecretRequest.
    }
  }

  @VisibleForTesting
  public S3TemporarySecretValue getS3TemporarySecretValue() {
    return s3TemporarySecretValue;
  }
}

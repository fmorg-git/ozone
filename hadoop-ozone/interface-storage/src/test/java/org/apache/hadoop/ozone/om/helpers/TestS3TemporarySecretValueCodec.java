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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.UUID;
import org.apache.hadoop.hdds.utils.db.Codec;
import org.apache.hadoop.hdds.utils.db.Proto2CodecTestBase;
import org.junit.jupiter.api.Test;

/**
 * Test {@link S3TemporarySecretValue#getCodec()}.
 */
public class TestS3TemporarySecretValueCodec
    extends Proto2CodecTestBase<S3TemporarySecretValue> {
  @Override
  public Codec<S3TemporarySecretValue> getCodec() {
    return S3TemporarySecretValue.getCodec();
  }

  @Test
  public void testCodecWithCorrectData() throws Exception {
    final Codec<S3TemporarySecretValue> codec = getCodec();

    final String accessKeyId = UUID.randomUUID().toString();
    final String secretAccessKey = UUID.randomUUID().toString();
    final String sessionToken = UUID.randomUUID().toString();
    final long expirationEpochSeconds = UUID.randomUUID().getMostSignificantBits();
    final String roleArn = UUID.randomUUID().toString();
    final String roleSessionName = UUID.randomUUID().toString();

    final S3TemporarySecretValue s3TemporarySecretValue =
        S3TemporarySecretValue.of(
            accessKeyId,
            secretAccessKey,
            sessionToken,
            expirationEpochSeconds,
            roleArn,
            roleSessionName
        );

    final byte[] data = codec.toPersistedFormat(s3TemporarySecretValue);
    assertNotNull(data);

    final S3TemporarySecretValue decodedS3TemporarySecret = codec.fromPersistedFormat(data);

    assertEquals(s3TemporarySecretValue, decodedS3TemporarySecret);
  }
}

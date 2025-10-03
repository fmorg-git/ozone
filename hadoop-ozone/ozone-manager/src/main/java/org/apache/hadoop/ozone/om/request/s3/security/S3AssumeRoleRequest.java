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

package org.apache.hadoop.ozone.om.request.s3.security;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.exceptions.OMException;
import org.apache.hadoop.ozone.om.execution.flowcontrol.ExecutionContext;
import org.apache.hadoop.ozone.om.request.OMClientRequest;
import org.apache.hadoop.ozone.om.request.util.OmResponseUtil;
import org.apache.hadoop.ozone.om.response.OMClientResponse;
import org.apache.hadoop.ozone.om.response.s3.security.S3AssumeRoleResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.AssumeRoleRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.AssumeRoleResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMRequest;
import org.apache.hadoop.ozone.security.STSTokenManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles S3AssumeRoleRequest request.
 */
public class S3AssumeRoleRequest extends OMClientRequest {
  private static final Logger LOG = LoggerFactory.getLogger(S3AssumeRoleRequest.class);

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public S3AssumeRoleRequest(OMRequest omRequest) {
    super(omRequest);
  }

  @Override
  public OMClientResponse validateAndUpdateCache(OzoneManager ozoneManager,
                                                 ExecutionContext context) {
    final AssumeRoleRequest request = getOmRequest().getAssumeRoleRequest();
    final String roleArn = request.getRoleArn();
    final String roleSessionName = request.getRoleSessionName();
    final int durationSeconds = request.getDurationSeconds();

    // Validate duration
    if (durationSeconds < 900 || durationSeconds > 43200) { // 15 minutes to 12 hours
      final OMException omException = new OMException("Duration: " +
          durationSeconds + " is not valid",
          OMException.ResultCodes.INVALID_REQUEST);
      return new S3AssumeRoleResponse(
          createErrorOMResponse(OmResponseUtil.getOMResponseBuilder(getOmRequest()), omException)
      );
    }

    final AssumeRoleResponse.Builder responseBuilder = AssumeRoleResponse.newBuilder();

    try {
      // Determine the caller's access key ID - this will be referred to as the original
      // access key id.  When STS tokens are used, the tokes will be authorized as
      // the kerberos principal associated to the original access key id.
      if (!getOmRequest().hasS3Authentication()) {
        final String msg = "S3AssumeRoleRequest does not have S3 authentication";
        final OMException omException = new OMException(msg, OMException.ResultCodes.INVALID_REQUEST);
        LOG.error(msg);
        return new S3AssumeRoleResponse(
            createErrorOMResponse(OmResponseUtil.getOMResponseBuilder(getOmRequest()), omException)
        );
      }

      final String originalAccessKeyId = getOmRequest().getS3Authentication().getAccessId();

      // Generate temporary AWS-style credentials
      final String tempAccessKeyId = "ASIA" + generateRandomAlphanumeric(16); // AWS temp keys start with ASIA
      final String secretAccessKey = generateRandomBase64(40);

      // Create STS token request and generate the session token
      final STSTokenRequest tokenRequest = new STSTokenRequest(
          originalAccessKeyId,
          roleArn,
          roleSessionName,
          tempAccessKeyId,
          durationSeconds,
          Arrays.asList("s3:GetObject", "s3:PutObject", "s3:ListBucket") // TODO: resolve from role
      );
      final String sessionToken = STSTokenManager.createSTSToken(tokenRequest, ozoneManager);

      // Generate AssumedRoleId
      final String roleId = "AROA" + generateRandomAlphanumeric(16);
      final String assumedRoleId = roleId + ":" + roleSessionName;

      // Calculate expiration
      final long expirationEpochSeconds = Instant.now().plusSeconds(durationSeconds).getEpochSecond();

      responseBuilder
          .setAccessKeyId(tempAccessKeyId)
          .setSecretAccessKey(secretAccessKey)
          .setSessionToken(sessionToken)
          .setExpirationEpochSeconds(expirationEpochSeconds)
          .setAssumedRoleId(assumedRoleId);

      return new S3AssumeRoleResponse(
          OmResponseUtil.getOMResponseBuilder(getOmRequest())
              .setAssumeRoleResponse(responseBuilder.build())
              .build());

    } catch (IOException e) {
      LOG.error("Error generating STS token for role: {}", roleArn, e);
      final OMException omException = new OMException("Failed to generate STS token", e,
          OMException.ResultCodes.INTERNAL_ERROR);
      return new S3AssumeRoleResponse(
          createErrorOMResponse(OmResponseUtil.getOMResponseBuilder(getOmRequest()), omException)
      );
    }
  }

  @SuppressWarnings("SameParameterValue")
  private static String generateRandomAlphanumeric(int length) {
    final String alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    final StringBuilder sb = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
      sb.append(alphabet.charAt(SECURE_RANDOM.nextInt(alphabet.length())));
    }
    return sb.toString();
  }

  @SuppressWarnings("SameParameterValue")
  private static String generateRandomBase64(int numBytes) {
    final byte[] bytes = new byte[numBytes];
    SECURE_RANDOM.nextBytes(bytes);
    return Base64.getEncoder().withoutPadding().encodeToString(bytes);
  }
}

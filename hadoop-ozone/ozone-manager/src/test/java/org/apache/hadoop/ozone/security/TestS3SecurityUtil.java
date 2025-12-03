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

package org.apache.hadoop.ozone.security;

import static org.apache.hadoop.ozone.om.exceptions.OMException.ResultCodes.INVALID_TOKEN;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import org.apache.hadoop.hdds.utils.db.Table;
import org.apache.hadoop.ozone.om.OMMetadataManager;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.exceptions.OMException;
import org.apache.hadoop.ozone.security.STSTokenIdentifier;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.S3Authentication;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.Type;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

/**
 * Tests for STS revocation handling in {@link S3SecurityUtil}.
 */
public class TestS3SecurityUtil {

  private static OMRequest createRequestWithSessionToken(String sessionToken) {
    final S3Authentication auth = S3Authentication.newBuilder()
        .setAccessId("accessId")
        .setStringToSign("dummy-string-to-sign")
        .setSignature("dummy-signature")
        .setSessionToken(sessionToken)
        .build();

    return OMRequest.newBuilder()
        .setClientId("client")
        .setCmdType(Type.CreateVolume)
        .setS3Authentication(auth)
        .build();
  }

  /**
   * If the revoked STS token table contains an entry for the temporary access
   * key ID extracted from the session token, validateS3Credential should
   * reject the request with INVALID_TOKEN before performing full STS
   * validation.
   */
  @Test
  public void testValidateS3CredentialFailsWhenTokenRevoked() throws Exception {
    final String sessionToken = "dummy-session-token";
    final String tempAccessKeyId = "ASIA_TEMP_ACCESS";

    final OzoneManager ozoneManager = mock(OzoneManager.class);
    when(ozoneManager.isSecurityEnabled()).thenReturn(true);

    final OMMetadataManager metadataManager = mock(OMMetadataManager.class);
    when(ozoneManager.getMetadataManager()).thenReturn(metadataManager);

    @SuppressWarnings("unchecked")
    final Table<String, String> revokedTable = mock(Table.class);
    when(metadataManager.getS3RevokedStsTokenTable()).thenReturn(revokedTable);

    // Static mock STSSecurityUtil.constructSTSToken to return a token
    // whose tempAccessKeyId matches the one we'll mark as revoked.
    final STSTokenIdentifier stsId = new STSTokenIdentifier(
        tempAccessKeyId,
        "original-access",
        "arn:aws:iam::123456789012:role/test-role",
        Instant.now().plusSeconds(3600),
        "secret-access-key",
        null,
        "session-policy");

    try (MockedStatic<STSSecurityUtil> stsUtilMock =
             Mockito.mockStatic(STSSecurityUtil.class, Mockito.CALLS_REAL_METHODS)) {

      stsUtilMock.when(() -> STSSecurityUtil.constructSTSToken(sessionToken))
          .thenReturn(stsId);

      // Mark the temp access key as revoked in the table.
      when(revokedTable.getIfExist(tempAccessKeyId)).thenReturn("marker");

      final OMRequest omRequest = createRequestWithSessionToken(sessionToken);

      OMException ex = assertThrows(OMException.class,
          () -> S3SecurityUtil.validateS3Credential(omRequest, ozoneManager));
      assertEquals(INVALID_TOKEN, ex.getResult());
    }
  }

  /**
   * If the metadata manager is not available, the revocation check should be
   * treated as best-effort and not cause the request to be rejected.
   */
  @Test
  public void testValidateS3CredentialBestEffortWhenMetadataUnavailable()
      throws Exception {
    final String sessionToken = "dummy-session-token";

    final OzoneManager ozoneManager = mock(OzoneManager.class);
    when(ozoneManager.isSecurityEnabled()).thenReturn(true);
    when(ozoneManager.getMetadataManager()).thenReturn(null);

    final OMRequest omRequest = createRequestWithSessionToken(sessionToken);

    try (MockedStatic<STSSecurityUtil> stsUtilMock =
             Mockito.mockStatic(STSSecurityUtil.class, Mockito.CALLS_REAL_METHODS);
         MockedStatic<AWSV4AuthValidator> awsMock =
             Mockito.mockStatic(AWSV4AuthValidator.class, Mockito.CALLS_REAL_METHODS)) {

      // Skip real STS token verification and decryption.
      stsUtilMock.when(() -> STSSecurityUtil.validateSTSToken(sessionToken, ozoneManager))
          .thenAnswer(invocation -> null);

      final STSTokenIdentifier decryptedId = new STSTokenIdentifier(
          "ASIA_TEMP_ACCESS",
          "original-access",
          "arn:aws:iam::123456789012:role/test-role",
          Instant.now().plusSeconds(3600),
          "secret-access-key",
          null,
          "session-policy");

      stsUtilMock.when(
              () -> STSSecurityUtil.constructAndDecryptSTSToken(sessionToken, ozoneManager))
          .thenReturn(decryptedId);

      // Short-circuit AWS V4 signature validation.
      awsMock.when(
              () -> AWSV4AuthValidator.validateRequest(anyString(), anyString(), anyString()))
          .thenReturn(true);

      assertDoesNotThrow(
          () -> S3SecurityUtil.validateS3Credential(omRequest, ozoneManager));
    }
  }

  /**
   * If decoding the STS token for revocation checking fails with OMException,
   * the error should be treated as best-effort and normal validation should
   * still proceed.
   */
  @Test
  public void testValidateS3CredentialBestEffortOnTokenDecodeError()
      throws Exception {
    final String sessionToken = "invalid-session-token";

    final OzoneManager ozoneManager = mock(OzoneManager.class);
    when(ozoneManager.isSecurityEnabled()).thenReturn(true);

    final OMMetadataManager metadataManager = mock(OMMetadataManager.class);
    when(ozoneManager.getMetadataManager()).thenReturn(metadataManager);

    @SuppressWarnings("unchecked")
    final Table<String, String> revokedTable = mock(Table.class);
    when(metadataManager.getS3RevokedStsTokenTable()).thenReturn(revokedTable);

    final OMRequest omRequest = createRequestWithSessionToken(sessionToken);

    try (MockedStatic<STSSecurityUtil> stsUtilMock =
             Mockito.mockStatic(STSSecurityUtil.class, Mockito.CALLS_REAL_METHODS);
         MockedStatic<AWSV4AuthValidator> awsMock =
             Mockito.mockStatic(AWSV4AuthValidator.class, Mockito.CALLS_REAL_METHODS)) {

      // Simulate decode failure in isRevokedStsTempAccessKey.
      stsUtilMock.when(() -> STSSecurityUtil.constructSTSToken(sessionToken))
          .thenThrow(new OMException("bad token", INVALID_TOKEN));

      // Normal validation path should still run and be successful.
      stsUtilMock.when(() -> STSSecurityUtil.validateSTSToken(sessionToken, ozoneManager))
          .thenAnswer(invocation -> null);

      final STSTokenIdentifier decryptedId = new STSTokenIdentifier(
          "ASIA_TEMP_ACCESS",
          "original-access",
          "arn:aws:iam::123456789012:role/test-role",
          Instant.now().plusSeconds(3600),
          "secret-access-key",
          null,
          "session-policy");

      stsUtilMock.when(
              () -> STSSecurityUtil.constructAndDecryptSTSToken(sessionToken, ozoneManager))
          .thenReturn(decryptedId);

      // Short-circuit AWS V4 signature validation.
      try (MockedStatic<AWSV4AuthValidator> awsMock2 =
               Mockito.mockStatic(AWSV4AuthValidator.class, Mockito.CALLS_REAL_METHODS)) {
        awsMock2.when(
                () -> AWSV4AuthValidator.validateRequest(anyString(), anyString(), anyString()))
            .thenReturn(true);
        assertDoesNotThrow(
            () -> S3SecurityUtil.validateS3Credential(omRequest, ozoneManager));
      }
    }
  }

  /**
   * Normal case: token is NOT revoked; full validation path runs and
   * request is accepted (no exception).
   */
  @Test
  public void testValidateS3CredentialSuccessWhenNotRevoked() throws Exception {
    final String sessionToken = "valid-session-token";
    final String tempAccessKeyId = "ASIA_TEMP_ACCESS";

    final OzoneManager ozoneManager = mock(OzoneManager.class);
    when(ozoneManager.isSecurityEnabled()).thenReturn(true);

    final OMMetadataManager metadataManager = mock(OMMetadataManager.class);
    when(ozoneManager.getMetadataManager()).thenReturn(metadataManager);

    @SuppressWarnings("unchecked")
    final Table<String, String> revokedTable = mock(Table.class);
    when(metadataManager.getS3RevokedStsTokenTable()).thenReturn(revokedTable);

    // Not revoked -> getIfExist returns null
    when(revokedTable.getIfExist(tempAccessKeyId)).thenReturn(null);

    final OMRequest omRequest = createRequestWithSessionToken(sessionToken);

    final STSTokenIdentifier decodedForRevocation = new STSTokenIdentifier(
        tempAccessKeyId,
        "original-access",
        "arn:aws:iam::123456789012:role/test-role",
        Instant.now().plusSeconds(3600),
        "secret-access-key",
        null,
        "session-policy");

    final STSTokenIdentifier decryptedForSignature = new STSTokenIdentifier(
        tempAccessKeyId,
        "original-access",
        "arn:aws:iam::123456789012:role/test-role",
        Instant.now().plusSeconds(3600),
        "secret-access-key",
        null,
        "session-policy");

    try (MockedStatic<STSSecurityUtil> stsUtilMock =
             Mockito.mockStatic(STSSecurityUtil.class, Mockito.CALLS_REAL_METHODS);
         MockedStatic<AWSV4AuthValidator> awsMock =
             Mockito.mockStatic(AWSV4AuthValidator.class, Mockito.CALLS_REAL_METHODS)) {

      // Revocation check decode
      stsUtilMock.when(() -> STSSecurityUtil.constructSTSToken(sessionToken))
          .thenReturn(decodedForRevocation);
      // Full validation
      stsUtilMock.when(() -> STSSecurityUtil.validateSTSToken(sessionToken, ozoneManager))
          .thenAnswer(invocation -> null);
      stsUtilMock.when(() -> STSSecurityUtil.constructAndDecryptSTSToken(sessionToken, ozoneManager))
          .thenReturn(decryptedForSignature);
      // Signature OK
      awsMock.when(() -> AWSV4AuthValidator.validateRequest(anyString(), anyString(), anyString()))
          .thenReturn(true);

      assertDoesNotThrow(
          () -> S3SecurityUtil.validateS3Credential(omRequest, ozoneManager));
    }
  }
}



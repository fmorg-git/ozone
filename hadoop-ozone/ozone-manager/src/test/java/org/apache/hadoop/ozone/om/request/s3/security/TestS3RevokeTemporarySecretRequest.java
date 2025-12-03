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

import static org.apache.hadoop.security.authentication.util.KerberosName.DEFAULT_MECHANISM;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.hadoop.hdds.security.symmetric.ManagedSecretKey;
import org.apache.hadoop.hdds.security.symmetric.SecretKeySignerClient;
import org.apache.hadoop.ipc.ExternalCall;
import org.apache.hadoop.ipc.Server;
import org.apache.hadoop.ozone.om.OMMultiTenantManager;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.exceptions.OMException;
import org.apache.hadoop.ozone.om.request.OMClientRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.RevokeS3TemporarySecretRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.Type;
import org.apache.hadoop.ozone.security.STSTokenIdentifier;
import org.apache.hadoop.ozone.security.STSTokenSecretManager;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.authentication.util.KerberosName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link S3RevokeTemporarySecretRequest}.
 */
public class TestS3RevokeTemporarySecretRequest {

  private STSTokenSecretManager stsTokenSecretManager;
  private OMMultiTenantManager omMultiTenantManager;

  @BeforeEach
  public void setUp() throws Exception {
    // Initialize KerberosName rules so that UGI short names derived from
    // principals like "alice@EXAMPLE.COM" are computed correctly.
    KerberosName.setRuleMechanism(DEFAULT_MECHANISM);
    KerberosName.setRules(
        "RULE:[2:$1@$0](.*@EXAMPLE.COM)s/@.*//\n" +
        "RULE:[1:$1@$0](.*@EXAMPLE.COM)s/@.*//\n" +
        "DEFAULT");
    // Minimal STSTokenSecretManager setup copied from TestSTSTokenSecretManager.
    final SecretKeySignerClient secretKeyClient = mock(SecretKeySignerClient.class);
    final ManagedSecretKey managedSecretKey = mock(ManagedSecretKey.class);

    final KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
    keyGenerator.init(256);
    final SecretKey secretKey = keyGenerator.generateKey();

    when(managedSecretKey.getId()).thenReturn(UUID.randomUUID());
    when(managedSecretKey.getSecretKey()).thenReturn(secretKey);
    when(managedSecretKey.sign(any(STSTokenIdentifier.class)))
        .thenReturn("mock-signature".getBytes(StandardCharsets.UTF_8));
    when(secretKeyClient.getCurrentSecretKey()).thenReturn(managedSecretKey);

    stsTokenSecretManager = new STSTokenSecretManager(secretKeyClient);

    // Multi-tenant manager mock used for tests that exercise
    // the S3 multi-tenancy permission branch.
    omMultiTenantManager = mock(OMMultiTenantManager.class);
  }

  @AfterEach
  public void tearDown() {
    Server.getCurCall().set(null);
  }

  private String createSessionToken(String tempAccessKeyId,
                                   String originalAccessKeyId) throws IOException {
    return stsTokenSecretManager.createSTSTokenString(
        tempAccessKeyId,
        originalAccessKeyId,
        "arn:aws:iam::123456789012:role/test-role",
        3600,
        "test-secret-access-key",
        "test-session-policy");
  }

  /**
   * Verify that preExecute enforces permissions based on the original
   * access key id encoded in the STS token and rejects revocation
   * attempts from non-owners.
   */
  @Test
  public void testPreExecuteFailsForNonOwnerOfOriginalAccessKey() throws Exception {
    final String tempAccessKeyId = "ASIA_TEMP_ACCESS";
    final String originalAccessKeyId = "original-access-id";

    final String sessionToken =
        createSessionToken(tempAccessKeyId, originalAccessKeyId);

    // Simulate an RPC call running as the temporary access key id,
    // which should NOT be allowed to revoke the token whose original
    // access key id is different.
    final UserGroupInformation tempUgi =
        UserGroupInformation.createRemoteUser(tempAccessKeyId);
    Server.getCurCall().set(new StubCall(tempUgi));

    OMException ex;
    try (OzoneManager ozoneManager = mock(OzoneManager.class)) {
      when(ozoneManager.isS3MultiTenancyEnabled()).thenReturn(false);
      when(ozoneManager.isS3Admin(any(UserGroupInformation.class)))
          .thenReturn(false);

      final RevokeS3TemporarySecretRequest revokeProto =
          RevokeS3TemporarySecretRequest.newBuilder()
              .setAccessKeyId(tempAccessKeyId)
              .setSessionToken(sessionToken)
              .build();

      final OMRequest omRequest = OMRequest.newBuilder()
          .setClientId(UUID.randomUUID().toString())
          .setCmdType(Type.RevokeS3TemporarySecret)
          .setRevokeS3TemporarySecretRequest(revokeProto)
          .build();

      final OMClientRequest omClientRequest =
          new S3RevokeTemporarySecretRequest(omRequest);

      ex = assertThrows(OMException.class,
          () -> omClientRequest.preExecute(ozoneManager));
    }
    assertEquals(OMException.ResultCodes.USER_MISMATCH, ex.getResult());
  }

  /**
   * Verify that preExecute allows the owner of the original access key id
   * (as encoded in the STS token) to revoke the temporary credentials.
   */
  @Test
  public void testPreExecuteSucceedsForOriginalAccessKeyOwner() throws Exception {
    final String tempAccessKeyId = "ASIA_TEMP_ACCESS";
    final String originalAccessKeyId = "original-access-id";

    final String sessionToken =
        createSessionToken(tempAccessKeyId, originalAccessKeyId);

    // Simulate an RPC call running as the original access key id.
    final UserGroupInformation originalUgi =
        UserGroupInformation.createRemoteUser(originalAccessKeyId);
    Server.getCurCall().set(new StubCall(originalUgi));

    final OzoneManager ozoneManager = mock(OzoneManager.class);
    when(ozoneManager.isS3MultiTenancyEnabled()).thenReturn(false);
    when(ozoneManager.isS3Admin(any(UserGroupInformation.class)))
        .thenReturn(false);

    final RevokeS3TemporarySecretRequest revokeProto =
        RevokeS3TemporarySecretRequest.newBuilder()
            .setAccessKeyId(tempAccessKeyId)
            .setSessionToken(sessionToken)
            .build();

    final OMRequest omRequest = OMRequest.newBuilder()
        .setClientId(UUID.randomUUID().toString())
        .setCmdType(Type.RevokeS3TemporarySecret)
        .setRevokeS3TemporarySecretRequest(revokeProto)
        .build();

    final OMClientRequest omClientRequest =
        new S3RevokeTemporarySecretRequest(omRequest);

    OMRequest result = omClientRequest.preExecute(ozoneManager);
    assertNotNull(result);
    assertEquals(Type.RevokeS3TemporarySecret, result.getCmdType());
  }

  /**
   * When S3 multi-tenancy is enabled and the original access key id is
   * assigned to a tenant, verify that the tenant access ID owner is allowed
   * to revoke the temporary credentials.
   */
  @Test
  public void testPreExecuteSucceedsForTenantAccessIdOwner() throws Exception {
    final String tenantId = "finance";
    final String originalAccessKeyId = "alice@EXAMPLE.COM";
    final String tempAccessKeyId = "ASIA_TEMP_ACCESS";

    final String sessionToken =
        createSessionToken(tempAccessKeyId, originalAccessKeyId);

    // Caller short name "alice" should match the owner username returned
    // from the multi-tenant manager.
    final UserGroupInformation callerUgi =
        UserGroupInformation.createRemoteUser(originalAccessKeyId);
    Server.getCurCall().set(new StubCall(callerUgi));

    final OzoneManager ozoneManager = mock(OzoneManager.class);
    when(ozoneManager.isS3MultiTenancyEnabled()).thenReturn(true);
    when(ozoneManager.getMultiTenantManager()).thenReturn(omMultiTenantManager);

    // Original access key id is assigned to a tenant and owned by "alice".
    when(omMultiTenantManager.getTenantForAccessID(originalAccessKeyId))
        .thenReturn(java.util.Optional.of(tenantId));
    when(omMultiTenantManager.getUserNameGivenAccessId(originalAccessKeyId))
        .thenReturn("alice");
    // Not a tenant admin; ownership should be sufficient.
    when(omMultiTenantManager.isTenantAdmin(callerUgi, tenantId, false))
        .thenReturn(false);

    final RevokeS3TemporarySecretRequest revokeProto =
        RevokeS3TemporarySecretRequest.newBuilder()
            .setAccessKeyId(tempAccessKeyId)
            .setSessionToken(sessionToken)
            .build();

    final OMRequest omRequest = OMRequest.newBuilder()
        .setClientId(UUID.randomUUID().toString())
        .setCmdType(Type.RevokeS3TemporarySecret)
        .setRevokeS3TemporarySecretRequest(revokeProto)
        .build();

    final OMClientRequest omClientRequest =
        new S3RevokeTemporarySecretRequest(omRequest);

    OMRequest result = omClientRequest.preExecute(ozoneManager);
    assertNotNull(result);
    assertEquals(Type.RevokeS3TemporarySecret, result.getCmdType());
  }

  /**
   * When S3 multi-tenancy is enabled and the original access key id is
   * assigned to a tenant, verify that a tenant admin (who is not the owner)
   * is allowed to revoke the temporary credentials.
   */
  @Test
  public void testPreExecuteSucceedsForTenantAdmin() throws Exception {
    final String tenantId = "finance";
    final String originalAccessKeyId = "alice@EXAMPLE.COM";
    final String tempAccessKeyId = "ASIA_TEMP_ACCESS";

    final String sessionToken =
        createSessionToken(tempAccessKeyId, originalAccessKeyId);

    // Caller short name "bob" does not own the access ID but will be
    // configured as tenant admin.
    final UserGroupInformation callerUgi =
        UserGroupInformation.createRemoteUser("bob@EXAMPLE.COM");
    Server.getCurCall().set(new StubCall(callerUgi));

    final OzoneManager ozoneManager = mock(OzoneManager.class);
    when(ozoneManager.isS3MultiTenancyEnabled()).thenReturn(true);
    when(ozoneManager.getMultiTenantManager()).thenReturn(omMultiTenantManager);

    // Original access key id is assigned to a tenant and owned by "alice".
    when(omMultiTenantManager.getTenantForAccessID(originalAccessKeyId))
        .thenReturn(java.util.Optional.of(tenantId));
    when(omMultiTenantManager.getUserNameGivenAccessId(originalAccessKeyId))
        .thenReturn("alice");
    // Caller is configured as tenant admin so the check should pass.
    when(omMultiTenantManager.isTenantAdmin(callerUgi, tenantId, false))
        .thenReturn(true);

    final RevokeS3TemporarySecretRequest revokeProto =
        RevokeS3TemporarySecretRequest.newBuilder()
            .setAccessKeyId(tempAccessKeyId)
            .setSessionToken(sessionToken)
            .build();

    final OMRequest omRequest = OMRequest.newBuilder()
        .setClientId(UUID.randomUUID().toString())
        .setCmdType(Type.RevokeS3TemporarySecret)
        .setRevokeS3TemporarySecretRequest(revokeProto)
        .build();

    final OMClientRequest omClientRequest =
        new S3RevokeTemporarySecretRequest(omRequest);

    OMRequest result = omClientRequest.preExecute(ozoneManager);
    assertNotNull(result);
    assertEquals(Type.RevokeS3TemporarySecret, result.getCmdType());
  }

  /**
   * When S3 multi-tenancy is enabled and the original access key id is
   * assigned to a tenant, verify that a non-owner, non-admin caller is
   * rejected.
   */
  @Test
  public void testPreExecuteFailsForNonOwnerNonAdminInTenant() throws Exception {
    final String tenantId = "finance";
    final String originalAccessKeyId = "alice@EXAMPLE.COM";
    final String tempAccessKeyId = "ASIA_TEMP_ACCESS";

    final String sessionToken =
        createSessionToken(tempAccessKeyId, originalAccessKeyId);

    // Caller short name "carol" does not own the access ID and is not
    // configured as tenant admin.
    final UserGroupInformation callerUgi =
        UserGroupInformation.createRemoteUser("carol@EXAMPLE.COM");
    Server.getCurCall().set(new StubCall(callerUgi));

    OMException ex;
    try (OzoneManager ozoneManager = mock(OzoneManager.class)) {
      when(ozoneManager.isS3MultiTenancyEnabled()).thenReturn(true);
      when(ozoneManager.getMultiTenantManager()).thenReturn(omMultiTenantManager);

      // Original access key id is assigned to a tenant and owned by "alice".
      when(omMultiTenantManager.getTenantForAccessID(originalAccessKeyId))
          .thenReturn(java.util.Optional.of(tenantId));
      when(omMultiTenantManager.getUserNameGivenAccessId(originalAccessKeyId))
          .thenReturn("alice");
      // Caller is not a tenant admin.
      when(omMultiTenantManager.isTenantAdmin(callerUgi, tenantId, false))
          .thenReturn(false);

      final RevokeS3TemporarySecretRequest revokeProto =
          RevokeS3TemporarySecretRequest.newBuilder()
              .setAccessKeyId(tempAccessKeyId)
              .setSessionToken(sessionToken)
              .build();

      final OMRequest omRequest = OMRequest.newBuilder()
          .setClientId(UUID.randomUUID().toString())
          .setCmdType(Type.RevokeS3TemporarySecret)
          .setRevokeS3TemporarySecretRequest(revokeProto)
          .build();

      final OMClientRequest omClientRequest =
          new S3RevokeTemporarySecretRequest(omRequest);

      ex = assertThrows(OMException.class,
          () -> omClientRequest.preExecute(ozoneManager));
    }
    assertEquals(OMException.ResultCodes.USER_MISMATCH, ex.getResult());
  }

  /**
   * Verify that if the request Access Key ID does not match the one inside
   * the session token, the request is rejected. This prevents a user with
   * a valid session token from revoking arbitrary keys.
   */
  @Test
  public void testPreExecuteFailsForMismatchedAccessKeyId() throws Exception {
    final String tempAccessKeyId = "ASIA_TEMP_ACCESS";
    final String otherAccessKeyId = "ASIA_OTHER_ACCESS";
    final String originalAccessKeyId = "original-access-id";

    final String sessionToken =
        createSessionToken(tempAccessKeyId, originalAccessKeyId);

    // Caller IS the owner of the session token, so permissions would pass
    final UserGroupInformation originalUgi =
        UserGroupInformation.createRemoteUser(originalAccessKeyId);
    Server.getCurCall().set(new StubCall(originalUgi));

    OMException ex;
    try (OzoneManager ozoneManager = mock(OzoneManager.class)) {
      when(ozoneManager.isS3MultiTenancyEnabled()).thenReturn(false);
      when(ozoneManager.isS3Admin(any(UserGroupInformation.class)))
          .thenReturn(false);

      // Request tries to revoke "ASIA_OTHER_ACCESS" using a token for "ASIA_TEMP_ACCESS"
      final RevokeS3TemporarySecretRequest revokeProto =
          RevokeS3TemporarySecretRequest.newBuilder()
              .setAccessKeyId(otherAccessKeyId)
              .setSessionToken(sessionToken)
              .build();

      final OMRequest omRequest = OMRequest.newBuilder()
          .setClientId(UUID.randomUUID().toString())
          .setCmdType(Type.RevokeS3TemporarySecret)
          .setRevokeS3TemporarySecretRequest(revokeProto)
          .build();

      final OMClientRequest omClientRequest =
          new S3RevokeTemporarySecretRequest(omRequest);

      ex = assertThrows(OMException.class,
          () -> omClientRequest.preExecute(ozoneManager));
    }
    assertEquals(OMException.ResultCodes.INVALID_REQUEST, ex.getResult());
  }

  /**
   * Simple ExternalCall stub used to inject a remote user into the
   * ProtobufRpcEngine.Server.getRemoteUser() thread-local.
   */
  private static final class StubCall extends ExternalCall<String> {
    private final UserGroupInformation ugi;

    StubCall(UserGroupInformation ugi) {
      super(null);
      this.ugi = ugi;
    }

    @Override
    public UserGroupInformation getRemoteUser() {
      return ugi;
    }
  }
}

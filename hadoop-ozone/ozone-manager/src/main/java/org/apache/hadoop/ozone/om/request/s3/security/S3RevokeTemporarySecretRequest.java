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
import java.util.HashMap;
import java.util.Map;

import org.apache.hadoop.ozone.OzoneConsts;
import org.apache.hadoop.ozone.audit.OMAction;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.execution.flowcontrol.ExecutionContext;
import org.apache.hadoop.ozone.om.request.OMClientRequest;
import org.apache.hadoop.ozone.om.request.util.OmResponseUtil;
import org.apache.hadoop.ozone.om.response.OMClientResponse;
import org.apache.hadoop.ozone.om.response.s3.security.S3RevokeTemporarySecretResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.RevokeS3TemporarySecretRequest;
import org.apache.hadoop.ozone.security.STSSecurityUtil;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles RevokeS3TemporarySecret request.
 *
 * <p>This request marks an STS temporary access key id as revoked by inserting
 * it into the {@code s3RevokedStsTokenTable}. Subsequent S3 requests
 * authenticated with the same STS access key id will be rejected when the
 * revocation state has propagated.</p>
 */
public class S3RevokeTemporarySecretRequest extends OMClientRequest {

  private static final Logger LOG =
      LoggerFactory.getLogger(S3RevokeTemporarySecretRequest.class);

  public S3RevokeTemporarySecretRequest(OMRequest omRequest) {
    super(omRequest);
  }

  @Override
  public OMRequest preExecute(OzoneManager ozoneManager) throws IOException {
    final RevokeS3TemporarySecretRequest revokeReq =
        getOmRequest().getRevokeS3TemporarySecretRequest();

    // Derive the original (long-lived) access key id from the session token
    // and enforce the same permission model that is used for S3 secret
    // operations (get/set/revoke). Only the owner of the original access
    // key (or an S3 / tenant admin) is allowed to revoke its temporary
    // STS credentials.
    final String sessionToken = revokeReq.getSessionToken();
    final String originalAccessKeyId =
        STSSecurityUtil.extractOriginalAccessKeyId(sessionToken);

    final UserGroupInformation ugi =
        S3SecretRequestHelper.getOrCreateUgi(originalAccessKeyId);
    S3SecretRequestHelper.checkAccessIdSecretOpPermission(
        ozoneManager, ugi, originalAccessKeyId);

    // No complex transformation is needed; simply rewrap the request
    // with the resolved user info and trace id if present.
    OMRequest.Builder omRequest = OMRequest.newBuilder()
        .setRevokeS3TemporarySecretRequest(revokeReq)
        .setCmdType(getOmRequest().getCmdType())
        .setClientId(getOmRequest().getClientId())
        .setUserInfo(getUserInfo());

    if (getOmRequest().hasTraceID()) {
      omRequest.setTraceID(getOmRequest().getTraceID());
    }

    return omRequest.build();
  }

  @Override
  public OMClientResponse validateAndUpdateCache(
      OzoneManager ozoneManager, ExecutionContext context) {

    OMClientResponse omClientResponse;
    OMResponse.Builder omResponse =
        OmResponseUtil.getOMResponseBuilder(getOmRequest());

    final RevokeS3TemporarySecretRequest revokeReq =
        getOmRequest().getRevokeS3TemporarySecretRequest();
    final String accessKeyId = revokeReq.getAccessKeyId();
    final String sessionToken = revokeReq.getSessionToken();

    // All actual DB mutations are done in the response's addToDBBatch().
    omClientResponse = new S3RevokeTemporarySecretResponse(
        accessKeyId,
        sessionToken,
        omResponse.build());

    // Audit log
    Map<String, String> auditMap = new HashMap<>();
    auditMap.put(OzoneConsts.S3_REVOKESECRET_USER, accessKeyId);
    markForAudit(ozoneManager.getAuditLogger(), buildAuditMessage(
        OMAction.REVOKE_S3_TEMPORARY_SECRET, auditMap,
        null, getOmRequest().getUserInfo()));

    LOG.info("Marked STS temporary access key '{}' as revoked.", accessKeyId);
    return omClientResponse;
  }
}



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
import static org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMTokenProto.Type.S3AUTHINFO;

import com.google.protobuf.ServiceException;
import org.apache.hadoop.hdds.annotation.InterfaceAudience;
import org.apache.hadoop.hdds.annotation.InterfaceStability;
import org.apache.hadoop.hdds.utils.db.Table;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.ozone.om.OMMetadataManager;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.exceptions.OMException;
import org.apache.hadoop.ozone.om.exceptions.OMLeaderNotReadyException;
import org.apache.hadoop.ozone.om.exceptions.OMNotLeaderException;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.S3Authentication;
import org.apache.hadoop.ozone.protocolPB.OzoneManagerProtocolServerSideTranslatorPB;
import org.apache.hadoop.security.token.SecretManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class which holds methods required for parse/validation of
 * S3 Authentication Information which is part of OMRequest.
 */
@InterfaceAudience.Private
@InterfaceStability.Evolving
public final class S3SecurityUtil {
  private static final Logger LOG = LoggerFactory.getLogger(S3SecurityUtil.class);

  private S3SecurityUtil() {
  }

  /**
   * Validate S3 Credentials which are part of {@link OMRequest}.
   * <p>
   * If validation is successful returns, else throw exception.
   * @throws OMException         validation failure
   *         ServiceException    Server is not leader or not ready
   */
  public static void validateS3Credential(OMRequest omRequest,
      OzoneManager ozoneManager) throws ServiceException, OMException {
    if (ozoneManager.isSecurityEnabled()) {
      // If session token is present, validate it via STSSecurityUtil first
      if (omRequest.hasS3Authentication() && omRequest.getS3Authentication().hasSessionToken()) {
        LOG.info("[FM] S3 request has session token ");
        final String sessionToken = omRequest.getS3Authentication().getSessionToken();

        // Best-effort revocation check based on the STS temporary access key
        // ID. This uses RocksDB keyMayExist via Table#getIfExist under the
        // hood for efficiency.
        if (isRevokedStsTempAccessKey(sessionToken, ozoneManager)) {
          LOG.info("[FM] Session token has been revoked: {}", sessionToken);
          throw new OMException("STS token has been revoked",
              INVALID_TOKEN);
        }

        STSSecurityUtil.validateSTSToken(sessionToken, ozoneManager);
        // STS token validated
        LOG.info("[FM] S3 request session token successfully validated ");

        // Validate signature
        final STSTokenIdentifier stsTokenIdentifier =
            STSSecurityUtil.constructAndDecryptSTSToken(sessionToken, ozoneManager);
        final String secretAccessKey = stsTokenIdentifier.getSecretAccessKey();
        if (AWSV4AuthValidator.validateRequest(omRequest.getS3Authentication().getStringToSign(),
            omRequest.getS3Authentication().getSignature(), secretAccessKey)) {
          return;
        }
        throw new OMException("STS token validation failed for token: " + sessionToken,
            INVALID_TOKEN);
      }

      OzoneTokenIdentifier s3Token = constructS3Token(omRequest);
      try {
        // authenticate user with signature verification through
        // delegationTokenMgr validateToken via retrievePassword
        ozoneManager.getDelegationTokenMgr().retrievePassword(s3Token);
      } catch (SecretManager.InvalidToken e) {
        if (e.getCause() != null &&
            (e.getCause().getClass() == OMNotLeaderException.class ||
            e.getCause().getClass() == OMLeaderNotReadyException.class)) {
          throw new ServiceException(e.getCause());
        }

        // TODO: Just check are we okay to log entire token in failure case.
        OzoneManagerProtocolServerSideTranslatorPB.getLog().error(
            "signatures do NOT match for S3 identifier:{}", s3Token, e);
        throw new OMException("User " + s3Token.getAwsAccessId()
            + " request authorization failure: signatures do NOT match",
            INVALID_TOKEN);
      }
    }
  }

  /**
   * Return true if the STS token's temporary access key ID is present in the
   * revoked STS access key table.
   *
   * <p>This is a best-effort check: failures while decoding the token or
   * accessing the table are logged and treated as "not revoked" so that
   * normal validation (signature, expiry, etc.) can still proceed.</p>
   */
  private static boolean isRevokedStsTempAccessKey(String sessionToken,
                                                   OzoneManager ozoneManager) {
    try {
      final OMMetadataManager metadataManager = ozoneManager.getMetadataManager();
      if (metadataManager == null) {
        return false;
      }

      final Table<String, String> revokedTable =
          metadataManager.getS3RevokedStsTokenTable();
      if (revokedTable == null) {
        return false;
      }

      // Decode without full validation; constructSTSToken performs basic
      // format checks and will throw OMException for invalid tokens.
      final STSTokenIdentifier stsToken =
          STSSecurityUtil.constructSTSToken(sessionToken);
      final String tempAccessKeyId = stsToken.getTempAccessKeyId();
      if (tempAccessKeyId == null || tempAccessKeyId.isEmpty()) {
        return false;
      }

      return revokedTable.getIfExist(tempAccessKeyId) != null;
    } catch (OMException e) {
      // Token parsing issues will be handled by the normal validation path.
      LOG.warn("Failed to decode STS token while checking revocation: {}",
          e.getMessage());
      return false;
    } catch (Exception e) {
      // Any DB or codec problem is treated as best-effort failure.
      LOG.warn("Failed to check STS revocation state: {}", e.getMessage());
      return false;
    }
  }

  /**
   * Construct and return {@link OzoneTokenIdentifier} from {@link OMRequest}.
   */
  private static OzoneTokenIdentifier constructS3Token(OMRequest omRequest) {
    S3Authentication auth = omRequest.getS3Authentication();
    OzoneTokenIdentifier s3Token = new OzoneTokenIdentifier();
    s3Token.setTokenType(S3AUTHINFO);
    s3Token.setStrToSign(auth.getStringToSign());
    s3Token.setSignature(auth.getSignature());
    s3Token.setAwsAccessId(auth.getAccessId());
    s3Token.setOwner(new Text(auth.getAccessId()));
    return s3Token;
  }
}

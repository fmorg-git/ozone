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

import com.google.protobuf.ServiceException;
import java.io.IOException;
import org.apache.hadoop.hdds.annotation.InterfaceAudience;
import org.apache.hadoop.hdds.annotation.InterfaceStability;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.exceptions.OMException;
import org.apache.hadoop.ozone.om.exceptions.OMLeaderNotReadyException;
import org.apache.hadoop.ozone.om.exceptions.OMNotLeaderException;
import org.apache.hadoop.security.token.SecretManager;
import org.apache.hadoop.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class which holds methods required for parse/validation of
 * STS Authentication Information which is part of OMRequest.
 */
@InterfaceAudience.Private
@InterfaceStability.Evolving
public final class STSSecurityUtil {
  private static final Logger LOG = LoggerFactory.getLogger(STSSecurityUtil.class);

  // Singleton instance of STSTokenVerifier
  private static volatile STSTokenVerifier tokenVerifier;
  private static final Object LOCK = new Object();

  private STSSecurityUtil() {
  }

  /**
   * Get or create the singleton STSTokenVerifier instance.
   * 
   * @param ozoneManager the OzoneManager instance
   * @return the singleton STSTokenVerifier
   */
  private static STSTokenVerifier getTokenVerifier(OzoneManager ozoneManager) {
    if (tokenVerifier == null) {
      synchronized (LOCK) {
        if (tokenVerifier == null) {
          tokenVerifier = new STSTokenVerifier(ozoneManager.getSecretKeyClient());
        }
      }
    }
    return tokenVerifier;
  }

  /**
   * Validate STS session token using the new STSTokenVerifier.
   * <p>
   * If validation is successful returns token details, else throw exception.
   *
   * @throws OMException validation failure
   *                     ServiceException    Server is not leader or not ready
   */
  public static void validateSTSToken(String sessionToken,
                                      OzoneManager ozoneManager)
      throws ServiceException, OMException {

    try {
      // Check leader status first - needed for consistency with existing behavior
      ozoneManager.checkLeaderStatus();
    } catch (OMNotLeaderException | OMLeaderNotReadyException e) {
      throw new ServiceException(e);
    }

    try {
      // Get singleton STS token verifier
      STSTokenVerifier verifier = getTokenVerifier(ozoneManager);

      // Verify the token
      verifier.verifyToken(sessionToken);
      
      // If we get here, the token is valid
    } catch (SecretManager.InvalidToken e) {
      if (e.getCause() != null &&
          (e.getCause().getClass() == OMNotLeaderException.class ||
          e.getCause().getClass() == OMLeaderNotReadyException.class)) {
        throw new ServiceException(e.getCause());
      }

      LOG.warn("STS token validation failed: {}", e.getMessage());
      throw new OMException("STS token validation failed: " + e.getMessage(),
          INVALID_TOKEN);
    } catch (IllegalArgumentException e) {
      LOG.warn("STS token parsing failed: {}", e.getMessage());
      throw new OMException("Invalid STS token format", INVALID_TOKEN);
    }
  }

  /**
   * Decode the supplied STS session token without validating it and return
   * the parsed {@link STSTokenIdentifier}. This helper can be used in
   * places where the caller only needs to inspect the token fields (for
   * example to get the original access key id) but does not require
   * full validation. Validation should still be performed at the
   * operation entrance via {@link #validateSTSToken(String, OzoneManager)}.
   */
  public static STSTokenIdentifier constructSTSToken(String sessionToken) throws OMException {
    try {
      Token<STSTokenIdentifier> token = new Token<>();
      token.decodeFromUrlString(sessionToken);
      return STSTokenIdentifier.readProtoBuf(token.getIdentifier());
    } catch (IOException | IllegalArgumentException e) {
      LOG.warn("Failed to decode/parse STS token: {}", e.getMessage());
      throw new OMException("Invalid STS token format", INVALID_TOKEN);
    }
  }

  /**
   * Convenience helper to obtain the original caller access key id from an
   * encoded STS session token string.
   *
   * @param sessionToken Base-64 encoded session token string
   * @return the original (long-lived) access key id of the caller, or null if
   *         it cannot be determined
   * @throws OMException if the token cannot be decoded / parsed.
   */
  public static String extractOriginalAccessKeyId(String sessionToken) throws OMException {
    final STSTokenIdentifier id = constructSTSToken(sessionToken);
    return id.getOriginalAccessKeyId();
  }
}


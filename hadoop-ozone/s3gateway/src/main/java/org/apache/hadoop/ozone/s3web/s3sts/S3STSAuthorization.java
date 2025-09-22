package org.apache.hadoop.ozone.s3web.s3sts;

import com.google.common.annotations.VisibleForTesting;
import org.apache.hadoop.ozone.s3.AuthorizationFilter;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;
import org.apache.hadoop.ozone.s3.signature.SignatureInfo;
import org.apache.hadoop.ozone.s3.signature.SignatureProcessor;
import org.apache.hadoop.ozone.s3.signature.StringToSignProducer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.*;
import static org.apache.hadoop.ozone.s3.util.S3Utils.wrapOS3Exception;

@S3AWSCredentialsEndpoint
@Provider
//@Priority(S3STSAuthorization.PRIORITY)
public class S3STSAuthorization implements ContainerRequestFilter {
//  public static final int PRIORITY = 100;
  private static final Logger LOG = LoggerFactory.getLogger(
      AuthorizationFilter.class);

  @Inject
  private SignatureProcessor signatureProcessor;

  @Inject
  private SignatureInfo signatureInfo;

  @Override
  public void filter(ContainerRequestContext context) throws IOException {
    try {
      LOG.info("REN: Authorization filter invoked");
      signatureInfo.initialize(signatureProcessor.parseSignature());
      if (signatureInfo.getVersion() == SignatureInfo.Version.V4) {
        signatureInfo.setStrToSign(
            StringToSignProducer.createSignatureBase(signatureInfo, context));
      } else {
        LOG.debug("Unsupported AWS signature version: {}",
            signatureInfo.getVersion());
        throw S3_AUTHINFO_CREATION_ERROR;
      }

      String awsAccessId = signatureInfo.getAwsAccessId();
      LOG.info("REN: signature: {}, strToSign: {}, awsAccessId: {}",
          signatureInfo.getSignature(), signatureInfo.getStringToSign(), awsAccessId);
      if (awsAccessId == null || awsAccessId.equals("")) {
        LOG.debug("Malformed s3 header. awsAccessID: {}", awsAccessId);
        throw ACCESS_DENIED;
      }
    } catch (OS3Exception ex) {
      LOG.debug("Error during Client Creation: ", ex);
      throw wrapOS3Exception(ex);
    } catch (Exception e) {
      // For any other critical errors during object creation throw Internal
      // error.
      LOG.debug("Error during Client Creation: ", e);
      throw wrapOS3Exception(
          S3ErrorTable.newError(INTERNAL_ERROR, null, e));
    }
  }

  @VisibleForTesting
  public void setSignatureParser(SignatureProcessor awsSignatureProcessor) {
    this.signatureProcessor = awsSignatureProcessor;
  }

  @VisibleForTesting
  public void setSignatureInfo(SignatureInfo signatureInfo) {
    this.signatureInfo = signatureInfo;
  }

  @VisibleForTesting
  public SignatureInfo getSignatureInfo() {
    return signatureInfo;
  }
}

package org.apache.hadoop.ozone.om.request.s3.security;

import java.io.IOException;
import org.apache.hadoop.ozone.om.OzoneManager;
import org.apache.hadoop.ozone.om.execution.flowcontrol.ExecutionContext;
import org.apache.hadoop.ozone.om.request.OMClientRequest;
import org.apache.hadoop.ozone.om.request.util.OmResponseUtil;
import org.apache.hadoop.ozone.om.response.OMClientResponse;
import org.apache.hadoop.ozone.om.response.s3.security.S3GetStsTokenResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.GetS3StsTokenRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.GetS3StsTokenResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMRequest;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handle S3 Get STS Token request.
 */
public class S3GetStsTokenRequest extends OMClientRequest {

  private static final Logger LOG =
      LoggerFactory.getLogger(S3GetStsTokenRequest.class);

  public S3GetStsTokenRequest(OMRequest omRequest) {
    super(omRequest);
  }

  @Override
  public OMRequest preExecute(OzoneManager ozoneManager) throws IOException {
    final GetS3StsTokenRequest s3GetS3StsToken =
        getOmRequest().getGetS3StsTokenRequest();

    OMRequest.Builder omRequest = OMRequest.newBuilder()
        .setGetS3StsTokenRequest(s3GetS3StsToken)
        .setCmdType(getOmRequest().getCmdType())
        .setClientId(getOmRequest().getClientId());

    return omRequest.build();
  }

  @Override
  public OMClientResponse validateAndUpdateCache(OzoneManager ozoneManager, ExecutionContext context) {
    OMResponse.Builder omResponse = OmResponseUtil.getOMResponseBuilder(
        getOmRequest());
    final GetS3StsTokenResponse.Builder getS3StsTokenResponse =
        GetS3StsTokenResponse.newBuilder().setAccessId("testAccessId");

    return new S3GetStsTokenResponse("testAccessId",
        omResponse.setGetS3StsTokenResponse(getS3StsTokenResponse).build());
  }
}

package org.apache.hadoop.ozone.om.response.s3.security;

import jakarta.annotation.Nonnull;
import org.apache.hadoop.hdds.utils.db.BatchOperation;
import org.apache.hadoop.ozone.om.OMMetadataManager;
import org.apache.hadoop.ozone.om.response.OMClientResponse;
import org.apache.hadoop.ozone.protocol.proto.OzoneManagerProtocolProtos.OMResponse;
import java.io.IOException;

/**
 * Response for GetS3StsToken request.
 */
public class S3GetStsTokenResponse extends OMClientResponse {
  private final String accessId;

  public S3GetStsTokenResponse(String accessId,
      @Nonnull OMResponse omResponse) {
    super(omResponse);
    this.accessId = accessId;
  }

  @Override
  public void addToDBBatch(OMMetadataManager omMetadataManager,
      BatchOperation batchOperation) throws IOException {
  }
}

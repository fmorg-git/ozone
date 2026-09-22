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

package org.apache.hadoop.ozone.s3.endpoint;

import java.io.IOException;
import java.io.InputStream;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.hadoop.ozone.audit.S3GAction;
import org.apache.hadoop.ozone.client.OzoneBucket;
import org.apache.hadoop.ozone.client.OzoneLifecycleConfiguration;
import org.apache.hadoop.ozone.om.exceptions.OMException;
import org.apache.hadoop.ozone.om.helpers.OmLifecycleConfiguration;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;

/**
 * Handler for S3 bucket lifecycle configuration operations.
 */

public class BucketLifecycleHandler extends BucketOperationHandler {

  @Override
  Response handleGetRequest(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    context.setAction(S3GAction.GET_BUCKET_LIFECYCLE);
    return getBucketLifecycleConfiguration(context, bucketName);
  }

  @Override
  Response handlePutRequest(
      S3RequestContext context, String bucketName, InputStream body)
      throws IOException, OS3Exception {
    context.setAction(S3GAction.PUT_BUCKET_LIFECYCLE);
    return putBucketLifecycleConfiguration(context, bucketName, body);
  }

  @Override
  Response handleDeleteRequest(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    context.setAction(S3GAction.DELETE_BUCKET_LIFECYCLE);
    return deleteBucketLifecycleConfiguration(context, bucketName);
  }

  public Response deleteBucketLifecycleConfiguration(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    deleteLifecycleConfiguration(context, bucketName);
    return Response.noContent().build();
  }

  protected void deleteLifecycleConfiguration(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    try {
      context.getBucket(bucketName).deleteLifecycleConfiguration();
    } catch (OMException ex) {
      // DeleteBucketLifecycle is idempotent: deleting a missing config
      // must still return 204, not 404 — same as normal key deletion.
      if (ex.getResult() != OMException.ResultCodes.LIFECYCLE_CONFIGURATION_NOT_FOUND) {
        throw S3ErrorTable.newError(bucketName, ex);
      }
    }
  }

  public Response putBucketLifecycleConfiguration(S3RequestContext context, String bucketName, InputStream body)
      throws IOException, OS3Exception {
    S3LifecycleConfiguration s3LifecycleConfiguration;
    OzoneBucket ozoneBucket = context.getBucket(bucketName);
    OmLifecycleConfiguration lcc;
    try {
      s3LifecycleConfiguration = new PutBucketLifecycleConfigurationUnmarshaller().readFrom(body);
      lcc = s3LifecycleConfiguration.toOmLifecycleConfiguration(ozoneBucket);
    } catch (WebApplicationException ex) {
      throw S3ErrorTable.newError(S3ErrorTable.MALFORMED_XML, bucketName);
    } catch (OMException ex) {
      // Rule validation rejects client-supplied values with INVALID_REQUEST, which the shared
      // translation maps to InvalidRequest. AWS S3 uses InvalidArgument for a rejected lifecycle
      // configuration, so only this validation step is remapped.
      if (ex.getResult() == OMException.ResultCodes.INVALID_REQUEST) {
        throw S3ErrorTable.newError(S3ErrorTable.INVALID_ARGUMENT, bucketName, ex).withMessage(ex.getMessage());
      }
      throw S3ErrorTable.newError(bucketName, ex);
    }

    try {
      ozoneBucket.setLifecycleConfiguration(lcc);
    } catch (OMException ex) {
      // OM raises INVALID_REQUEST for server-side conditions as well, such as a bucket layout
      // mismatch, so its result codes keep the shared translation instead of being remapped.
      if (ex.getResult() == OMException.ResultCodes.INVALID_REQUEST) {
        throw S3ErrorTable.newError(bucketName, ex).withMessage(ex.getMessage());
      }
      throw S3ErrorTable.newError(bucketName, ex);
    }
    return Response.ok().build();
  }

  public Response getBucketLifecycleConfiguration(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    OzoneLifecycleConfiguration ozoneLifecycleConfiguration =
        getLifecycleConfiguration(context, bucketName);
    return Response.ok(S3LifecycleConfiguration.fromOzoneLifecycleConfiguration(
        ozoneLifecycleConfiguration), MediaType.APPLICATION_XML_TYPE).build();
  }

  protected OzoneLifecycleConfiguration getLifecycleConfiguration(
      S3RequestContext context, String bucketName) throws IOException, OS3Exception {
    try {
      OzoneBucket ozoneBucket = context.getBucket(bucketName);
      return ozoneBucket.getLifecycleConfiguration();
    } catch (OMException ex) {
      if (ex.getResult() == OMException.ResultCodes.LIFECYCLE_CONFIGURATION_NOT_FOUND) {
        throw S3ErrorTable.newError(
            S3ErrorTable.NO_SUCH_LIFECYCLE_CONFIGURATION, bucketName);
      }
      throw ex;
    }
  }
}

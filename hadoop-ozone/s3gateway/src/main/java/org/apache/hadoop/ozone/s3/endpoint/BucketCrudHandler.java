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
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import org.apache.hadoop.ozone.audit.S3GAction;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.http.HttpStatus;

/**
 * Handler for default bucket CRUD operations.
 * Implements PUT (create bucket) and DELETE operations when no
 * subresource query parameters are present.
 *
 * This handler processes bucket-level requests that do not target
 * specific subresources (such as {@code ?acl}, {@code ?uploads},
 * {@code ?delete} or {@code ?tagging}), which are handled by dedicated handlers.
 *
 * This handler extends EndpointBase to inherit all required functionality
 * (configuration, headers, request context, audit logging, metrics, etc.).
 */
public class BucketCrudHandler extends BucketOperationHandler {

  /**
   * Handle PUT /{bucket} for bucket creation.
   */
  @Override
  Response handlePutRequest(S3RequestContext context, String bucketName, InputStream body)
      throws IOException, OS3Exception {

    context.setAction(S3GAction.CREATE_BUCKET);
    // CreateBucket has no existing bucket to read an owner from, so AWS ignores
    // x-amz-expected-bucket-owner here. Satisfy the router's invariant directly.

    try {
      getClient().getObjectStore().createS3Bucket(bucketName);
      getMetrics().updateCreateBucketSuccessStats(context.getStartNanos());
      return Response.status(HttpStatus.SC_OK)
          .header(HttpHeaders.LOCATION, "/" + bucketName)
          .build();
    } catch (Exception e) {
      getMetrics().updateCreateBucketFailureStats(context.getStartNanos());
      throw e;
    }
  }

  /**
   * Handle DELETE /{bucket} for bucket deletion.
   */
  @Override
  Response handleDeleteRequest(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {

    context.setAction(S3GAction.DELETE_BUCKET);

    try {
        context.getVolume().deleteBucket(bucketName);
    } catch (Exception ex) {
      getMetrics().updateDeleteBucketFailureStats(context.getStartNanos());
      throw ex;
    }

    getMetrics().updateDeleteBucketSuccessStats(context.getStartNanos());
    return Response
        .status(HttpStatus.SC_NO_CONTENT)
        .build();
  }
}

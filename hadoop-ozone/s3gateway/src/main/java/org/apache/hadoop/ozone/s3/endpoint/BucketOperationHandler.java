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
import javax.ws.rs.core.Response;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;

/**
 * Handler for a specific S3 bucket operation or subresource (e.g. {@code ?acl},
 * {@code ?lifecycle}). The {@link BucketOperationHandlerRouter} dispatches requests
 * to the appropriate handler instance.
 */
abstract class BucketOperationHandler extends EndpointBase {

  /** Handle PUT /{bucket} for the routed subresource or plain bucket operation. */
  Response handlePutRequest(S3RequestContext context, String bucketName, InputStream body)
      throws IOException, OS3Exception {
    return null;
  }

  /** Handle GET /{bucket} for the routed subresource or plain bucket operation. */
  Response handleGetRequest(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    return null;
  }

  Response handleDeleteRequest(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    return null;
  }

  BucketOperationHandler copyDependenciesFrom(EndpointBase other) {
    other.copyDependenciesTo(this);
    return this;
  }
}

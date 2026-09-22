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

import static org.apache.hadoop.ozone.s3.util.S3Utils.wrapOS3Exception;

import java.io.IOException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;
import org.apache.hadoop.ozone.s3.commontypes.RequestParameters;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;

/**
 * Resolves S3 subresource operations after resource matching and before
 * JAX-RS unmarshals a request body.
 */
@Provider
final class S3OperationRequestFilter implements ContainerRequestFilter {

  @Context
  private ResourceInfo resourceInfo;

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    final ResourceLevel resourceLevel = resourceLevelOf(resourceInfo.getResourceClass());
    if (resourceLevel == null) {
      return;
    }

    try {
      final S3Operation operation = S3Operation.resolve(
          resourceLevel, requestContext.getMethod(), RequestParameters.of(
              requestContext.getUriInfo().getQueryParameters()));
      requestContext.setProperty(S3Operation.class.getName(), operation);
    } catch (OS3Exception ex) {
      throw wrapOS3Exception(ex);
    }
  }

  private static ResourceLevel resourceLevelOf(Class<?> resourceClass) {
    if (RootEndpoint.class.equals(resourceClass)) {
      return ResourceLevel.SERVICE;
    }
    if (BucketEndpoint.class.equals(resourceClass)) {
      return ResourceLevel.BUCKET;
    }
    if (ObjectEndpoint.class.equals(resourceClass)) {
      return ResourceLevel.OBJECT;
    }
    return null;
  }
}

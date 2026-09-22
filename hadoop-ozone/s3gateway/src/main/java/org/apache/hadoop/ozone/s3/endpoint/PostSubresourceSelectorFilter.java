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
import java.util.Set;
import javax.annotation.Priority;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.ext.Provider;
import org.apache.hadoop.ozone.s3.ClientIpFilter;
import org.apache.hadoop.ozone.s3.S3GatewayHttpServer;
import org.apache.hadoop.ozone.s3.endpoint.SubresourceRouteTable.Scope;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;

/** Validates POST subresource routing before JAX-RS unmarshals the request body. */
@Provider
@PreMatching
@Priority(PostSubresourceSelectorFilter.PRIORITY)
public class PostSubresourceSelectorFilter implements ContainerRequestFilter {

  public static final int PRIORITY = ClientIpFilter.PRIORITY +
      S3GatewayHttpServer.FILTER_PRIORITY_DO_AFTER;

  /**
   * Content-Type used to select the POST resource method annotated with
   * {@code @Consumes(INVALID_POST_SUBRESOURCE_MARKER)}. JAX-RS prefers the method with the most
   * specific {@code @Consumes} match, so a rewritten request reaches that method instead of the
   * body-consuming POST methods, which accept any media type.
   */
  public static final String INVALID_POST_SUBRESOURCE_MARKER = "ozone/invalid-post-subresource";

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    if (!HttpMethod.POST.equals(requestContext.getMethod())) {
      return;
    }

    // Use the encoded path because JAX-RS matches path templates against encoded
    // segments. Decoding here could classify an encoded slash as an object separator.
    final String path = requestContext.getUriInfo().getPath(false);
    if (!hasS3ResourcePath(path)) {
      return;
    }

    final Set<String> queryKeys = requestContext.getUriInfo().getQueryParameters().keySet();
    try {
      SubresourceRouteTable.validatePostSubresourceSelectors(queryKeys, scopeOf(path));
    } catch (final OS3Exception ignored) {
      // Route to an untyped endpoint so owner verification and audit happen before
      // the selector error is returned, without unmarshalling the original body.
      requestContext.getHeaders().putSingle(HttpHeaders.CONTENT_TYPE, INVALID_POST_SUBRESOURCE_MARKER);
    }
  }

  private static boolean hasS3ResourcePath(String path) {
    if (path != null) {
      for (int i = 0; i < path.length(); i++) {
        if (path.charAt(i) != '/') {
          return true;
        }
      }
    }
    return false;
  }

  /** A path with a key segment after the bucket segment targets {@link ObjectEndpoint}. */
  private static Scope scopeOf(String path) {
    int start = 0;
    while (start < path.length() && path.charAt(start) == '/') {
      start++;
    }
    final int separator = path.indexOf('/', start);
    return separator >= start && separator + 1 < path.length() ? Scope.OBJECT : Scope.BUCKET;
  }
}

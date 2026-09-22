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
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.Response;
import org.apache.hadoop.ozone.s3.endpoint.SubresourceRouteTable.Scope;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;

/** HashMap-based dispatcher for bucket subresource operations. */
final class BucketOperationHandlerRouter extends BucketOperationHandler {

  private final SubresourceRouteTable<BucketOperationHandler> routes;
  private final Set<BucketOperationHandler> handlers;

  private BucketOperationHandlerRouter(
      SubresourceRouteTable<BucketOperationHandler> routes,
      Set<BucketOperationHandler> handlers) {
    this.routes = routes;
    this.handlers = Collections.unmodifiableSet(new HashSet<>(handlers));
  }

  void refreshDependencies(BucketEndpoint endpoint) {
    for (BucketOperationHandler handler : handlers) {
      endpoint.copyDependenciesTo(handler);
    }
    endpoint.copyDependenciesTo(this);
  }

  @Override
  Response handleDeleteRequest(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    return dispatch(HttpMethod.DELETE, context, bucketName, null);
  }

  @Override
  Response handleGetRequest(S3RequestContext context, String bucketName)
      throws IOException, OS3Exception {
    return dispatch(HttpMethod.GET, context, bucketName, null);
  }

  @Override
  Response handlePutRequest(S3RequestContext context, String bucketName, InputStream body)
      throws IOException, OS3Exception {
    return dispatch(HttpMethod.PUT, context, bucketName, body);
  }

  private Response dispatch(String method, S3RequestContext context, String bucketName, InputStream body)
      throws IOException, OS3Exception {
    final BucketOperationHandler handler;
    try {
      handler = routes.resolve(method, queryParams().keySet());
    } catch (OS3Exception e) {
      SubresourceS3GAction.applyRouterFailure(context, method, e, subresourceScope());
      getMetrics().updateSubresourceRoutingFailureStats(context.getStartNanos());
      verifyBucketOwner(context, bucketName);
      throw e;
    }
    final Response response;
    if (HttpMethod.PUT.equals(method)) {
      response = handler.handlePutRequest(context, bucketName, body);
    } else if (HttpMethod.GET.equals(method)) {
      response = handler.handleGetRequest(context, bucketName);
    } else if (HttpMethod.DELETE.equals(method)) {
      response = handler.handleDeleteRequest(context, bucketName);
    } else {
      throw new IllegalStateException("unsupported method: " + method);
    }
    if (response == null) {
      throw new IllegalStateException("handler returned null for " + method);
    }
    if (!context.isOwnerVerified()) {
      throw new IllegalStateException(
          handler.getClass().getSimpleName() + " did not call verifyBucketOwner for " + method);
    }
    return response;
  }

  static final class Builder {
    private final SubresourceRouteTable.Builder<BucketOperationHandler> routes =
        new SubresourceRouteTable.Builder<>();
    private final Set<BucketOperationHandler> handlers = new HashSet<>();

    Builder get(String selector, BucketOperationHandler handler) {
      validateAction(HttpMethod.GET, selector);
      routes.route(HttpMethod.GET, selector, handler);
      handlers.add(handler);
      return this;
    }

    Builder put(String selector, BucketOperationHandler handler) {
      validateAction(HttpMethod.PUT, selector);
      routes.route(HttpMethod.PUT, selector, handler);
      handlers.add(handler);
      return this;
    }

    Builder delete(String selector, BucketOperationHandler handler) {
      validateAction(HttpMethod.DELETE, selector);
      routes.route(HttpMethod.DELETE, selector, handler);
      handlers.add(handler);
      return this;
    }

    Builder plainGet(BucketOperationHandler handler, Set<String> allowedQueryParameters) {
      routes.plain(HttpMethod.GET, handler, allowedQueryParameters);
      handlers.add(handler);
      return this;
    }

    Builder plainPut(BucketOperationHandler handler, Set<String> allowedQueryParameters) {
      routes.plain(HttpMethod.PUT, handler, allowedQueryParameters);
      handlers.add(handler);
      return this;
    }

    Builder plainDelete(BucketOperationHandler handler, Set<String> allowedQueryParameters) {
      routes.plain(HttpMethod.DELETE, handler, allowedQueryParameters);
      handlers.add(handler);
      return this;
    }

    BucketOperationHandlerRouter build() {
      return new BucketOperationHandlerRouter(routes.build(), handlers);
    }

    private static void validateAction(String method, String selector) {
      if (SubresourceS3GAction.resolve(method, selector, Scope.BUCKET) == null) {
        throw new IllegalArgumentException("missing bucket subresource action for " + method + " " + selector);
      }
    }
  }
}

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

import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.INVALID_ARGUMENT;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.NOT_IMPLEMENTED;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.newError;

import com.google.common.collect.ImmutableSet;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.ozone.s3.endpoint.ObjectEndpoint.ObjectRequestContext;
import org.apache.hadoop.ozone.s3.endpoint.SubresourceRouteTable.Scope;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.util.S3Consts.QueryParams;

/** HashMap-based dispatcher for object subresource operations. */
final class ObjectOperationHandlerRouter extends ObjectOperationHandler {

  /** PUT parameters that target an object subresource. */
  private static final Set<String> PUT_SUBRESOURCE_SELECTORS = ImmutableSet.of(QueryParams.ACL, QueryParams.TAGGING);

  /** PUT parameters that target a multipart part upload; ambiguous alongside a subresource. */
  private static final Set<String> PUT_PART_UPLOAD_PARAMS =
      ImmutableSet.of(QueryParams.UPLOAD_ID, QueryParams.PART_NUMBER);

  private final SubresourceRouteTable<ObjectOperationHandler> routes;
  private final Set<ObjectOperationHandler> handlers;

  private ObjectOperationHandlerRouter(
      SubresourceRouteTable<ObjectOperationHandler> routes,
      Set<ObjectOperationHandler> handlers) {
    this.routes = routes;
    this.handlers = Collections.unmodifiableSet(new HashSet<>(handlers));
  }

  void refreshDependencies(ObjectEndpoint endpoint) {
    for (ObjectOperationHandler handler : handlers) {
      endpoint.copyDependenciesTo(handler);
    }
    endpoint.copyDependenciesTo(this);
  }

  @Override
  Response handleDeleteRequest(ObjectRequestContext context, String keyName) throws IOException, OS3Exception {
    return dispatch(HttpMethod.DELETE, context, keyName, null);
  }

  @Override
  Response handleGetRequest(ObjectRequestContext context, String keyName) throws IOException, OS3Exception {
    return dispatch(HttpMethod.GET, context, keyName, null);
  }

  @Override
  Response handlePutRequest(ObjectRequestContext context, String keyName, InputStream body)
      throws IOException, OS3Exception {
    return dispatch(HttpMethod.PUT, context, keyName, body);
  }

  private Response dispatch(String method, ObjectRequestContext context, String keyName, InputStream body)
      throws IOException, OS3Exception {
    final Set<String> queryKeys = queryParams().keySet();
    final ObjectOperationHandler handler;
    try {
      validateObjectQueryParams(method, queryKeys);
      handler = routes.resolve(method, queryKeys);
    } catch (OS3Exception e) {
      SubresourceS3GAction.applyRouterFailure(context, method, e, subresourceScope());
      getMetrics().updateSubresourceRoutingFailureStats(context.getStartNanos());
      recordRouterValidationFailure(context, method, e);
      verifyBucketOwner(context);
      throw e;
    }
    final Response response;
    if (HttpMethod.PUT.equals(method)) {
      response = handler.handlePutRequest(context, keyName, body);
    } else if (HttpMethod.GET.equals(method)) {
      response = handler.handleGetRequest(context, keyName);
    } else if (HttpMethod.DELETE.equals(method)) {
      response = handler.handleDeleteRequest(context, keyName);
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

  private void recordRouterValidationFailure(ObjectRequestContext context, String method, OS3Exception e) {
    if (!INVALID_ARGUMENT.getCode().equals(e.getCode())
        || !QueryParams.UPLOAD_ID.equals(e.getResource())) {
      return;
    }
    if (HttpMethod.GET.equals(method) && queryParams().containsKey(QueryParams.UPLOAD_ID)) {
      getMetrics().updateListPartsFailureStats(context.getStartNanos());
    } else if (HttpMethod.DELETE.equals(method) && queryParams().containsKey(QueryParams.UPLOAD_ID)) {
      getMetrics().updateAbortMultipartUploadFailureStats(context.getStartNanos());
    }
  }

  private void validateObjectQueryParams(String method, Set<String> queryKeys) throws OS3Exception {
    if (queryKeys.contains(QueryParams.VERSION_ID)) {
      // Ozone has no object versioning, so versionId is rejected even where AWS accepts it as a
      // companion parameter (for example GetObjectAttributes) rather than silently serving the
      // current version.
      throw newError(NOT_IMPLEMENTED, QueryParams.VERSION_ID);
    }
    final boolean put = HttpMethod.PUT.equals(method);
    if (put && SubresourceRouteTable.hasMultipleSubresourceSelectors(queryKeys)) {
      throw SubresourceRouteTable.conflictingSubresourceSelectors(queryKeys);
    }
    if (put && hasPutSubresourceConflict(queryKeys)) {
      // partNumber is not a subresource selector, so these combinations are not caught above.
      final Set<String> conflictingParameters = new HashSet<>(PUT_SUBRESOURCE_SELECTORS);
      conflictingParameters.addAll(PUT_PART_UPLOAD_PARAMS);
      conflictingParameters.retainAll(queryKeys);
      throw SubresourceRouteTable.conflictingQueryParameters(conflictingParameters);
    }
    if (queryKeys.contains(QueryParams.UPLOAD_ID)
        && StringUtils.isEmpty(queryParams().get(QueryParams.UPLOAD_ID))) {
      throw newError(INVALID_ARGUMENT, QueryParams.UPLOAD_ID);
    }
    if (put && queryKeys.contains(QueryParams.PART_NUMBER) && !queryKeys.contains(QueryParams.UPLOAD_ID)) {
      throw newError(INVALID_ARGUMENT, QueryParams.PART_NUMBER);
    }
    if (HttpMethod.DELETE.equals(method) && queryKeys.contains(QueryParams.PART_NUMBER)) {
      throw newError(NOT_IMPLEMENTED, QueryParams.PART_NUMBER);
    }
  }

  private static boolean hasPutSubresourceConflict(Set<String> queryKeys) {
    return !Collections.disjoint(queryKeys, PUT_SUBRESOURCE_SELECTORS)
        && !Collections.disjoint(queryKeys, PUT_PART_UPLOAD_PARAMS);
  }

  static final class Builder {
    private final SubresourceRouteTable.Builder<ObjectOperationHandler> routes =
        new SubresourceRouteTable.Builder<>();
    private final Set<ObjectOperationHandler> handlers = new HashSet<>();

    Builder get(String selector, ObjectOperationHandler handler) {
      validateAction(HttpMethod.GET, selector);
      routes.route(HttpMethod.GET, selector, handler);
      handlers.add(handler);
      return this;
    }

    Builder put(String selector, ObjectOperationHandler handler) {
      validateAction(HttpMethod.PUT, selector);
      routes.route(HttpMethod.PUT, selector, handler);
      handlers.add(handler);
      return this;
    }

    Builder delete(String selector, ObjectOperationHandler handler) {
      validateAction(HttpMethod.DELETE, selector);
      routes.route(HttpMethod.DELETE, selector, handler);
      handlers.add(handler);
      return this;
    }

    Builder plainGet(ObjectOperationHandler handler, Set<String> allowedQueryParameters) {
      routes.plain(HttpMethod.GET, handler, allowedQueryParameters);
      handlers.add(handler);
      return this;
    }

    Builder plainPut(ObjectOperationHandler handler, Set<String> allowedQueryParameters) {
      routes.plain(HttpMethod.PUT, handler, allowedQueryParameters);
      handlers.add(handler);
      return this;
    }

    Builder plainDelete(ObjectOperationHandler handler, Set<String> allowedQueryParameters) {
      routes.plain(HttpMethod.DELETE, handler, allowedQueryParameters);
      handlers.add(handler);
      return this;
    }

    ObjectOperationHandlerRouter build() {
      return new ObjectOperationHandlerRouter(routes.build(), handlers);
    }

    private static void validateAction(String method, String selector) {
      if (SubresourceS3GAction.resolve(method, selector, Scope.OBJECT) == null) {
        throw new IllegalArgumentException("missing object subresource action for " + method + " " + selector);
      }
    }
  }
}

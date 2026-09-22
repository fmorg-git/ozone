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

import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.METHOD_NOT_ALLOWED;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.NOT_IMPLEMENTED;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.newConflictingQueryParameters;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.newError;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.ws.rs.HttpMethod;
import org.apache.hadoop.ozone.audit.S3GAction;
import org.apache.hadoop.ozone.s3.commontypes.RequestParameters;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;

/**
 * Catalog of S3 operations implemented by the Gateway and request resolver.
 *
 * <p>Identifies a routable S3 Gateway request (HTTP method + resource level + optional subresource selector).
 * Header/body variants (e.g. CopyObject) and non-routed endpoints (STS) are not represented here.</p>
 *
 * <p>The catalog intentionally contains only operations with a handler. Known
 * AWS operations without a handler are resolved by {@link #resolve} and return
 * {@code NotImplemented}; they must not fall through to a base operation.</p>
 */
enum S3Operation {

  // Service operations.
  LIST_BUCKETS(ResourceLevel.SERVICE, HttpMethod.GET, S3GAction.LIST_S3_BUCKETS, "ListBuckets"),

  // Bucket operations.
  CREATE_BUCKET(ResourceLevel.BUCKET, HttpMethod.PUT, S3GAction.CREATE_BUCKET, "CreateBucket"),
  DELETE_BUCKET(ResourceLevel.BUCKET, HttpMethod.DELETE, S3GAction.DELETE_BUCKET, "DeleteBucket"),
  DELETE_BUCKET_LIFECYCLE(S3Subresource.BUCKET_LIFECYCLE, HttpMethod.DELETE, S3GAction.DELETE_BUCKET_LIFECYCLE),
  DELETE_BUCKET_TAGGING(S3Subresource.BUCKET_TAGGING, HttpMethod.DELETE, S3GAction.DELETE_BUCKET_TAGGING),
  DELETE_OBJECTS(S3Subresource.BUCKET_DELETE, HttpMethod.POST, S3GAction.MULTI_DELETE),
  GET_BUCKET_ACL(S3Subresource.BUCKET_ACL, HttpMethod.GET, S3GAction.GET_ACL),
  GET_BUCKET_LIFECYCLE(S3Subresource.BUCKET_LIFECYCLE, HttpMethod.GET, S3GAction.GET_BUCKET_LIFECYCLE),
  GET_BUCKET_TAGGING(S3Subresource.BUCKET_TAGGING, HttpMethod.GET, S3GAction.GET_BUCKET_TAGGING),
  HEAD_BUCKET(ResourceLevel.BUCKET, HttpMethod.HEAD, S3GAction.HEAD_BUCKET, "HeadBucket"),
  LIST_MULTIPART_UPLOADS(S3Subresource.BUCKET_UPLOADS, HttpMethod.GET, S3GAction.LIST_MULTIPART_UPLOAD),
  LIST_OBJECTS(ResourceLevel.BUCKET, HttpMethod.GET, S3GAction.GET_BUCKET, "ListObjectsV2"),
  PUT_BUCKET_ACL(S3Subresource.BUCKET_ACL, HttpMethod.PUT, S3GAction.PUT_ACL),
  PUT_BUCKET_LIFECYCLE(S3Subresource.BUCKET_LIFECYCLE, HttpMethod.PUT, S3GAction.PUT_BUCKET_LIFECYCLE),
  PUT_BUCKET_TAGGING(S3Subresource.BUCKET_TAGGING, HttpMethod.PUT, S3GAction.PUT_BUCKET_TAGGING),

  // Object operations.
  ABORT_MULTIPART_UPLOAD(S3Subresource.OBJECT_UPLOAD_ID, HttpMethod.DELETE, S3GAction.ABORT_MULTIPART_UPLOAD),
  COMPLETE_MULTIPART_UPLOAD(S3Subresource.OBJECT_UPLOAD_ID, HttpMethod.POST, S3GAction.COMPLETE_MULTIPART_UPLOAD),
  CREATE_MULTIPART_UPLOAD(S3Subresource.OBJECT_UPLOADS, HttpMethod.POST, S3GAction.INIT_MULTIPART_UPLOAD),
  DELETE_OBJECT(ResourceLevel.OBJECT, HttpMethod.DELETE, S3GAction.DELETE_KEY, "DeleteObject"),
  DELETE_OBJECT_TAGGING(S3Subresource.OBJECT_TAGGING, HttpMethod.DELETE, S3GAction.DELETE_OBJECT_TAGGING),
  GET_OBJECT(ResourceLevel.OBJECT, HttpMethod.GET, S3GAction.GET_KEY, "GetObject"),
  GET_OBJECT_ATTRIBUTES(S3Subresource.OBJECT_ATTRIBUTES, HttpMethod.GET, S3GAction.GET_OBJECT_ATTRIBUTES),
  GET_OBJECT_TAGGING(S3Subresource.OBJECT_TAGGING, HttpMethod.GET, S3GAction.GET_OBJECT_TAGGING),
  HEAD_OBJECT(ResourceLevel.OBJECT, HttpMethod.HEAD, S3GAction.HEAD_KEY, "HeadObject"),
  LIST_PARTS(S3Subresource.OBJECT_UPLOAD_ID, HttpMethod.GET, S3GAction.LIST_PARTS),
  PUT_OBJECT(ResourceLevel.OBJECT, HttpMethod.PUT, S3GAction.CREATE_KEY, "PutObject"),
  PUT_OBJECT_TAGGING(S3Subresource.OBJECT_TAGGING, HttpMethod.PUT, S3GAction.PUT_OBJECT_TAGGING),
  UPLOAD_PART(S3Subresource.OBJECT_UPLOAD_ID, HttpMethod.PUT, S3GAction.CREATE_MULTIPART_KEY);

  private static final Map<String, S3Operation> BY_KEY = buildLookup();

  private final ResourceLevel resourceLevel;
  private final String method;
  private final String selector;
  private final S3GAction auditAction;
  private final String awsOperationName;

  S3Operation(S3Subresource subresource, String method, S3GAction auditAction) {
    if (!subresource.supports(method)) {
      throw new IllegalArgumentException(subresource + " does not support HTTP method " + method);
    }
    this.resourceLevel = subresource.getResourceLevel();
    this.method = method;
    this.selector = subresource.getSelector();
    this.auditAction = auditAction;
    this.awsOperationName = subresource.getOperationName(method);
  }

  S3Operation(ResourceLevel resourceLevel, String method, S3GAction auditAction, String awsOperationName) {
    this.resourceLevel = resourceLevel;
    this.method = method;
    this.selector = null;
    this.auditAction = auditAction;
    this.awsOperationName = awsOperationName;
  }

  /**
   * Resolves a request before its JAX-RS method unmarshals the request body.
   *
   * <p>Only query parameters in {@link S3Subresource} participate in routing.
   * Unknown parameters are deliberately ignored.</p>
   */
  static S3Operation resolve(ResourceLevel resourceLevel, String method, RequestParameters queryParameters)
      throws OS3Exception {
    final String normalizedMethod = method.toUpperCase(Locale.ROOT);
    final Set<String> selectors = new TreeSet<>();
    for (final String key : queryParameters.keySet()) {
      if (S3Subresource.isSelector(key)) {
        selectors.add(key);
      }
    }

    if (selectors.size() > 1) {
      throw newConflictingQueryParameters(selectors);
    }

    if (selectors.size() == 1) {
      final String selector = selectors.iterator().next();
      final S3Operation operation = BY_KEY.get(key(resourceLevel, normalizedMethod, selector));
      if (operation != null) {
        return operation;
      }

      final S3Subresource subresource = S3Subresource.resolve(resourceLevel, selector);
      if (subresource != null && subresource.supports(normalizedMethod)) {
        throw newError(NOT_IMPLEMENTED, subresource.getOperationName(normalizedMethod));
      }
      throw newError(METHOD_NOT_ALLOWED, selector);
    }

    final S3Operation operation = BY_KEY.get(key(resourceLevel, normalizedMethod, null));
    if (operation == null) {
      throw newError(METHOD_NOT_ALLOWED, normalizedMethod);
    }
    return operation;
  }

  ResourceLevel getResourceLevel() {
    return resourceLevel;
  }

  String getMethod() {
    return method;
  }

  String getSelector() {
    return selector;
  }

  S3GAction getAuditAction() {
    return auditAction;
  }

  String getAwsOperationName() {
    return awsOperationName;
  }

  private static Map<String, S3Operation> buildLookup() {
    final Map<String, S3Operation> lookup = new HashMap<>();
    for (final S3Operation operation : values()) {
      final String key = key(operation.resourceLevel, operation.method, operation.selector);
      if (lookup.put(key, operation) != null) {
        throw new IllegalStateException("Duplicate S3 operation: " + key);
      }
    }
    return lookup;
  }

  private static String key(ResourceLevel resourceLevel, String method, String selector) {
    return resourceLevel + "\u0000" + method + "\u0000" + selector;
  }
}

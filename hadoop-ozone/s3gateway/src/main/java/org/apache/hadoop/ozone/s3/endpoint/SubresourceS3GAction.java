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

import jakarta.annotation.Nullable;
import javax.ws.rs.HttpMethod;
import org.apache.hadoop.ozone.audit.S3GAction;
import org.apache.hadoop.ozone.s3.endpoint.SubresourceRouteTable.Scope;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.util.S3Consts.QueryParams;

/** Maps subresource selectors to {@link S3GAction} for router-level failures. */
final class SubresourceS3GAction {

  private SubresourceS3GAction() {
  }

  /** Sets the audit action implied by a router failure, based on the selector it reported. */
  static void applyRouterFailure(S3RequestContext context, String httpMethod, OS3Exception exception, Scope scope) {
    if (SubresourceRouteTable.isConflictingQueryParameters(exception)) {
      context.setAction(S3GAction.UNSUPPORTED_SUBRESOURCE);
      return;
    }
    final String selector = exception.getResource() != null
        ? exception.getResource() : exception.getArgumentValue();
    apply(context, httpMethod, selector, scope);
  }

  static void apply(S3RequestContext context, String httpMethod, @Nullable String selector, Scope scope) {
    if (selector == null || !QueryParams.SUBRESOURCE_SELECTORS.contains(selector)) {
      return;
    }
    final S3GAction action = resolve(httpMethod, selector, scope);
    context.setAction(action != null ? action : S3GAction.UNSUPPORTED_SUBRESOURCE);
  }

  @Nullable
  static S3GAction resolve(String httpMethod, String selector, Scope scope) {
    final boolean objectEndpoint = scope.isObject();
    switch (selector) {
    case QueryParams.ACL:
      if (objectEndpoint) {
        if (HttpMethod.GET.equals(httpMethod)) {
          return S3GAction.GET_OBJECT_ACL;
        }
        if (HttpMethod.PUT.equals(httpMethod)) {
          return S3GAction.PUT_OBJECT_ACL;
        }
      } else {
        if (HttpMethod.GET.equals(httpMethod)) {
          return S3GAction.GET_ACL;
        }
        if (HttpMethod.PUT.equals(httpMethod)) {
          return S3GAction.PUT_ACL;
        }
      }
      return null;
    case QueryParams.TAGGING:
      if (objectEndpoint) {
        if (HttpMethod.GET.equals(httpMethod)) {
          return S3GAction.GET_OBJECT_TAGGING;
        }
        if (HttpMethod.PUT.equals(httpMethod)) {
          return S3GAction.PUT_OBJECT_TAGGING;
        }
        if (HttpMethod.DELETE.equals(httpMethod)) {
          return S3GAction.DELETE_OBJECT_TAGGING;
        }
      } else {
        if (HttpMethod.GET.equals(httpMethod)) {
          return S3GAction.GET_BUCKET_TAGGING;
        }
        if (HttpMethod.PUT.equals(httpMethod)) {
          return S3GAction.PUT_BUCKET_TAGGING;
        }
        if (HttpMethod.DELETE.equals(httpMethod)) {
          return S3GAction.DELETE_BUCKET_TAGGING;
        }
      }
      return null;
    case QueryParams.LIFECYCLE:
      if (objectEndpoint) {
        return null;
      }
      if (HttpMethod.GET.equals(httpMethod)) {
        return S3GAction.GET_BUCKET_LIFECYCLE;
      }
      if (HttpMethod.PUT.equals(httpMethod)) {
        return S3GAction.PUT_BUCKET_LIFECYCLE;
      }
      if (HttpMethod.DELETE.equals(httpMethod)) {
        return S3GAction.DELETE_BUCKET_LIFECYCLE;
      }
      return null;
    case QueryParams.LOCATION:
      if (!objectEndpoint && HttpMethod.GET.equals(httpMethod)) {
        return S3GAction.GET_BUCKET_LOCATION;
      }
      return null;
    case QueryParams.UPLOADS:
      if (!objectEndpoint && HttpMethod.GET.equals(httpMethod)) {
        return S3GAction.LIST_MULTIPART_UPLOAD;
      }
      return null;
    case QueryParams.UPLOAD_ID:
      if (!objectEndpoint) {
        return null;
      }
      if (HttpMethod.GET.equals(httpMethod)) {
        return S3GAction.LIST_PARTS;
      }
      if (HttpMethod.DELETE.equals(httpMethod)) {
        return S3GAction.ABORT_MULTIPART_UPLOAD;
      }
      return null;
    case QueryParams.TORRENT:
      if (objectEndpoint && HttpMethod.GET.equals(httpMethod)) {
        return S3GAction.GET_OBJECT_TORRENT;
      }
      return null;
    case QueryParams.ATTRIBUTES:
      if (objectEndpoint && HttpMethod.GET.equals(httpMethod)) {
        return S3GAction.GET_OBJECT_ATTRIBUTES;
      }
      return null;
    default:
      return null;
    }
  }
}

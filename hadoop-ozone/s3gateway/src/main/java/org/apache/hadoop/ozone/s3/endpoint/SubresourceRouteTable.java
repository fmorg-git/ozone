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
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.METHOD_NOT_ALLOWED;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.NOT_IMPLEMENTED;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.newError;
import static org.apache.hadoop.ozone.s3.util.S3Consts.QueryParams;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;

/**
 * Immutable per-HTTP-method dispatch table for S3 subresource query parameters.
 */
final class SubresourceRouteTable<H> {

  /** {@code ArgumentName} reported by {@link #conflictingQueryParameters(Set)}. */
  private static final String CONFLICTING_PARAMETERS_ARGUMENT = "ResourceType";

  /** Whether a subresource selector applies to a bucket-level or an object-level S3 operation. */
  enum Scope {
    BUCKET,
    OBJECT;

    boolean isObject() {
      return this == OBJECT;
    }
  }

  private final Map<String, MethodRoutes<H>> routesByMethod;

  private SubresourceRouteTable(Map<String, MethodRoutes<H>> routesByMethod) {
    this.routesByMethod = routesByMethod;
  }

  H resolve(String method, Set<String> queryKeys) throws OS3Exception {
    final MethodRoutes<H> routes = routesByMethod.get(method);
    if (routes == null) {
      throw newError(NOT_IMPLEMENTED, method);
    }
    return routes.resolve(queryKeys);
  }

  static boolean isNoise(String key) {
    if (key == null) {
      return true;
    }
    // S3 ignores x- prefixed query parameters for request processing.
    return key.toLowerCase(Locale.ROOT).startsWith("x-");
  }

  static void validateSubresourceSelectors(Set<String> queryKeys, Set<String> allowedSelectors)
      throws OS3Exception {
    if (allowedSelectors.isEmpty()) {
      // A required selector cannot be satisfied by an empty set, so this is always a wiring bug.
      throw new IllegalArgumentException("allowedSelectors must not be empty");
    }
    validateSelectors(queryKeys, allowedSelectors, true);
  }

  static void validateOptionalSubresourceSelectors(Set<String> queryKeys, Set<String> allowedSelectors)
      throws OS3Exception {
    validateSelectors(queryKeys, allowedSelectors, false);
  }

  private static void validateSelectors(
      Set<String> queryKeys, Set<String> allowedSelectors, boolean selectorRequired)
      throws OS3Exception {
    // More than one selector is always ambiguous, so at most one selector remains below and an
    // unsupported one can never be accompanied by an allowed one.
    final Set<String> selectors = subresourceSelectors(queryKeys);
    if (selectors.size() > 1) {
      throw conflictingSubresourceSelectors(selectors);
    }
    if (selectors.isEmpty()) {
      if (selectorRequired) {
        throw newError(INVALID_ARGUMENT, allowedSelectors.iterator().next());
      }
      return;
    }

    final String selector = selectors.iterator().next();
    if (!allowedSelectors.contains(selector)) {
      throw newError(NOT_IMPLEMENTED, selector);
    }
  }

  static boolean hasMultipleSubresourceSelectors(Set<String> queryKeys) {
    return subresourceSelectors(queryKeys).size() > 1;
  }

  static OS3Exception conflictingSubresourceSelectors(Set<String> queryKeys) {
    return conflictingQueryParameters(subresourceSelectors(queryKeys));
  }

  static OS3Exception conflictingQueryParameters(Set<String> queryKeys) {
    final Set<String> parameters = new TreeSet<>(queryKeys);
    final String firstSelector = parameters.iterator().next();
    final OS3Exception exception = newError(INVALID_ARGUMENT, firstSelector);
    exception.setErrorMessage("Conflicting query string parameters: "
        + String.join(", ", parameters));
    return exception;
  }

  /**
   * Whether the error reports an ambiguous combination of query parameters rather than a single
   * selector, in which case no concrete audit action can be attributed to the request.
   */
  static boolean isConflictingQueryParameters(OS3Exception exception) {
    return INVALID_ARGUMENT.getCode().equals(exception.getCode())
        && exception.getErrorMessage() != null
        && exception.getErrorMessage().startsWith("Conflicting query string parameters:");
  }

  private static Set<String> subresourceSelectors(Set<String> queryKeys) {
    return subresourceSelectors(queryKeys, QueryParams.SUBRESOURCE_SELECTORS, Collections.emptySet());
  }

  /** Returns the subresource selectors present on the request, in a deterministic order. */
  private static Set<String> subresourceSelectors(
      Set<String> queryKeys, Set<String> knownSelectors, Set<String> ignoredSelectors) {
    final Set<String> selectors = new TreeSet<>();
    for (final String key : queryKeys) {
      if (!isNoise(key) && knownSelectors.contains(key) && !ignoredSelectors.contains(key)) {
        selectors.add(key);
      }
    }
    return selectors;
  }

  static boolean isBareObjectPost(Set<String> queryKeys) {
    return subresourceSelectors(queryKeys).isEmpty();
  }

  static void validatePostSubresourceSelectors(Set<String> queryKeys, Scope scope) throws OS3Exception {
    if (scope.isObject() && isBareObjectPost(queryKeys)) {
      throw newError(METHOD_NOT_ALLOWED);
    }
    final String requiredSelector;
    if (!scope.isObject()) {
      requiredSelector = QueryParams.DELETE;
    } else if (queryKeys.contains(QueryParams.UPLOADS)) {
      requiredSelector = QueryParams.UPLOADS;
    } else {
      requiredSelector = QueryParams.UPLOAD_ID;
    }
    validateSubresourceSelectors(queryKeys, Collections.singleton(requiredSelector));
  }

  static final class MethodRoutes<H> {
    private final H plainHandler;
    private final Map<String, H> handlersBySelector;
    private final Set<String> plainParameters;
    private final Set<String> subresourceSelectors;

    private MethodRoutes(
        H plainHandler,
        Map<String, H> handlersBySelector,
        Set<String> plainParameters,
        Set<String> subresourceSelectors) {
      this.plainHandler = plainHandler;
      this.handlersBySelector = handlersBySelector;
      this.plainParameters = plainParameters;
      this.subresourceSelectors = subresourceSelectors;
    }

    H resolve(Set<String> queryKeys) throws OS3Exception {
      // Routed selectors are always part of subresourceSelectors and never a plain parameter of
      // the same method (enforced by Builder), so a request can match at most one handler here.
      final Set<String> selectors = subresourceSelectors(queryKeys, subresourceSelectors, plainParameters);
      if (selectors.size() > 1) {
        throw conflictingQueryParameters(selectors);
      }
      if (selectors.isEmpty()) {
        return plainHandler;
      }

      final String selector = selectors.iterator().next();
      final H handler = handlersBySelector.get(selector);
      if (handler == null) {
        throw newError(NOT_IMPLEMENTED, selector);
      }
      return handler;
    }
  }

  static final class Builder<H> {
    private final Map<String, MutableMethodRoutes<H>> routesByMethod = new HashMap<>();

    Builder<H> route(String method, String selector, H handler) {
      validateMethod(method);
      if (StringUtils.isEmpty(selector)) {
        throw new IllegalArgumentException("selector must not be empty");
      }
      if (handler == null) {
        throw new IllegalArgumentException("handler must not be null");
      }

      final MutableMethodRoutes<H> routes = routesFor(method);
      if (routes.handlersBySelector.containsKey(selector)) {
        throw new IllegalArgumentException("duplicate route for " + method + " " + selector);
      }
      if (routes.plainParameters.contains(selector)) {
        throw new IllegalArgumentException("selector conflicts with plain parameter: " + selector);
      }
      routes.handlersBySelector.put(selector, handler);
      return this;
    }

    Builder<H> plain(String method, H handler, Set<String> allowedQueryParameters) {
      validateMethod(method);
      if (handler == null) {
        throw new IllegalArgumentException("plain handler must not be null");
      }

      final MutableMethodRoutes<H> routes = routesFor(method);
      if (routes.plainHandler != null) {
        throw new IllegalArgumentException("duplicate plain handler for " + method);
      }
      routes.plainHandler = handler;
      if (allowedQueryParameters != null) {
        for (String parameter : allowedQueryParameters) {
          if (StringUtils.isEmpty(parameter)) {
            throw new IllegalArgumentException("plain parameter must not be empty");
          }
          if (routes.handlersBySelector.containsKey(parameter)) {
            throw new IllegalArgumentException("plain parameter conflicts with selector: " + parameter);
          }
          routes.plainParameters.add(parameter);
        }
      }
      return this;
    }

    SubresourceRouteTable<H> build() {
      if (routesByMethod.isEmpty()) {
        throw new IllegalStateException("no routes configured");
      }

      final Set<String> allSelectors = new HashSet<>(QueryParams.SUBRESOURCE_SELECTORS);
      for (MutableMethodRoutes<H> routes : routesByMethod.values()) {
        allSelectors.addAll(routes.handlersBySelector.keySet());
      }
      // Shared across methods: the table is immutable, so every MethodRoutes can hold the same set.
      final Set<String> subresourceSelectors = ImmutableSet.copyOf(allSelectors);

      final Map<String, MethodRoutes<H>> builtRoutes = new HashMap<>();
      for (Map.Entry<String, MutableMethodRoutes<H>> entry : routesByMethod.entrySet()) {
        final MutableMethodRoutes<H> routes = entry.getValue();
        if (routes.plainHandler == null) {
          throw new IllegalStateException("missing plain handler for " + entry.getKey());
        }
        builtRoutes.put(entry.getKey(), new MethodRoutes<>(
            routes.plainHandler,
            ImmutableMap.copyOf(routes.handlersBySelector),
            ImmutableSet.copyOf(routes.plainParameters),
            subresourceSelectors));
      }
      return new SubresourceRouteTable<>(ImmutableMap.copyOf(builtRoutes));
    }

    private MutableMethodRoutes<H> routesFor(String method) {
      return routesByMethod.computeIfAbsent(method, ignored -> new MutableMethodRoutes<>());
    }

    private static void validateMethod(String method) {
      if (StringUtils.isEmpty(method)) {
        throw new IllegalArgumentException("method must not be empty");
      }
    }

    private static final class MutableMethodRoutes<H> {
      private H plainHandler;
      private final Map<String, H> handlersBySelector = new HashMap<>();
      private final Set<String> plainParameters = new HashSet<>();
    }
  }
}

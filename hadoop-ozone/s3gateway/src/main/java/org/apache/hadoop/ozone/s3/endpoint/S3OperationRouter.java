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

import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.NOT_IMPLEMENTED;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.newError;

import java.util.EnumMap;
import java.util.Map;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;

/**
 * Maps each resolved S3 operation to exactly one operation handler.
 */
final class S3OperationRouter<H extends EndpointBase> {

  private final Map<S3Operation, H> handlers;

  private S3OperationRouter(Map<S3Operation, H> handlers) {
    this.handlers = handlers;
  }

  H handlerFor(S3Operation operation) throws OS3Exception {
    final H handler = handlers.get(operation);
    if (handler == null) {
      throw newError(NOT_IMPLEMENTED, operation.getAwsOperationName());
    }
    return handler;
  }

  static <H extends EndpointBase> Builder<H> newBuilder(ResourceLevel resourceLevel, H endpoint) {
    return new Builder<>(resourceLevel, endpoint);
  }

  static final class Builder<H extends EndpointBase> {
    private final ResourceLevel resourceLevel;
    private final H endpoint;
    private final EnumMap<S3Operation, H> handlers = new EnumMap<>(S3Operation.class);

    private Builder(ResourceLevel resourceLevel, H endpoint) {
      this.resourceLevel = resourceLevel;
      this.endpoint = endpoint;
    }

    Builder<H> register(S3Operation operation, H handler) {
      if (operation.getResourceLevel() != resourceLevel) {
        throw new IllegalArgumentException("Expected " + resourceLevel + " operation: " + operation);
      }
      if (handlers.put(operation, copyDependencies(handler)) != null) {
        throw new IllegalArgumentException("Duplicate handler for operation: " + operation);
      }
      return this;
    }

    Builder<H> registerAll(H handler) {
      for (final S3Operation operation : S3Operation.values()) {
        if (operation.getResourceLevel() == resourceLevel) {
          register(operation, handler);
        }
      }
      return this;
    }

    S3OperationRouter<H> build() {
      for (final S3Operation operation : S3Operation.values()) {
        if (operation.getResourceLevel() == resourceLevel
            && !handlers.containsKey(operation)) {
          throw new IllegalStateException("No handler registered for operation: " + operation);
        }
      }
      return new S3OperationRouter<>(handlers);
    }

    private H copyDependencies(H handler) {
      endpoint.copyDependenciesTo(handler);
      return handler;
    }
  }
}

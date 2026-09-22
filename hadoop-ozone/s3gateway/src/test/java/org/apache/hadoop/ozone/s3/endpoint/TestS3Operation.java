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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MultivaluedHashMap;
import org.apache.hadoop.ozone.s3.commontypes.RequestParameters;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for explicit S3 operation resolution.
 */
public class TestS3Operation {

  @Test
  public void resolvesBaseOperationAndIgnoresUnknownParameters() {
    final RequestParameters parameters = parameters(
        "foo", "bar", "x-id", "GetObject", "X-Amz-Algorithm", "AWS4-HMAC-SHA256",
        "versionId", "ignored", "partNumber", "1");

    assertEquals(S3Operation.GET_OBJECT, S3Operation.resolve(ResourceLevel.OBJECT, HttpMethod.GET, parameters));
  }

  @Test
  public void resolvesImplementedSubresources() {
    assertEquals(
        S3Operation.GET_BUCKET_ACL, S3Operation.resolve(ResourceLevel.BUCKET, HttpMethod.GET, parameters("acl", "")));
    assertEquals(
        S3Operation.PUT_OBJECT_TAGGING, S3Operation.resolve(ResourceLevel.OBJECT, HttpMethod.PUT, parameters(
            "tagging", "")));
    assertEquals(
        S3Operation.UPLOAD_PART, S3Operation.resolve(ResourceLevel.OBJECT, HttpMethod.PUT, parameters(
            "uploadId", "upload-1", "partNumber", "1")));
  }

  @Test
  public void resolvesEveryCatalogOperation() {
    for (S3Operation expected : S3Operation.values()) {
      final RequestParameters parameters = expected.getSelector() == null ? parameters() :
          parameters(expected.getSelector(), "");
      assertEquals(expected, S3Operation.resolve(expected.getResourceLevel(), expected.getMethod(), parameters));
    }
  }

  @Test
  public void returnsNotImplementedForKnownMissingOperations() {
    assertNotImplemented(ResourceLevel.OBJECT, HttpMethod.GET, "acl");
    assertNotImplemented(ResourceLevel.OBJECT, HttpMethod.GET, "torrent");
    assertNotImplemented(ResourceLevel.BUCKET, HttpMethod.GET, "location");
    assertNotImplemented(ResourceLevel.BUCKET, HttpMethod.GET, "policy");
  }

  @Test
  public void returnsMethodNotAllowedWhenAwsHasNoOperationForMethod() {
    assertMethodNotAllowed(ResourceLevel.OBJECT, HttpMethod.HEAD, "acl");
    assertMethodNotAllowed(ResourceLevel.OBJECT, HttpMethod.GET, "website");
    assertMethodNotAllowed(ResourceLevel.OBJECT, HttpMethod.POST);
  }

  @Test
  public void rejectsConflictingSubresourcesWithAwsFields() {
    final OS3Exception exception = assertThrows(
        OS3Exception.class, () -> S3Operation.resolve(ResourceLevel.OBJECT, HttpMethod.POST, parameters(
            "uploadId", "upload-1", "website", "")));

    assertEquals(INVALID_ARGUMENT.getCode(), exception.getCode());
    assertEquals("ResourceType", exception.getArgumentName());
    assertEquals("uploadId", exception.getArgumentValue());
    assertTrue(exception.getErrorMessage().contains("Conflicting query string parameters: uploadId, website"));

    exception.setRequestId("request-id");
    final String xml = exception.toXml();
    final String expected = String.format(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>%n"
            + "<Error>%n"
            + "  <Code>InvalidArgument</Code>%n"
            + "  <Message>Conflicting query string parameters: uploadId, website</Message>%n"
            + "  <ArgumentName>ResourceType</ArgumentName>%n"
            + "  <ArgumentValue>uploadId</ArgumentValue>%n"
            + "  <RequestId>request-id</RequestId>%n"
            + "</Error>%n");
    assertEquals(expected, xml);
    assertFalse(xml.contains("<Resource>"));
  }

  private static void assertNotImplemented(ResourceLevel resourceLevel, String method, String selector) {
    final OS3Exception exception = assertThrows(
        OS3Exception.class, () -> S3Operation.resolve(resourceLevel, method, parameters(selector, "")));
    assertEquals(NOT_IMPLEMENTED.getCode(), exception.getCode());
  }

  private static void assertMethodNotAllowed(ResourceLevel resourceLevel, String method, String selector) {
    final OS3Exception exception = assertThrows(
        OS3Exception.class, () -> S3Operation.resolve(resourceLevel, method, parameters(selector, "")));
    assertEquals(METHOD_NOT_ALLOWED.getCode(), exception.getCode());
  }

  private static void assertMethodNotAllowed(ResourceLevel resourceLevel, String method) {
    final OS3Exception exception = assertThrows(
        OS3Exception.class, () -> S3Operation.resolve(resourceLevel, method, parameters()));
    assertEquals(METHOD_NOT_ALLOWED.getCode(), exception.getCode());
  }

  private static RequestParameters parameters(String... keyValuePairs) {
    final MultivaluedHashMap<String, String> values = new MultivaluedHashMap<>();
    for (int i = 0; i < keyValuePairs.length; i += 2) {
      values.putSingle(keyValuePairs[i], keyValuePairs[i + 1]);
    }
    return RequestParameters.of(values);
  }
}

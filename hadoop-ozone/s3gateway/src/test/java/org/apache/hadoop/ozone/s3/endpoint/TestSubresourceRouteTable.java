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
import static org.apache.hadoop.ozone.s3.util.S3Consts.QueryParams;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.common.collect.ImmutableSet;
import java.util.Collections;
import javax.ws.rs.HttpMethod;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link SubresourceRouteTable}. */
public class TestSubresourceRouteTable {

  private static final String PLAIN = "plain";
  private static final String ACL = "acl";
  private static final String TAGGING = "tagging";
  private static final String UPLOAD_ID = "uploadId";

  @Test
  public void registeredSelectorReturnsHandler() throws OS3Exception {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, ACL, ACL)
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build();

    assertEquals(ACL, routes.resolve(HttpMethod.GET, ImmutableSet.of(ACL)));
  }

  @Test
  public void knownSubresourceSelectorReturnsNotImplemented() {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> routes.resolve(HttpMethod.GET, ImmutableSet.of("website")));
    assertEquals(NOT_IMPLEMENTED.getCode(), ex.getCode());
  }

  @Test
  public void arbitraryUnknownParameterReturnsPlainHandler() throws OS3Exception {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build();

    assertEquals(PLAIN, routes.resolve(HttpMethod.GET, ImmutableSet.of("foo")));
  }

  @Test
  public void modifierOnlyRequestReturnsPlainHandler() throws OS3Exception {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .plain(HttpMethod.GET, PLAIN, ImmutableSet.of(QueryParams.PREFIX))
        .build();

    assertEquals(PLAIN, routes.resolve(HttpMethod.GET, ImmutableSet.of(QueryParams.PREFIX)));
  }

  @Test
  public void knownSubresourceWithPlainModifierReturnsNotImplemented() {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .plain(HttpMethod.GET, PLAIN, ImmutableSet.of(QueryParams.PREFIX))
        .build();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> routes.resolve(HttpMethod.GET, ImmutableSet.of(QueryParams.PREFIX, "website")));
    assertEquals(NOT_IMPLEMENTED.getCode(), ex.getCode());
  }

  @Test
  public void arbitraryUnknownParameterWithPlainModifierReturnsPlainHandler() throws OS3Exception {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .plain(HttpMethod.GET, PLAIN, ImmutableSet.of(QueryParams.PREFIX))
        .build();

    assertEquals(PLAIN, routes.resolve(HttpMethod.GET, ImmutableSet.of(QueryParams.PREFIX, "foo")));
  }

  @Test
  public void noiseParametersPreservePlainRouting() throws OS3Exception {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build();

    assertEquals(PLAIN, routes.resolve(HttpMethod.GET,
        ImmutableSet.of("X-Amz-Algorithm", "x-id", "x-amz-credential")));
  }

  @Test
  public void selectorWithCompanionParamsRoutesToSelectorHandler() throws OS3Exception {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, UPLOAD_ID, UPLOAD_ID)
        .plain(HttpMethod.GET, PLAIN, ImmutableSet.of(QueryParams.MAX_PARTS, QueryParams.PART_NUMBER_MARKER))
        .plain(HttpMethod.PUT, PLAIN, ImmutableSet.of(UPLOAD_ID, QueryParams.PART_NUMBER))
        .build();

    assertEquals(UPLOAD_ID, routes.resolve(HttpMethod.GET,
        ImmutableSet.of(UPLOAD_ID, QueryParams.MAX_PARTS, QueryParams.PART_NUMBER_MARKER)));
  }

  @Test
  public void twoRegisteredSelectorsReturnInvalidArgument() {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, ACL, ACL)
        .route(HttpMethod.GET, TAGGING, TAGGING)
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> routes.resolve(HttpMethod.GET, ImmutableSet.of(ACL, TAGGING)));
    assertEquals(INVALID_ARGUMENT.getCode(), ex.getCode());
  }

  @Test
  public void uploadIdIsGetSelectorButPutPlainModifier() throws OS3Exception {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, UPLOAD_ID, UPLOAD_ID)
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .plain(HttpMethod.PUT, PLAIN, ImmutableSet.of(UPLOAD_ID, QueryParams.PART_NUMBER))
        .build();

    assertEquals(UPLOAD_ID, routes.resolve(HttpMethod.GET, ImmutableSet.of(UPLOAD_ID)));
    assertEquals(PLAIN, routes.resolve(HttpMethod.PUT,
        ImmutableSet.of(UPLOAD_ID, QueryParams.PART_NUMBER)));
  }

  @Test
  public void duplicateSelectorFailsAtBuildTime() {
    assertThrows(IllegalArgumentException.class, () -> new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, ACL, ACL)
        .route(HttpMethod.GET, ACL, TAGGING)
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build());
  }

  @Test
  public void duplicatePlainHandlerFailsAtBuildTime() {
    assertThrows(IllegalArgumentException.class, () -> new SubresourceRouteTable.Builder<String>()
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .plain(HttpMethod.GET, ACL, Collections.emptySet())
        .build());
  }

  @Test
  public void selectorModifierConflictFailsAtBuildTime() {
    assertThrows(IllegalArgumentException.class, () -> new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.PUT, UPLOAD_ID, UPLOAD_ID)
        .plain(HttpMethod.PUT, PLAIN, ImmutableSet.of(UPLOAD_ID))
        .build());
  }

  @Test
  public void missingPlainHandlerFailsAtBuildTime() {
    assertThrows(IllegalStateException.class, () -> new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, ACL, ACL)
        .build());
  }

  @Test
  public void emptySelectorFailsAtBuildTime() {
    assertThrows(IllegalArgumentException.class, () -> new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, "", ACL));
  }

  @Test
  public void unconfiguredMethodReturnsNotImplemented() {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> routes.resolve(HttpMethod.PUT, Collections.emptySet()));
    assertEquals(NOT_IMPLEMENTED.getCode(), ex.getCode());
  }

  @Test
  public void isNoiseMatchesCaseInsensitively() {
    assertEquals(true, SubresourceRouteTable.isNoise("X-Id"));
    assertEquals(true, SubresourceRouteTable.isNoise("x-amz-date"));
    assertEquals(true, SubresourceRouteTable.isNoise("x-custom"));
    assertEquals(false, SubresourceRouteTable.isNoise("prefix"));
  }

  @Test
  public void registeredSelectorOnOtherMethodReturnsNotImplemented() {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, QueryParams.TORRENT, QueryParams.TORRENT)
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .plain(HttpMethod.PUT, PLAIN, Collections.emptySet())
        .build();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> routes.resolve(HttpMethod.PUT, ImmutableSet.of(QueryParams.TORRENT)));
    assertEquals(NOT_IMPLEMENTED.getCode(), ex.getCode());
  }

  @Test
  public void postWithoutRequiredSelectorReturnsInvalidArgument() {
    assertThrows(OS3Exception.class, () -> SubresourceRouteTable.validateSubresourceSelectors(
        Collections.emptySet(), ImmutableSet.of(QueryParams.DELETE)));
  }

  @Test
  public void objectPostWithoutSelectorReturnsMethodNotAllowed() {
    final OS3Exception exception = assertThrows(OS3Exception.class,
        () -> SubresourceRouteTable.validatePostSubresourceSelectors(
            Collections.emptySet(), SubresourceRouteTable.Scope.OBJECT));
    assertEquals(METHOD_NOT_ALLOWED.getCode(), exception.getCode());
    assertEquals(METHOD_NOT_ALLOWED.getHttpCode(), exception.getHttpCode());
  }

  @Test
  public void requiredSelectorWithoutAllowedSelectorsFailsFast() {
    assertThrows(IllegalArgumentException.class, () -> SubresourceRouteTable.validateSubresourceSelectors(
        ImmutableSet.of(QueryParams.DELETE), Collections.emptySet()));
  }

  @Test
  public void postWithUnsupportedSelectorReturnsInvalidArgument() {
    OS3Exception ex = assertThrows(OS3Exception.class, () -> SubresourceRouteTable.validateSubresourceSelectors(
        ImmutableSet.of(QueryParams.DELETE, "website"), ImmutableSet.of(QueryParams.DELETE)));
    assertEquals(INVALID_ARGUMENT.getCode(), ex.getCode());
    assertEquals("Conflicting query string parameters: delete, website", ex.getErrorMessage());
    assertEquals("ResourceType", ex.getArgumentName());
    assertEquals("delete", ex.getArgumentValue());
  }

  @Test
  public void postWithOnlyUnsupportedSelectorReturnsNotImplemented() {
    OS3Exception ex = assertThrows(OS3Exception.class, () -> SubresourceRouteTable.validateSubresourceSelectors(
        ImmutableSet.of("restore"), ImmutableSet.of(QueryParams.UPLOAD_ID)));
    assertEquals(NOT_IMPLEMENTED.getCode(), ex.getCode());
    assertEquals("restore", ex.getResource());
  }

  @Test
  public void headWithSubresourceReturnsNotImplemented() {
    final OS3Exception exception = assertThrows(OS3Exception.class,
        () -> SubresourceRouteTable.validateOptionalSubresourceSelectors(
            ImmutableSet.of(QueryParams.TAGGING), Collections.emptySet()));

    assertEquals(NOT_IMPLEMENTED.getCode(), exception.getCode());
    assertEquals(QueryParams.TAGGING, exception.getResource());
  }

  @Test
  public void headIgnoresNonSubresourceQueryParameters() {
    assertDoesNotThrow(() -> SubresourceRouteTable.validateOptionalSubresourceSelectors(
        ImmutableSet.of("foo", "X-Amz-Signature"), Collections.emptySet()));
  }

  @Test
  public void headAllowsConfiguredOptionalSelector() {
    assertDoesNotThrow(() -> SubresourceRouteTable.validateOptionalSubresourceSelectors(
        ImmutableSet.of(QueryParams.VERSION_ID), ImmutableSet.of(QueryParams.VERSION_ID)));
  }

  @Test
  public void headWithAllowedAndUnsupportedSelectorsReturnsInvalidArgument() {
    final OS3Exception exception = assertThrows(OS3Exception.class,
        () -> SubresourceRouteTable.validateOptionalSubresourceSelectors(
            ImmutableSet.of(QueryParams.VERSION_ID, QueryParams.TAGGING),
            ImmutableSet.of(QueryParams.VERSION_ID)));

    assertEquals(INVALID_ARGUMENT.getCode(), exception.getCode());
    assertEquals("Conflicting query string parameters: tagging, versionId", exception.getErrorMessage());
    assertEquals(QueryParams.TAGGING, exception.getArgumentValue());
  }

  @Test
  public void ambiguousRegisteredSelectorsReportDeterministically() {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, ACL, ACL)
        .route(HttpMethod.GET, TAGGING, TAGGING)
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> routes.resolve(HttpMethod.GET, ImmutableSet.of(ACL, TAGGING)));
    assertEquals(INVALID_ARGUMENT.getCode(), ex.getCode());
    assertEquals("Conflicting query string parameters: acl, tagging", ex.getErrorMessage());
    assertEquals(ACL, ex.getArgumentValue());
  }

  @Test
  public void implementedSelectorWithUnimplementedSelectorReturnsInvalidArgument() {
    SubresourceRouteTable<String> routes = new SubresourceRouteTable.Builder<String>()
        .route(HttpMethod.GET, ACL, ACL)
        .plain(HttpMethod.GET, PLAIN, Collections.emptySet())
        .build();

    OS3Exception ex = assertThrows(OS3Exception.class,
        () -> routes.resolve(HttpMethod.GET, ImmutableSet.of(ACL, "website")));
    assertEquals(INVALID_ARGUMENT.getCode(), ex.getCode());
    assertEquals("Conflicting query string parameters: acl, website", ex.getErrorMessage());
    assertEquals(ACL, ex.getArgumentValue());
  }
}

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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.apache.hadoop.ozone.s3.endpoint.EndpointTestUtils.assertErrorResponse;
import static org.apache.hadoop.ozone.s3.endpoint.EndpointTestUtils.assertSucceeds;
import static org.apache.hadoop.ozone.s3.endpoint.EndpointTestUtils.delete;
import static org.apache.hadoop.ozone.s3.endpoint.EndpointTestUtils.get;
import static org.apache.hadoop.ozone.s3.endpoint.EndpointTestUtils.initiateMultipartUpload;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.BUCKET_OWNER_MISMATCH;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.INVALID_ARGUMENT;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.NOT_IMPLEMENTED;
import static org.apache.hadoop.ozone.s3.util.S3Consts.EXPECTED_BUCKET_OWNER_HEADER;
import static org.apache.hadoop.ozone.s3.util.S3Consts.QueryParams;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Collections;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.ozone.OzoneConfigKeys;
import org.apache.hadoop.ozone.audit.S3GAction;
import org.apache.hadoop.ozone.client.BucketArgs;
import org.apache.hadoop.ozone.client.OzoneClient;
import org.apache.hadoop.ozone.client.OzoneClientStub;
import org.apache.hadoop.ozone.client.io.OzoneOutputStream;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.exception.S3ErrorTable;
import org.apache.hadoop.ozone.s3.metrics.S3GatewayMetrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Smoke tests for HashMap-based object and bucket subresource routing. */
public class TestSubresourceRouting {

  private static final String BUCKET_NAME = "routing-bucket";
  private static final String KEY_NAME = "routing-key";
  private static final String CONTENT = "routing-content";

  private ObjectEndpoint objectEndpoint;
  private BucketEndpoint bucketEndpoint;

  @BeforeEach
  public void setup() throws IOException {
    final OzoneClient clientStub = new OzoneClientStub();
    clientStub.getObjectStore().createS3Bucket(BUCKET_NAME);
    try (OzoneOutputStream output =
        clientStub.getObjectStore().getS3Bucket(BUCKET_NAME).createKey(KEY_NAME, CONTENT.length())) {
      output.write(CONTENT.getBytes(UTF_8));
    }

    objectEndpoint = EndpointBuilder.newObjectEndpointBuilder()
        .setClient(clientStub)
        .build();
    bucketEndpoint = EndpointBuilder.newBucketEndpointBuilder()
        .setClient(clientStub)
        .build();
  }

  @Test
  public void objectGetKnownSubresourceReturnsNotImplemented() {
    objectEndpoint.queryParamsForTest().set("website", "");

    assertErrorResponse(NOT_IMPLEMENTED, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }

  @Test
  public void objectGetArbitraryUnknownParameterStillSucceeds() throws OS3Exception, IOException {
    objectEndpoint.queryParamsForTest().set("foo", "bar");

    assertSucceeds(() -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }

  @Test
  public void bucketGetKnownSubresourceReturnsNotImplemented() {
    final S3GatewayMetrics metrics = bucketEndpoint.getMetrics();
    final long failuresBefore = metrics.getSubresourceRoutingFailure();
    bucketEndpoint.queryParamsForTest().set("policy", "");

    assertErrorResponse(NOT_IMPLEMENTED, () -> bucketEndpoint.get(BUCKET_NAME));
    assertEquals(1L, metrics.getSubresourceRoutingFailure() - failuresBefore);
  }

  @Test
  public void bucketGetArbitraryUnknownParameterStillListsObjects() throws OS3Exception, IOException {
    bucketEndpoint.queryParamsForTest().set("foo", "bar");

    assertSucceeds(() -> bucketEndpoint.get(BUCKET_NAME));
  }

  @Test
  public void objectDeleteAclReturnsNotImplemented() {
    objectEndpoint.queryParamsForTest().set(QueryParams.ACL, "");

    assertErrorResponse(NOT_IMPLEMENTED, () -> delete(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }

  @Test
  public void objectDeleteEmptyUploadIdReturnsInvalidArgument() {
    final S3GatewayMetrics metrics = objectEndpoint.getMetrics();
    final long failuresBefore = metrics.getAbortMultiPartUploadFailure();
    objectEndpoint.queryParamsForTest().set(QueryParams.UPLOAD_ID, "");

    final OS3Exception exception =
        assertErrorResponse(INVALID_ARGUMENT, () -> delete(objectEndpoint, BUCKET_NAME, KEY_NAME));
    assertEquals(QueryParams.UPLOAD_ID, exception.getResource());
    assertEquals(1L, metrics.getAbortMultiPartUploadFailure() - failuresBefore);
  }

  @Test
  public void objectGetEmptyUploadIdRecordsListPartsFailure() {
    final S3GatewayMetrics metrics = objectEndpoint.getMetrics();
    final long failuresBefore = metrics.getListPartsFailure();
    objectEndpoint.queryParamsForTest().set(QueryParams.UPLOAD_ID, "");

    final OS3Exception exception =
        assertErrorResponse(INVALID_ARGUMENT, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
    assertEquals(QueryParams.UPLOAD_ID, exception.getResource());
    assertEquals(1L, metrics.getListPartsFailure() - failuresBefore);
  }

  @Test
  public void objectListPartsValidatesAndClampsMaxParts() throws Exception {
    objectEndpoint.queryParamsForTest().set(QueryParams.UPLOAD_ID, "upload-id");
    objectEndpoint.queryParamsForTest().setInt(QueryParams.MAX_PARTS, -1);

    assertErrorResponse(INVALID_ARGUMENT, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));

    objectEndpoint.queryParamsForTest().unset(QueryParams.UPLOAD_ID);
    final String uploadId = initiateMultipartUpload(objectEndpoint, BUCKET_NAME, KEY_NAME);
    objectEndpoint.queryParamsForTest().set(QueryParams.UPLOAD_ID, uploadId);
    objectEndpoint.queryParamsForTest().setInt(QueryParams.MAX_PARTS, 1001);
    try (Response response = get(objectEndpoint, BUCKET_NAME, KEY_NAME)) {
      assertEquals(1000, ((ListPartsResponse) response.getEntity()).getMaxParts());
    }

    // AWS returns an empty page for max-parts=0 rather than an error.
    objectEndpoint.queryParamsForTest().setInt(QueryParams.MAX_PARTS, 0);
    try (Response response = get(objectEndpoint, BUCKET_NAME, KEY_NAME)) {
      final ListPartsResponse parts = (ListPartsResponse) response.getEntity();
      assertEquals(0, parts.getMaxParts());
      assertTrue(parts.getPartList().isEmpty());
    }
  }

  @Test
  public void objectListPartsRejectsInvalidPartNumberMarker() {
    objectEndpoint.queryParamsForTest().set(QueryParams.UPLOAD_ID, "upload-id");
    objectEndpoint.queryParamsForTest().set(QueryParams.PART_NUMBER_MARKER, "-1");

    assertErrorResponse(INVALID_ARGUMENT, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));

    objectEndpoint.queryParamsForTest().set(QueryParams.PART_NUMBER_MARKER, "not-a-number");
    assertErrorResponse(INVALID_ARGUMENT, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }


  @Test
  public void objectDeletePartNumberReturnsNotImplementedWithoutDeletingObject() throws OS3Exception, IOException {
    objectEndpoint.queryParamsForTest().setInt(QueryParams.PART_NUMBER, 1);

    final OS3Exception exception =
        assertErrorResponse(NOT_IMPLEMENTED, () -> delete(objectEndpoint, BUCKET_NAME, KEY_NAME));
    assertEquals(QueryParams.PART_NUMBER, exception.getResource());

    objectEndpoint.queryParamsForTest().unset(QueryParams.PART_NUMBER);
    assertSucceeds(() -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }

  @Test
  public void objectPutPartNumberWithoutUploadIdReturnsInvalidArgument() {
    objectEndpoint.queryParamsForTest().setInt(QueryParams.PART_NUMBER, 1);
    when(objectEndpoint.getContext().getMethod()).thenReturn(HttpMethod.PUT);

    final OS3Exception exception =
        assertErrorResponse(INVALID_ARGUMENT, () -> objectEndpoint.put(BUCKET_NAME, KEY_NAME, null));
    assertEquals(QueryParams.PART_NUMBER, exception.getResource());
  }

  @Test
  public void objectPutTaggingAndUploadIdReturnsConflictingParameters() {
    objectEndpoint.queryParamsForTest().set(QueryParams.TAGGING, "");
    objectEndpoint.queryParamsForTest().set(QueryParams.UPLOAD_ID, "upload-id");
    when(objectEndpoint.getContext().getMethod()).thenReturn(HttpMethod.PUT);

    final OS3Exception exception =
        assertErrorResponse(INVALID_ARGUMENT, () -> objectEndpoint.put(BUCKET_NAME, KEY_NAME, null));

    assertEquals("Conflicting query string parameters: tagging, uploadId", exception.getErrorMessage());
  }

  @Test
  public void objectPutTaggingAndPartNumberUsesUnsupportedAction() throws IOException {
    final ObjectOperationHandler handler = new ObjectOperationHandler() {
    };
    final ObjectOperationHandlerRouter router = new ObjectOperationHandlerRouter.Builder()
        .plainPut(handler, Collections.emptySet())
        .build();
    router.copyDependenciesFrom(objectEndpoint);
    objectEndpoint.queryParamsForTest().set(QueryParams.TAGGING, "");
    objectEndpoint.queryParamsForTest().setInt(QueryParams.PART_NUMBER, 1);
    final ObjectEndpoint.ObjectRequestContext context =
        objectEndpoint.new ObjectRequestContext(S3GAction.CREATE_KEY, BUCKET_NAME);

    assertThrows(OS3Exception.class,
        () -> router.handlePutRequest(context, KEY_NAME, null));

    assertEquals(S3GAction.UNSUPPORTED_SUBRESOURCE, context.getAction());
  }

  @Test
  public void objectGetAnnotationReturnsNotImplemented() {
    objectEndpoint.queryParamsForTest().set("annotation", "");

    assertErrorResponse(NOT_IMPLEMENTED, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }

  @Test
  public void objectDeleteVersionIdReturnsNotImplementedWithoutDeletingObject() throws OS3Exception, IOException {
    objectEndpoint.queryParamsForTest().set(QueryParams.VERSION_ID, "version");

    final OS3Exception exception =
        assertErrorResponse(NOT_IMPLEMENTED, () -> delete(objectEndpoint, BUCKET_NAME, KEY_NAME));
    assertEquals(QueryParams.VERSION_ID, exception.getResource());

    objectEndpoint.queryParamsForTest().unset(QueryParams.VERSION_ID);
    assertSucceeds(() -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }






  @Test
  public void objectPutTorrentReturnsNotImplemented() {
    objectEndpoint.queryParamsForTest().set(QueryParams.TORRENT, "");
    when(objectEndpoint.getContext().getMethod()).thenReturn(HttpMethod.PUT);

    assertErrorResponse(NOT_IMPLEMENTED,
        () -> objectEndpoint.put(BUCKET_NAME, KEY_NAME, null));
  }




  @Test
  public void objectGetVersionIdReturnsNotImplemented() {
    objectEndpoint.queryParamsForTest().set(QueryParams.VERSION_ID, "version");

    assertErrorResponse(NOT_IMPLEMENTED, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }

  @Test
  public void objectGetAmbiguousSelectorsReturnInvalidArgument() {
    final S3GatewayMetrics metrics = objectEndpoint.getMetrics();
    final long failuresBefore = metrics.getSubresourceRoutingFailure();
    objectEndpoint.queryParamsForTest().set(QueryParams.ACL, "");
    objectEndpoint.queryParamsForTest().set(QueryParams.TAGGING, "");

    assertErrorResponse(INVALID_ARGUMENT, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
    assertEquals(1L, metrics.getSubresourceRoutingFailure() - failuresBefore);
  }

  @Test
  public void ambiguousSelectorsUseUnsupportedActionAttribution() throws IOException {
    final ObjectOperationHandler handler = new ObjectOperationHandler() {
    };
    final ObjectOperationHandlerRouter router = new ObjectOperationHandlerRouter.Builder()
        .get(QueryParams.ACL, handler)
        .get(QueryParams.TAGGING, handler)
        .plainGet(handler, Collections.emptySet())
        .build();
    router.copyDependenciesFrom(objectEndpoint);
    objectEndpoint.queryParamsForTest().set(QueryParams.ACL, "");
    objectEndpoint.queryParamsForTest().set(QueryParams.TAGGING, "");
    final ObjectEndpoint.ObjectRequestContext context =
        objectEndpoint.new ObjectRequestContext(S3GAction.GET_KEY, BUCKET_NAME);

    final OS3Exception exception = assertThrows(OS3Exception.class,
        () -> router.handleGetRequest(context, KEY_NAME));

    assertEquals(INVALID_ARGUMENT.getCode(), exception.getCode());
    assertEquals(S3GAction.UNSUPPORTED_SUBRESOURCE, context.getAction());
  }

  @Test
  public void objectGetImplementedSelectorWithUnimplementedSelectorReturnsInvalidArgument() {
    objectEndpoint.queryParamsForTest().set(QueryParams.ACL, "");
    objectEndpoint.queryParamsForTest().set("website", "");

    assertErrorResponse(INVALID_ARGUMENT, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }

  @Test
  public void objectGetWithPresignedNoiseStillSucceeds() throws OS3Exception, IOException {
    objectEndpoint.queryParamsForTest().set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
    objectEndpoint.queryParamsForTest().set("x-id", "GetObject");

    assertSucceeds(() -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }

  @Test
  public void bucketGetWithListModifiersStillListsObjects() throws OS3Exception, IOException {
    bucketEndpoint.queryParamsForTest().set(QueryParams.PREFIX, KEY_NAME);

    assertSucceeds(() -> bucketEndpoint.get(BUCKET_NAME));
  }

  @Test
  public void objectGetAclReturnsNotImplemented() {
    objectEndpoint.queryParamsForTest().set(QueryParams.ACL, "");

    assertErrorResponse(S3ErrorTable.NOT_IMPLEMENTED, () -> get(objectEndpoint, BUCKET_NAME, KEY_NAME));
  }






  @Test
  public void bucketGetAmbiguousSelectorsReturnInvalidArgument() {
    bucketEndpoint.queryParamsForTest().set(QueryParams.ACL, "");
    bucketEndpoint.queryParamsForTest().set(QueryParams.TAGGING, "");

    assertErrorResponse(INVALID_ARGUMENT, () -> bucketEndpoint.get(BUCKET_NAME));
  }

  @Test
  public void bucketDeletePublicAccessBlockReturnsNotImplemented() {
    bucketEndpoint.queryParamsForTest().set("publicAccessBlock", "");

    assertErrorResponse(NOT_IMPLEMENTED, () -> bucketEndpoint.delete(BUCKET_NAME));
  }

  @Test
  public void bucketPutUnimplementedSelectorDoesNotCreateBucket() {
    final String newBucket = "policy-put-bucket";
    bucketEndpoint.queryParamsForTest().set("policy", "");

    final OS3Exception exception =
        assertErrorResponse(NOT_IMPLEMENTED, () -> bucketEndpoint.put(newBucket, null));
    assertEquals("policy", exception.getResource());

    bucketEndpoint.queryParamsForTest().unset("policy");
    assertErrorResponse(S3ErrorTable.NO_SUCH_BUCKET, () -> bucketEndpoint.head(newBucket));
  }



  @Test
  public void bucketGetListMultipartUploadsWithModifiersStillSucceeds() throws Exception {
    HttpHeaders headers = mock(HttpHeaders.class);
    ObjectEndpoint uploadEndpoint = EndpointBuilder.newObjectEndpointBuilder()
        .setClient(objectEndpoint.getClient())
        .setHeaders(headers)
        .build();
    initiateMultipartUpload(uploadEndpoint, BUCKET_NAME, KEY_NAME);

    bucketEndpoint.queryParamsForTest().set(QueryParams.UPLOADS, "");
    bucketEndpoint.queryParamsForTest().set(QueryParams.PREFIX, KEY_NAME);
    bucketEndpoint.queryParamsForTest().setInt(QueryParams.MAX_UPLOADS, 10);

    assertSucceeds(() -> bucketEndpoint.get(BUCKET_NAME));
  }

  @Test
  public void subresourceRouterIsNotSharedAcrossRequests() throws IOException {
    final BucketEndpoint firstRequest = EndpointBuilder.newBucketEndpointBuilder()
        .setClient(new OzoneClientStub())
        .build();
    final BucketEndpoint secondRequest = EndpointBuilder.newBucketEndpointBuilder()
        .setClient(firstRequest.getClient())
        .build();

    assertNotSame(firstRequest, secondRequest);
    assertNotSame(firstRequest.subresourceRouterForTest(), secondRequest.subresourceRouterForTest());
  }




}

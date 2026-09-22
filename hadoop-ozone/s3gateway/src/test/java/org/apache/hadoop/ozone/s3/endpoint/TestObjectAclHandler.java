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

import static org.apache.hadoop.ozone.s3.endpoint.EndpointTestUtils.assertErrorResponse;
import static org.apache.hadoop.ozone.s3.exception.S3ErrorTable.NOT_IMPLEMENTED;
import static org.apache.hadoop.ozone.s3.util.S3Consts.QueryParams;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.io.IOException;
import org.apache.hadoop.hdds.conf.OzoneConfiguration;
import org.apache.hadoop.ozone.OzoneConfigKeys;
import org.apache.hadoop.ozone.OzoneConsts;
import org.apache.hadoop.ozone.audit.S3GAction;
import org.apache.hadoop.ozone.client.BucketArgs;
import org.apache.hadoop.ozone.client.OzoneClient;
import org.apache.hadoop.ozone.client.OzoneClientStub;
import org.apache.hadoop.ozone.client.OzoneVolume;
import org.apache.hadoop.ozone.s3.exception.OS3Exception;
import org.apache.hadoop.ozone.s3.metrics.S3GatewayMetrics;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link ObjectAclHandler}. */
public class TestObjectAclHandler {

  private static final String BUCKET_NAME = OzoneConsts.S3_BUCKET;
  private static final String KEY_NAME = OzoneConsts.KEY;
  private static final String OWNER = "owner";

  private OzoneClient client;
  private ObjectEndpoint objectEndpoint;
  private ObjectAclHandler aclHandler;

  @BeforeEach
  public void setup() throws IOException {
    client = new OzoneClientStub();
    client.getObjectStore().createS3Bucket(BUCKET_NAME);
    final OzoneVolume volume = client.getObjectStore().getS3Volume();
    volume.deleteBucket(BUCKET_NAME);
    volume.createBucket(BUCKET_NAME, BucketArgs.newBuilder().setOwner(OWNER).build());
    final OzoneConfiguration config = new OzoneConfiguration();
    config.setBoolean(OzoneConfigKeys.OZONE_S3G_STS_HTTP_ENABLED_KEY, true);

    objectEndpoint = EndpointBuilder.newObjectEndpointBuilder()
        .setClient(client)
        .setConfig(config)
        .build();
    aclHandler = EndpointBuilder.newObjectAclHandlerBuilder()
        .setClient(client)
        .setConfig(config)
        .build();
    aclHandler.queryParamsForTest().set(QueryParams.ACL, "");
  }

  @AfterEach
  public void clean() throws IOException {
    if (client != null) {
      client.close();
    }
  }

  @Test
  public void getObjectAclSetsActionAndFailureMetric() {
    final ObjectEndpoint.ObjectRequestContext context =
        objectEndpoint.new ObjectRequestContext(S3GAction.GET_KEY, BUCKET_NAME);
    final S3GatewayMetrics metrics = aclHandler.getMetrics();
    final long before = metrics.getGetObjectAclFailure();

    final OS3Exception exception =
        assertErrorResponse(NOT_IMPLEMENTED, () -> aclHandler.handleGetRequest(context, KEY_NAME));
    assertEquals(S3GAction.GET_OBJECT_ACL, context.getAction());
    assertEquals(KEY_NAME, exception.getResource());
    assertEquals(1L, metrics.getGetObjectAclFailure() - before);
  }

  @Test
  public void putObjectAclSetsAction() {
    final ObjectEndpoint.ObjectRequestContext context =
        objectEndpoint.new ObjectRequestContext(S3GAction.PUT_OBJECT_ACL, BUCKET_NAME);

    final OS3Exception exception = assertErrorResponse(NOT_IMPLEMENTED,
        () -> aclHandler.handlePutRequest(context, KEY_NAME, null));
    assertEquals(S3GAction.PUT_OBJECT_ACL, context.getAction());
    assertEquals(KEY_NAME, exception.getResource());
  }

}

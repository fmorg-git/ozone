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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriInfo;
import org.apache.hadoop.ozone.s3.util.S3Consts.QueryParams;
import org.junit.jupiter.api.Test;

/** Tests pre-unmarshal validation of POST subresource selectors. */
public class TestPostSubresourceSelectorFilter {

  private final PostSubresourceSelectorFilter filter = new PostSubresourceSelectorFilter();

  @Test
  public void marksUnsupportedObjectSubresourceForUntypedDispatch() {
    final ContainerRequestContext context = request(HttpMethod.POST, "bucket/key", "restore");

    assertMarkedForUntypedDispatch(context);
  }

  @Test
  public void marksUnsupportedBucketSubresourceForUntypedDispatch() {
    final ContainerRequestContext context =
        request(HttpMethod.POST, "bucket", "metadataConfiguration");

    assertMarkedForUntypedDispatch(context);
  }

  @Test
  public void allowsSupportedPostSelectors() {
    assertNotMarked(request(HttpMethod.POST, "bucket/key", QueryParams.UPLOAD_ID));
    assertNotMarked(request(HttpMethod.POST, "bucket/key", QueryParams.UPLOADS));
    assertNotMarked(request(HttpMethod.POST, "bucket", QueryParams.DELETE));
    assertNotMarked(request(HttpMethod.POST, "bucket/", QueryParams.DELETE));
    assertNotMarked(request(HttpMethod.POST, "/bucket/key/", QueryParams.UPLOAD_ID));
    assertNotMarked(request(HttpMethod.POST, "/bucket//", QueryParams.UPLOADS));
  }

  @Test
  public void classifiesEncodedSlashAsPartOfBucketPath() {
    assertNotMarked(request(HttpMethod.POST, "bucket%2Fkey", QueryParams.DELETE));
  }

  @Test
  public void marksMissingPostSelectorForUntypedDispatch() {
    assertMarkedForUntypedDispatch(request(HttpMethod.POST, "bucket/key"));
    assertMarkedForUntypedDispatch(request(HttpMethod.POST, "bucket"));
  }

  @Test
  public void ignoresStsRootPost() {
    assertNotMarked(request(HttpMethod.POST, "", "Action"));
    assertNotMarked(request(HttpMethod.POST, "/", "Action"));
  }

  @Test
  public void ignoresSelectorsForOtherMethods() {
    assertNotMarked(request(HttpMethod.GET, "bucket/key", "restore"));
  }

  private void assertMarkedForUntypedDispatch(ContainerRequestContext context) {
    assertDoesNotThrow(() -> filter.filter(context));
    assertEquals(PostSubresourceSelectorFilter.INVALID_POST_SUBRESOURCE_MARKER,
        context.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE));
  }

  private void assertNotMarked(ContainerRequestContext context) {
    assertDoesNotThrow(() -> filter.filter(context));
    assertNull(context.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE));
  }

  private static ContainerRequestContext request(String method, String path, String... queryKeys) {
    final ContainerRequestContext context = mock(ContainerRequestContext.class);
    final UriInfo uriInfo = mock(UriInfo.class);
    final MultivaluedMap<String, String> queryParameters = new MultivaluedHashMap<>();
    final MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
    for (final String queryKey : queryKeys) {
      queryParameters.putSingle(queryKey, "");
    }
    when(context.getMethod()).thenReturn(method);
    when(context.getUriInfo()).thenReturn(uriInfo);
    when(context.getHeaders()).thenReturn(headers);
    when(uriInfo.getPath(false)).thenReturn(path);
    when(uriInfo.getQueryParameters()).thenReturn(queryParameters);
    return context;
  }
}

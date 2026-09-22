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

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import java.util.EnumMap;
import java.util.Map;
import java.util.Set;
import javax.ws.rs.HttpMethod;

/**
 * AWS S3 subresource selectors and the methods AWS defines for each selector.
 *
 * <p>Query parameters outside this vocabulary are request modifiers or
 * client-specific parameters and must not affect operation routing.</p>
 */
enum S3Subresource {

  // Bucket subresources.
  BUCKET_ACCELERATE("accelerate", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketAccelerateConfiguration",
      HttpMethod.PUT, "PutBucketAccelerateConfiguration"),
  BUCKET_ACL("acl", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketAcl", HttpMethod.PUT, "PutBucketAcl"),
  BUCKET_ANALYTICS("analytics", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketAnalyticsConfiguration",
      HttpMethod.PUT, "PutBucketAnalyticsConfiguration", HttpMethod.DELETE, "DeleteBucketAnalyticsConfiguration"),
  BUCKET_CORS("cors", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketCors", HttpMethod.PUT, "PutBucketCors",
      HttpMethod.DELETE, "DeleteBucketCors"),
  BUCKET_DELETE("delete", ResourceLevel.BUCKET, HttpMethod.POST, "DeleteObjects"),
  BUCKET_ENCRYPTION("encryption", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketEncryption",
      HttpMethod.PUT, "PutBucketEncryption", HttpMethod.DELETE, "DeleteBucketEncryption"),
  BUCKET_INTELLIGENT_TIERING("intelligent-tiering", ResourceLevel.BUCKET, HttpMethod.GET,
      "GetBucketIntelligentTieringConfiguration", HttpMethod.PUT, "PutBucketIntelligentTieringConfiguration",
      HttpMethod.DELETE, "DeleteBucketIntelligentTieringConfiguration"),
  BUCKET_INVENTORY("inventory", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketInventoryConfiguration",
      HttpMethod.PUT, "PutBucketInventoryConfiguration", HttpMethod.DELETE, "DeleteBucketInventoryConfiguration"),
  BUCKET_LIFECYCLE("lifecycle", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketLifecycleConfiguration",
      HttpMethod.PUT, "PutBucketLifecycleConfiguration", HttpMethod.DELETE, "DeleteBucketLifecycleConfiguration"),
  BUCKET_LOCATION("location", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketLocation"),
  BUCKET_LOGGING("logging", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketLogging",
      HttpMethod.PUT, "PutBucketLogging"),
  BUCKET_METRICS("metrics", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketMetricsConfiguration",
      HttpMethod.PUT, "PutBucketMetricsConfiguration", HttpMethod.DELETE, "DeleteBucketMetricsConfiguration"),
  BUCKET_NOTIFICATION("notification", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketNotificationConfiguration",
      HttpMethod.PUT, "PutBucketNotificationConfiguration"),
  BUCKET_OBJECT_LOCK("object-lock", ResourceLevel.BUCKET, HttpMethod.GET, "GetObjectLockConfiguration",
      HttpMethod.PUT, "PutObjectLockConfiguration"),
  BUCKET_OWNERSHIP_CONTROLS("ownershipControls", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketOwnershipControls",
      HttpMethod.PUT, "PutBucketOwnershipControls", HttpMethod.DELETE, "DeleteBucketOwnershipControls"),
  BUCKET_POLICY("policy", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketPolicy",
      HttpMethod.PUT, "PutBucketPolicy", HttpMethod.DELETE, "DeleteBucketPolicy"),
  BUCKET_POLICY_STATUS("policyStatus", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketPolicyStatus"),
  BUCKET_PUBLIC_ACCESS_BLOCK("publicAccessBlock", ResourceLevel.BUCKET, HttpMethod.GET, "GetPublicAccessBlock",
      HttpMethod.PUT, "PutPublicAccessBlock", HttpMethod.DELETE, "DeletePublicAccessBlock"),
  BUCKET_REPLICATION("replication", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketReplication",
      HttpMethod.PUT, "PutBucketReplication", HttpMethod.DELETE, "DeleteBucketReplication"),
  BUCKET_REQUEST_PAYMENT("requestPayment", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketRequestPayment",
      HttpMethod.PUT, "PutBucketRequestPayment"),
  BUCKET_TAGGING("tagging", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketTagging",
      HttpMethod.PUT, "PutBucketTagging", HttpMethod.DELETE, "DeleteBucketTagging"),
  BUCKET_UPLOADS("uploads", ResourceLevel.BUCKET, HttpMethod.GET, "ListMultipartUploads"),
  BUCKET_VERSIONING("versioning", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketVersioning",
      HttpMethod.PUT, "PutBucketVersioning"),
  BUCKET_VERSIONS("versions", ResourceLevel.BUCKET, HttpMethod.GET, "ListObjectVersions"),
  BUCKET_WEBSITE("website", ResourceLevel.BUCKET, HttpMethod.GET, "GetBucketWebsite",
      HttpMethod.PUT, "PutBucketWebsite", HttpMethod.DELETE, "DeleteBucketWebsite"),

  // Object subresources.
  OBJECT_ACL("acl", ResourceLevel.OBJECT, HttpMethod.GET, "GetObjectAcl", HttpMethod.PUT, "PutObjectAcl"),
  OBJECT_ATTRIBUTES("attributes", ResourceLevel.OBJECT, HttpMethod.GET, "GetObjectAttributes"),
  OBJECT_LEGAL_HOLD("legal-hold", ResourceLevel.OBJECT, HttpMethod.GET, "GetObjectLegalHold",
      HttpMethod.PUT, "PutObjectLegalHold"),
  OBJECT_RESTORE("restore", ResourceLevel.OBJECT, HttpMethod.POST, "RestoreObject"),
  OBJECT_RETENTION("retention", ResourceLevel.OBJECT, HttpMethod.GET, "GetObjectRetention",
      HttpMethod.PUT, "PutObjectRetention"),
  OBJECT_SELECT("select", ResourceLevel.OBJECT, HttpMethod.POST, "SelectObjectContent"),
  OBJECT_TAGGING("tagging", ResourceLevel.OBJECT, HttpMethod.GET, "GetObjectTagging",
      HttpMethod.PUT, "PutObjectTagging", HttpMethod.DELETE, "DeleteObjectTagging"),
  OBJECT_TORRENT("torrent", ResourceLevel.OBJECT, HttpMethod.GET, "GetObjectTorrent"),
  OBJECT_UPLOAD_ID("uploadId", ResourceLevel.OBJECT, HttpMethod.GET, "ListParts",
      HttpMethod.PUT, "UploadPart", HttpMethod.POST, "CompleteMultipartUpload", HttpMethod.DELETE,
      "AbortMultipartUpload"),
  OBJECT_UPLOADS("uploads", ResourceLevel.OBJECT, HttpMethod.POST, "CreateMultipartUpload");

  private static final Map<ResourceLevel, Map<String, S3Subresource>> BY_LEVEL = buildLookup();
  private static final Set<String> ALL_SELECTORS = buildSelectors();

  private final String selector;
  private final ResourceLevel resourceLevel;
  private final Map<String, String> operationNames;

  S3Subresource(String selector, ResourceLevel resourceLevel, String... operations) {
    if (operations.length == 0 || operations.length % 2 != 0) {
      throw new IllegalArgumentException("Each subresource must define method/name pairs");
    }
    final ImmutableMap.Builder<String, String> names = ImmutableMap.builder();
    for (int i = 0; i < operations.length; i += 2) {
      names.put(operations[i], operations[i + 1]);
    }
    this.selector = selector;
    this.resourceLevel = resourceLevel;
    this.operationNames = names.build();
  }

  static S3Subresource resolve(ResourceLevel resourceLevel, String selector) {
    return BY_LEVEL.get(resourceLevel).get(selector);
  }

  static boolean isSelector(String selector) {
    return ALL_SELECTORS.contains(selector);
  }

  static Set<String> selectors(ResourceLevel resourceLevel) {
    return BY_LEVEL.get(resourceLevel).keySet();
  }

  String getSelector() {
    return selector;
  }

  ResourceLevel getResourceLevel() {
    return resourceLevel;
  }

  boolean supports(String method) {
    return operationNames.containsKey(method);
  }

  String getOperationName(String method) {
    return operationNames.get(method);
  }

  private static Map<ResourceLevel, Map<String, S3Subresource>> buildLookup() {
    final EnumMap<ResourceLevel, ImmutableMap.Builder<String, S3Subresource>> builders = new EnumMap<>(
        ResourceLevel.class);
    for (final ResourceLevel level : ResourceLevel.values()) {
      builders.put(level, ImmutableMap.builder());
    }
    for (final S3Subresource subresource : values()) {
      builders.get(subresource.resourceLevel).put(subresource.selector, subresource);
    }
    final EnumMap<ResourceLevel, Map<String, S3Subresource>> lookup = new EnumMap<>(ResourceLevel.class);
    for (final Map.Entry<ResourceLevel, ImmutableMap.Builder<String, S3Subresource>> entry : builders.entrySet()) {
      lookup.put(entry.getKey(), entry.getValue().build());
    }
    return lookup;
  }

  private static Set<String> buildSelectors() {
    final ImmutableSet.Builder<String> selectors = ImmutableSet.builder();
    for (final S3Subresource subresource : values()) {
      selectors.add(subresource.selector);
    }
    return selectors.build();
  }
}

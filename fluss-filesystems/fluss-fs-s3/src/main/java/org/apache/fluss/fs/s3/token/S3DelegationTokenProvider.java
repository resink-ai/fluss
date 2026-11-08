/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.fluss.fs.s3.token;

import org.apache.fluss.annotation.VisibleForTesting;
import org.apache.fluss.fs.token.CredentialsJsonSerde;
import org.apache.fluss.fs.FsPath;
import org.apache.fluss.fs.token.ObtainedSecurityToken;
import org.apache.fluss.fs.token.TokenScope;
import org.apache.fluss.utils.StringUtils;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.s3a.AWSCredentialProviderList;
import org.apache.hadoop.fs.s3a.auth.CredentialProviderListFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.services.sts.model.GetSessionTokenResponse;

import javax.annotation.Nullable;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.apache.fluss.utils.Preconditions.checkArgument;

/** Delegation token provider for S3 Hadoop filesystems. */
public class S3DelegationTokenProvider {

    private static final Logger LOG = LoggerFactory.getLogger(S3DelegationTokenProvider.class);

    private static final String ACCESS_KEY_ID = "fs.s3a.access.key";
    private static final String ACCESS_KEY_SECRET = "fs.s3a.secret.key";
    private static final String AWS_CREDENTIALS_PROVIDER = "fs.s3a.aws.credentials.provider";
    public static final String CREDENTIAL_PROVIDER_EXPLICITLY_CONFIGURED =
            "fluss.fs.s3.aws.credentials.provider.explicitly.configured";

    private static final String REGION_KEY = "fs.s3a.region";
    private static final String ENDPOINT_KEY = "fs.s3a.endpoint";
    private static final String PATH_STYLE_ACCESS_KEY = "fs.s3a.path.style.access";

    private static final String ROLE_ARN_KEY = "fs.s3a.assumed.role.arn";

    /**
     * How a token limited to a path may list objects: {@code prefix} (default) allows listing only
     * below the path using the standard {@code s3:prefix} condition; {@code none} allows no
     * listing at all (reading a known file does not need it); {@code bucket} allows listing the
     * whole bucket, which exposes other paths' object names but not their content. Stores that do
     * not evaluate the {@code s3:prefix} condition (such as RustFS) deny every listing under {@code
     * prefix}, so use {@code none} there.
     */
    public static final String SCOPED_LIST_MODE_KEY = "fs.s3a.scoped.token.list-mode";
    private static final String STS_ENDPOINT_KEY = "fs.s3a.assumed.role.sts.endpoint";

    private final String scheme;
    private final String region;
    @Nullable private final String accessKey;
    @Nullable private final String secretKey;
    @Nullable private final String roleArn;
    @Nullable private final String stsEndpoint;
    private final ListMode listMode;
    @Nullable private final AWSCredentialProviderList credentialProviderList;
    private final Map<String, String> additionInfos;

    public S3DelegationTokenProvider(String scheme, Configuration conf) throws IOException {
        this.scheme = scheme;
        this.region = conf.get(REGION_KEY);
        checkArgument(region != null, "Region is not set.");
        this.accessKey = conf.get(ACCESS_KEY_ID);
        this.secretKey = conf.get(ACCESS_KEY_SECRET);
        this.roleArn = conf.get(ROLE_ARN_KEY);
        this.stsEndpoint = conf.get(STS_ENDPOINT_KEY);
        this.listMode = ListMode.parse(conf.get(SCOPED_LIST_MODE_KEY, "prefix"));
        boolean hasCredentialProvider =
                conf.getBoolean(CREDENTIAL_PROVIDER_EXPLICITLY_CONFIGURED, false)
                        && !StringUtils.isNullOrWhitespaceOnly(
                                conf.getTrimmed(AWS_CREDENTIALS_PROVIDER));

        checkArgument(
                (accessKey == null) == (secretKey == null),
                "S3 access key and secret key must both be set or both be unset.");
        if (hasCredentialProvider) {
            checkArgument(
                    !Arrays.asList(conf.getTrimmedStrings(AWS_CREDENTIALS_PROVIDER))
                            .contains(DynamicTemporaryAWSCredentialsProvider.NAME),
                    "%s cannot be configured as a server-side AWS credentials provider.",
                    DynamicTemporaryAWSCredentialsProvider.NAME);
        }
        this.credentialProviderList =
                hasCredentialProvider
                        ? CredentialProviderListFactory.createAWSCredentialProviderList(null, conf)
                        : null;
        if (accessKey == null && credentialProviderList == null) {
            checkArgument(
                    roleArn != null,
                    "Role ARN must be set when static credentials are not provided.");
        }

        this.additionInfos = new HashMap<>();
        for (String key : Arrays.asList(REGION_KEY, ENDPOINT_KEY, PATH_STYLE_ACCESS_KEY)) {
            if (conf.get(key) != null) {
                additionInfos.put(key, conf.get(key));
            }
        }
    }

    public ObtainedSecurityToken obtainSecurityToken() {
        try (StsClient stsClient = buildStsClient()) {
            Credentials credentials;

            if (roleArn != null) {
                LOG.info("Obtaining session credentials via AssumeRole, role: {}", roleArn);
                AssumeRoleRequest request =
                        AssumeRoleRequest.builder()
                                .roleArn(roleArn)
                                .roleSessionName("fluss-" + UUID.randomUUID())
                                .build();
                AssumeRoleResponse response = stsClient.assumeRole(request);
                credentials = response.credentials();
            } else {
                LOG.info(
                        "Obtaining session credentials via GetSessionToken{}.",
                        credentialProviderList != null
                                ? " with configured AWS credentials provider"
                                : " with access key: " + S3TokenLogUtils.maskAccessKey(accessKey));
                GetSessionTokenResponse response = stsClient.getSessionToken();
                credentials = response.credentials();
            }

            LOG.info(
                    "Session credentials obtained successfully with access key: {} expiration: {}",
                    S3TokenLogUtils.maskAccessKey(credentials.accessKeyId()),
                    credentials.expiration());

            return new ObtainedSecurityToken(
                    scheme,
                    toJson(credentials),
                    credentials.expiration().toEpochMilli(),
                    additionInfos);
        }
    }

    /**
     * Obtains credentials that reach only the directories of the scope. The limit is a session
     * policy on an AssumeRole call, so it needs a role; with only GetSessionToken (which cannot
     * carry a policy) the call fails instead of handing out credentials for the whole bucket.
     */
    public ObtainedSecurityToken obtainSecurityToken(TokenScope scope) {
        checkArgument(
                roleArn != null,
                "Tokens limited to a path need '%s' to be set: GetSessionToken cannot carry a policy.",
                ROLE_ARN_KEY);
        checkArgument(!scope.isEmpty(), "The token scope is empty.");
        String policy = buildScopePolicy(scope, listMode);
        try (StsClient stsClient = buildStsClient()) {
            LOG.info(
                    "Obtaining scoped session credentials via AssumeRole, role: {}, scope: {}",
                    roleArn,
                    scope);
            AssumeRoleResponse response =
                    stsClient.assumeRole(
                            AssumeRoleRequest.builder()
                                    .roleArn(roleArn)
                                    .roleSessionName("fluss-" + UUID.randomUUID())
                                    .policy(policy)
                                    .build());
            Credentials credentials = response.credentials();
            return new ObtainedSecurityToken(
                    scheme,
                    toJson(credentials),
                    credentials.expiration().toEpochMilli(),
                    additionInfos);
        }
    }

    /** See {@link #SCOPED_LIST_MODE_KEY}. */
    enum ListMode {
        PREFIX,
        NONE,
        BUCKET;

        static ListMode parse(String value) {
            for (ListMode m : values()) {
                if (m.name().equalsIgnoreCase(value.trim())) {
                    return m;
                }
            }
            throw new IllegalArgumentException(
                    "Unknown value '" + value + "' for " + SCOPED_LIST_MODE_KEY
                            + ", expected prefix, none or bucket.");
        }
    }

    /** Builds the IAM session policy that allows exactly the directories of the scope. */
    @VisibleForTesting
    static String buildScopePolicy(TokenScope scope, ListMode listMode) {
        List<String> statements = new ArrayList<>();
        Set<String> buckets = new TreeSet<>();
        Map<String, List<String>> listPrefixes = new TreeMap<>();
        for (FsPath dir : scope.getReadWrite()) {
            addObjectStatement(statements, dir, true, buckets, listPrefixes);
        }
        for (FsPath dir : scope.getReadOnly()) {
            addObjectStatement(statements, dir, false, buckets, listPrefixes);
        }
        for (Map.Entry<String, List<String>> e : listMode == ListMode.NONE ? Collections.<String, List<String>>emptyMap().entrySet() : listPrefixes.entrySet()) {
            StringBuilder prefixes = new StringBuilder();
            for (String prefix : e.getValue()) {
                if (prefixes.length() > 0) {
                    prefixes.append(',');
                }
                // the directory itself and everything below it
                prefixes.append('"').append(prefix).append("\",\"").append(prefix).append("/*\"");
            }
            String condition =
                    listMode == ListMode.BUCKET
                            ? ""
                            : ",\"Condition\":{\"StringLike\":{\"s3:prefix\":[" + prefixes + "]}}";
            statements.add(
                    "{\"Effect\":\"Allow\",\"Action\":[\"s3:ListBucket\",\"s3:ListBucketMultipartUploads\"],"
                            + "\"Resource\":\"arn:aws:s3:::"
                            + e.getKey()
                            + "\""
                            + condition
                            + "}");
        }
        statements.add(
                "{\"Effect\":\"Allow\",\"Action\":\"s3:GetBucketLocation\",\"Resource\":["
                        + String.join(
                                ",",
                                buckets.stream()
                                        .map(b -> "\"arn:aws:s3:::" + b + "\"")
                                        .collect(Collectors.toList()))
                        + "]}");
        return "{\"Version\":\"2012-10-17\",\"Statement\":[" + String.join(",", statements) + "]}";
    }

    private static void addObjectStatement(
            List<String> statements,
            FsPath dir,
            boolean write,
            Set<String> buckets,
            Map<String, List<String>> listPrefixes) {
        URI uri = dir.toUri();
        String bucket = uri.getAuthority();
        String key = uri.getPath() == null ? "" : uri.getPath().replaceAll("^/+|/+$", "");
        checkArgument(bucket != null && !key.isEmpty(), "Not a directory below a bucket: %s", dir);
        checkArgument(
                key.indexOf('*') < 0 && key.indexOf('?') < 0 && key.indexOf('"') < 0,
                "Illegal characters in scope directory: %s",
                dir);
        buckets.add(bucket);
        listPrefixes.computeIfAbsent(bucket, b -> new ArrayList<>()).add(key);
        String actions =
                write
                        ? "\"s3:GetObject\",\"s3:PutObject\",\"s3:DeleteObject\","
                                + "\"s3:AbortMultipartUpload\",\"s3:ListMultipartUploadParts\""
                        : "\"s3:GetObject\"";
        statements.add(
                "{\"Effect\":\"Allow\",\"Action\":["
                        + actions
                        + "],\"Resource\":\"arn:aws:s3:::"
                        + bucket
                        + "/"
                        + key
                        + "/*\"}");
    }

    @VisibleForTesting
    static URI parseStsEndpoint(String stsEndpoint) {
        return URI.create(stsEndpoint.contains("://") ? stsEndpoint : "https://" + stsEndpoint);
    }

    private StsClient buildStsClient() {
        StsClientBuilder builder = StsClient.builder().region(Region.of(region));

        AwsCredentialsProvider stsCredentialsProvider = createStsCredentialsProvider();
        if (stsCredentialsProvider != null) {
            builder.credentialsProvider(stsCredentialsProvider);
        }

        if (stsEndpoint != null) {
            builder.endpointOverride(parseStsEndpoint(stsEndpoint));
        }

        return builder.build();
    }

    @Nullable
    AwsCredentialsProvider createStsCredentialsProvider() {
        if (credentialProviderList != null) {
            if (roleArn != null) {
                // Not the list itself: StsClient.close() would close it, breaking
                // every later token refresh.
                LOG.info("Using configured AWS credentials provider as the AssumeRole caller.");
                return () -> credentialProviderList.resolveCredentials();
            }
            AwsCredentials credentials = credentialProviderList.resolveCredentials();
            checkArgument(
                    !(credentials instanceof AwsSessionCredentials),
                    "Session credentials from the configured AWS credentials provider are not supported "
                            + "for Fluss S3 client-token generation.");
            checkArgument(
                    credentials.accessKeyId() != null && credentials.secretAccessKey() != null,
                    "The configured AWS credentials provider must return an access key and secret key.");
            LOG.info(
                    "Using configured AWS credentials provider for STS GetSessionToken with access key: {}",
                    S3TokenLogUtils.maskAccessKey(credentials.accessKeyId()));
            return StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(
                            credentials.accessKeyId(), credentials.secretAccessKey()));
        }

        if (accessKey != null && secretKey != null) {
            return StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(accessKey, secretKey));
        }

        return null;
    }

    private byte[] toJson(Credentials credentials) {
        org.apache.fluss.fs.token.Credentials flussCredentials =
                new org.apache.fluss.fs.token.Credentials(
                        credentials.accessKeyId(),
                        credentials.secretAccessKey(),
                        credentials.sessionToken());
        return CredentialsJsonSerde.toJson(flussCredentials);
    }
}

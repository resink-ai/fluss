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

import org.apache.fluss.fs.FsPath;
import org.apache.fluss.fs.token.TokenScope;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests for the session policy that limits a token to a scope. */
class S3ScopePolicyTest {

    private static final S3DelegationTokenProvider.ListMode PREFIX =
            S3DelegationTokenProvider.ListMode.PREFIX;

    private static TokenScope oneDirectory() {
        return new TokenScope(
                Collections.emptyList(),
                Collections.singletonList(new FsPath("s3://bkt/data/kv/acme")));
    }

    @Test
    void noneMeansNoListingAtAll() {
        String policy =
                S3DelegationTokenProvider.buildScopePolicy(
                        oneDirectory(), S3DelegationTokenProvider.ListMode.NONE);
        assertThat(policy).doesNotContain("ListBucket");
        assertThat(policy).contains("arn:aws:s3:::bkt/data/kv/acme/*");
    }

    @Test
    void bucketModeListsWithoutACondition() {
        String policy =
                S3DelegationTokenProvider.buildScopePolicy(
                        oneDirectory(), S3DelegationTokenProvider.ListMode.BUCKET);
        assertThat(policy).contains("s3:ListBucket").doesNotContain("s3:prefix");
    }

    @Test
    void unknownModeIsRejected() {
        assertThatThrownBy(() -> S3DelegationTokenProvider.ListMode.parse("everything"))
                .hasMessageContaining("expected prefix, none or bucket");
    }

    @Test
    void policyAllowsOnlyTheScopeDirectories() {
        TokenScope scope =
                new TokenScope(
                        Collections.singletonList(new FsPath("s3://bkt/data/log/acme")),
                        Arrays.asList(
                                new FsPath("s3://bkt/data/kv/acme"),
                                new FsPath("s3://bkt/data/kv/acme2")));
        String policy = S3DelegationTokenProvider.buildScopePolicy(scope, PREFIX);

        assertThat(policy).contains("\"Resource\":\"arn:aws:s3:::bkt/data/kv/acme/*\"");
        assertThat(policy).contains("\"Resource\":\"arn:aws:s3:::bkt/data/kv/acme2/*\"");
        // read-only directory: no write actions in its statement
        assertThat(policy)
                .contains("\"Action\":[\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::bkt/data/log/acme/*\"");
        // listing is limited to the same prefixes
        assertThat(policy).contains("\"s3:prefix\":[\"data/kv/acme\",\"data/kv/acme/*\"");
        // nothing grants the whole bucket
        assertThat(policy).doesNotContain("\"Resource\":\"arn:aws:s3:::bkt/*\"");
        assertThat(policy).doesNotContain("\"Resource\":\"*\"");
    }

    @Test
    void policyRejectsWildcardsAndBucketRoots() {
        assertThatThrownBy(
                        () ->
                                S3DelegationTokenProvider.buildScopePolicy(
                                        new TokenScope(
                                                Collections.emptyList(),
                                                Collections.singletonList(
                                                        new FsPath("s3://bkt/data/kv/*"))),
                                        PREFIX))
                .hasMessageContaining("Illegal characters");
        assertThatThrownBy(
                        () ->
                                S3DelegationTokenProvider.buildScopePolicy(
                                        new TokenScope(
                                                Collections.emptyList(),
                                                Collections.singletonList(new FsPath("s3://bkt/"))),
                                        PREFIX))
                .hasMessageContaining("Not a directory below a bucket");
    }
}

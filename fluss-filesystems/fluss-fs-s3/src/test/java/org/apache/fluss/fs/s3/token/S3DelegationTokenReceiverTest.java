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

import org.apache.fluss.fs.token.Credentials;
import org.apache.fluss.fs.token.CredentialsJsonSerde;
import org.apache.fluss.fs.token.ObtainedSecurityToken;
import org.apache.fluss.fs.token.TokenOwner;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests that the S3 credentials of connections sharing a JVM stay apart. */
class S3DelegationTokenReceiverTest {

    private final S3DelegationTokenReceiver receiver = new S3DelegationTokenReceiver();

    @Test
    void testEachConnectionReadsWithItsOwnTokenEvenAfterTheOtherRefreshed() throws Exception {
        receiver.onNewTokensObtained("tenant-a", token("key-a1"));
        receiver.onNewTokensObtained("tenant-b", token("key-b1"));
        // b refreshes last, which used to replace a's token as well
        receiver.onNewTokensObtained("tenant-b", token("key-b2"));

        assertThat(keyFor("tenant-a")).isEqualTo("key-a1");
        assertThat(keyFor("tenant-b")).isEqualTo("key-b2");

        receiver.onOwnerClosed("tenant-a");
        receiver.onOwnerClosed("tenant-b");
    }

    @Test
    void testAThreadOfAConnectionWithoutATokenGetsNoneInsteadOfSomeoneElses() throws Exception {
        receiver.onNewTokensObtained("tenant-a", token("key-a"));
        assertThat(keyFor("tenant-c")).isNull();

        receiver.onOwnerClosed("tenant-a");
        assertThat(keyFor("tenant-a")).isNull();
    }

    @Test
    void testAnUnboundThreadKeepsGettingTheLatestToken() throws Exception {
        receiver.onNewTokensObtained("tenant-a", token("key-latest"));
        assertThat(S3DelegationTokenReceiver.getCredentials().getAccessKeyId())
                .isEqualTo("key-latest");

        receiver.onNewTokensObtained(token("key-legacy"));
        assertThat(S3DelegationTokenReceiver.getCredentials().getAccessKeyId())
                .isEqualTo("key-legacy");
        receiver.onOwnerClosed("tenant-a");
    }

    private static String keyFor(String owner) throws ExecutionException, InterruptedException {
        // The provider resolves on the thread that reads, so read from a thread bound to the owner.
        CompletableFuture<String> result = new CompletableFuture<>();
        Thread thread =
                new Thread(
                        TokenOwner.bind(
                                owner,
                                () -> {
                                    Credentials c = S3DelegationTokenReceiver.getCredentials();
                                    result.complete(c == null ? null : c.getAccessKeyId());
                                }));
        thread.start();
        return result.get();
    }

    private static ObtainedSecurityToken token(String accessKey) {
        return new ObtainedSecurityToken(
                "s3",
                CredentialsJsonSerde.toJson(new Credentials(accessKey, "secret", "session")),
                null,
                Collections.singletonMap("fs.s3a.endpoint", "http://s3"));
    }
}

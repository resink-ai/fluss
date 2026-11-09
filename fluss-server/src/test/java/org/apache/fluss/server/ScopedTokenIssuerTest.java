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

package org.apache.fluss.server;

import org.apache.fluss.exception.AuthorizationException;
import org.apache.fluss.fs.FsPath;
import org.apache.fluss.fs.token.ObtainedSecurityToken;
import org.apache.fluss.fs.token.TokenScope;
import org.apache.fluss.rpc.netty.server.Session;
import org.apache.fluss.security.acl.AclBinding;
import org.apache.fluss.security.acl.AclBindingFilter;
import org.apache.fluss.security.acl.FlussPrincipal;
import org.apache.fluss.security.acl.OperationType;
import org.apache.fluss.security.acl.Resource;
import org.apache.fluss.security.acl.ResourceType;
import org.apache.fluss.server.authorizer.AclCreateResult;
import org.apache.fluss.server.authorizer.AclDeleteResult;
import org.apache.fluss.server.authorizer.Authorizer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests for {@link ScopedTokenIssuer}: who gets which file system token. */
class ScopedTokenIssuerTest {

    private static final long TTL = 60_000;
    private static final List<String> DATABASES = Arrays.asList("acme", "beta", "gamma");

    private final Map<String, Set<OperationType>> grants = new HashMap<>();
    private boolean superUser;
    private int sharedCalls;
    private final List<TokenScope> scopedCalls = new ArrayList<>();
    private boolean fileSystemCanScope = true;
    private List<String> remoteDirs = Collections.singletonList("s3://bucket/data");
    private ScopedTokenIssuer issuer;

    @BeforeEach
    void setUp() {
        issuer =
                new ScopedTokenIssuer(
                        new FakeAuthorizer(),
                        () -> DATABASES,
                        () -> remoteDirs,
                        new ScopedTokenIssuer.TokenSource() {
                            @Override
                            public ObtainedSecurityToken shared() {
                                sharedCalls++;
                                return token("shared");
                            }

                            @Override
                            public ObtainedSecurityToken scoped(TokenScope scope) {
                                if (!fileSystemCanScope) {
                                    throw new UnsupportedOperationException("cannot scope");
                                }
                                scopedCalls.add(scope);
                                return token("scoped-" + scopedCalls.size());
                            }
                        },
                        TTL);
    }

    @Test
    void testSuperUserGetsTheSharedTokenWithoutAnyScoping() throws Exception {
        superUser = true;
        assertThat(new String(issuer.issue(session(), 0).getToken())).isEqualTo("shared");
        assertThat(sharedCalls).isEqualTo(1);
        assertThat(scopedCalls).isEmpty();
    }

    @Test
    void testTokenIsLimitedToTheDatabasesTheCallerMayUse() throws Exception {
        grants.put("acme", operations(OperationType.READ, OperationType.WRITE));
        grants.put("beta", operations(OperationType.READ));
        // gamma: no rights at all

        issuer.issue(session(), 0);

        TokenScope scope = scopedCalls.get(0);
        assertThat(paths(scope.getReadWrite()))
                .containsExactlyInAnyOrder(
                        "s3://bucket/data/kv/acme", "s3://bucket/data/log/acme");
        assertThat(paths(scope.getReadOnly()))
                .containsExactlyInAnyOrder("s3://bucket/data/kv/beta", "s3://bucket/data/log/beta");
        assertThat(paths(scope.getReadWrite()) + "" + paths(scope.getReadOnly()))
                .doesNotContain("gamma");
        assertThat(sharedCalls).isZero();
    }

    @Test
    void testWriteAccessIsNotAlsoListedAsReadOnly() throws Exception {
        grants.put("acme", operations(OperationType.READ, OperationType.WRITE));
        issuer.issue(session(), 0);
        assertThat(scopedCalls.get(0).getReadOnly()).isEmpty();
    }

    @Test
    void testEveryRemoteDataDirIsCovered() throws Exception {
        remoteDirs = Arrays.asList("s3://a/data", "s3://b/data");
        grants.put("acme", operations(OperationType.READ));
        issuer.issue(session(), 0);
        assertThat(paths(scopedCalls.get(0).getReadOnly()))
                .containsExactlyInAnyOrder(
                        "s3://a/data/kv/acme",
                        "s3://a/data/log/acme",
                        "s3://b/data/kv/acme",
                        "s3://b/data/log/acme");
    }

    @Test
    void testACallerWithNoDatabaseGetsNoTokenAtAll() {
        assertThatThrownBy(() -> issuer.issue(session(), 0))
                .isInstanceOf(AuthorizationException.class);
        assertThat(sharedCalls).isZero();
        assertThat(scopedCalls).isEmpty();
    }

    @Test
    void testWithoutRemoteDataDirsANonSuperUserGetsNothing() {
        remoteDirs = Collections.emptyList();
        grants.put("acme", operations(OperationType.READ));
        assertThatThrownBy(() -> issuer.issue(session(), 0))
                .isInstanceOf(AuthorizationException.class);
    }

    @Test
    void testAFileSystemThatCannotScopeFailsInsteadOfFallingBackToTheSharedToken() {
        fileSystemCanScope = false;
        grants.put("acme", operations(OperationType.READ));
        assertThatThrownBy(() -> issuer.issue(session(), 0))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(sharedCalls).isZero();
    }

    @Test
    void testTokensAreCachedPerScopeAndExpire() throws Exception {
        grants.put("acme", operations(OperationType.READ));
        issuer.issue(session(), 0);
        issuer.issue(session(), TTL - 1);
        assertThat(scopedCalls).hasSize(1);

        issuer.issue(session(), TTL + 1);
        assertThat(scopedCalls).hasSize(2);

        // a different scope never reuses another caller's token
        grants.put("beta", operations(OperationType.READ));
        issuer.issue(session(), TTL + 2);
        assertThat(scopedCalls).hasSize(3);
        assertThat(paths(scopedCalls.get(2).getReadOnly())).anyMatch(p -> p.endsWith("/beta"));
    }

    // ------------------------------------------------------------------------------------------

    private static Set<OperationType> operations(OperationType... types) {
        return new HashSet<>(Arrays.asList(types));
    }

    private static List<String> paths(List<FsPath> paths) {
        return paths.stream().map(FsPath::toString).collect(Collectors.toList());
    }

    private static ObtainedSecurityToken token(String name) {
        return new ObtainedSecurityToken("s3", name.getBytes(), null, Collections.emptyMap());
    }

    private static Session session() {
        return new Session(
                (short) 1,
                "CLIENT",
                false,
                InetAddress.getLoopbackAddress(),
                FlussPrincipal.ANONYMOUS);
    }

    /** Grants by database name; ALL on the cluster is the super user flag. */
    private final class FakeAuthorizer implements Authorizer {
        @Override
        public void startup() {}

        @Override
        public void close() {}

        @Override
        public boolean isAuthorized(Session s, OperationType op, Resource r) {
            if (r.getType() == ResourceType.CLUSTER) {
                return superUser && op == OperationType.ALL;
            }
            return grants.getOrDefault(r.getName(), Collections.emptySet()).contains(op);
        }

        @Override
        public void authorize(Session s, OperationType op, Resource r) {
            if (!isAuthorized(s, op, r)) {
                throw new AuthorizationException("denied");
            }
        }

        @Override
        public Collection<Resource> filterByAuthorized(
                Session s, OperationType op, List<Resource> resources) {
            return resources.stream()
                    .filter(r -> isAuthorized(s, op, r))
                    .collect(Collectors.toList());
        }

        @Override
        public List<AclCreateResult> addAcls(Session s, List<AclBinding> bindings) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<AclDeleteResult> dropAcls(Session s, List<AclBindingFilter> filters) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Collection<AclBinding> listAcls(Session s, AclBindingFilter filter) {
            throw new UnsupportedOperationException();
        }
    }
}

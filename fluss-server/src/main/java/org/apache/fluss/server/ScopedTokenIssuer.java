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
import org.apache.fluss.security.acl.OperationType;
import org.apache.fluss.security.acl.Resource;
import org.apache.fluss.server.authorizer.Authorizer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

/**
 * Decides which file system token a caller gets when an authorizer is configured. A caller
 * authorized for everything on the cluster (a super user) gets the shared token. Anyone else gets a
 * token for the kv and log directories of the databases they may read, writable where they may
 * write. A caller who may access no database gets no token. Scoped tokens are cached per scope.
 */
final class ScopedTokenIssuer {

    /** Where the tokens come from. */
    interface TokenSource {
        /** The token for the whole remote file system. */
        ObtainedSecurityToken shared() throws IOException;

        /** A token limited to the scope; fails if the file system cannot limit tokens. */
        ObtainedSecurityToken scoped(TokenScope scope) throws IOException;
    }

    private final Authorizer authorizer;
    private final Supplier<? extends Iterable<String>> databases;
    private final Supplier<List<String>> remoteDataDirs;
    private final TokenSource source;
    private final long ttlMs;
    private final Map<String, Cached> cache = new HashMap<>();

    ScopedTokenIssuer(
            Authorizer authorizer,
            Supplier<? extends Iterable<String>> databases,
            Supplier<List<String>> remoteDataDirs,
            TokenSource source,
            long ttlMs) {
        this.authorizer = authorizer;
        this.databases = databases;
        this.remoteDataDirs = remoteDataDirs;
        this.source = source;
        this.ttlMs = ttlMs;
    }

    ObtainedSecurityToken issue(Session session, long nowMs) throws IOException {
        if (authorizer.isAuthorized(session, OperationType.ALL, Resource.cluster())) {
            return source.shared();
        }

        List<Resource> all = new ArrayList<>();
        for (String database : databases.get()) {
            all.add(Resource.database(database));
        }
        Set<String> writable = new TreeSet<>();
        for (Resource r : authorizer.filterByAuthorized(session, OperationType.WRITE, all)) {
            writable.add(r.getName());
        }
        Set<String> readable = new TreeSet<>();
        for (Resource r : authorizer.filterByAuthorized(session, OperationType.READ, all)) {
            readable.add(r.getName());
        }
        readable.removeAll(writable);
        TokenScope scope = new TokenScope(dirs(readable), dirs(writable));
        if (scope.isEmpty()) {
            throw new AuthorizationException(
                    "No authorization to read or write any database, "
                            + "so no file access token is issued.");
        }

        String key = scope.cacheKey();
        synchronized (cache) {
            cache.values().removeIf(c -> nowMs - c.obtainedAtMs > ttlMs);
            Cached cached = cache.get(key);
            if (cached == null) {
                cached = new Cached(source.scoped(scope), nowMs);
                cache.put(key, cached);
            }
            return cached.token;
        }
    }

    /** The remote kv and log directories of the databases, under every remote data directory. */
    private List<FsPath> dirs(Set<String> databaseNames) {
        List<FsPath> dirs = new ArrayList<>();
        for (String database : databaseNames) {
            for (String root : remoteDataDirs.get()) {
                for (String kind : new String[] {"kv", "log"}) {
                    dirs.add(new FsPath(new FsPath(root, kind), database));
                }
            }
        }
        return dirs;
    }

    private static final class Cached {
        final ObtainedSecurityToken token;
        final long obtainedAtMs;

        Cached(ObtainedSecurityToken token, long obtainedAtMs) {
            this.token = token;
            this.obtainedAtMs = obtainedAtMs;
        }
    }
}

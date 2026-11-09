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

package org.apache.fluss.fs.token;

import org.apache.fluss.fs.FsPath;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The part of a remote file system that a security token may reach: a set of directory prefixes,
 * some read-only and some read-write. A token issued for a scope must not allow access to any
 * object outside these prefixes.
 */
public final class TokenScope {

    private final List<FsPath> readOnly;
    private final List<FsPath> readWrite;

    public TokenScope(List<FsPath> readOnly, List<FsPath> readWrite) {
        this.readOnly = Collections.unmodifiableList(new ArrayList<>(readOnly));
        this.readWrite = Collections.unmodifiableList(new ArrayList<>(readWrite));
    }

    /** Directories the token may only read (get and list). */
    public List<FsPath> getReadOnly() {
        return readOnly;
    }

    /** Directories the token may read, write and delete in. */
    public List<FsPath> getReadWrite() {
        return readWrite;
    }

    public boolean isEmpty() {
        return readOnly.isEmpty() && readWrite.isEmpty();
    }

    /** A stable text form, usable as a cache key. */
    public String cacheKey() {
        return "ro=" + readOnly + ";rw=" + readWrite;
    }

    @Override
    public String toString() {
        return "TokenScope{" + cacheKey() + "}";
    }
}

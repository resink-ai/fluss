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

import org.apache.fluss.annotation.Internal;

import javax.annotation.Nullable;

/**
 * Tells a file system which client connection the current thread is reading for, so that it uses
 * that connection's security token. Tokens of connections in the same JVM (for example the jobs of
 * different tenants on one Flink TaskManager) are otherwise indistinguishable and overwrite each
 * other.
 */
@Internal
public final class TokenOwner {

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private TokenOwner() {}

    /** The connection the current thread reads for, or null if the thread is not bound. */
    @Nullable
    public static String current() {
        return CURRENT.get();
    }

    /** Wraps the task so that, while it runs, the thread is bound to the owner. */
    public static Runnable bind(@Nullable String owner, Runnable task) {
        if (owner == null) {
            return task;
        }
        return () -> {
            String previous = CURRENT.get();
            CURRENT.set(owner);
            try {
                task.run();
            } finally {
                if (previous == null) {
                    CURRENT.remove();
                } else {
                    CURRENT.set(previous);
                }
            }
        };
    }
}

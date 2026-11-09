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

/**
 * FileSystem security token receiver API. Currently, instances of {@link SecurityTokenReceiver}s
 * are loaded in client side through service loader.
 */
public interface SecurityTokenReceiver {

    /** Scheme of the filesystem to receive security tokens for. This name should be unique. */
    String scheme();

    /**
     * Callback function when new security tokens obtained.
     *
     * @param token security token obtained
     */
    void onNewTokensObtained(ObtainedSecurityToken token) throws Exception;

    /**
     * Callback function when new security tokens obtained for one client connection. Receivers that
     * can keep the tokens of several connections apart override this and use {@link
     * TokenOwner#current()} when they read; the default keeps one token for the whole JVM.
     *
     * @param owner the connection the token belongs to
     * @param token security token obtained
     */
    default void onNewTokensObtained(String owner, ObtainedSecurityToken token) throws Exception {
        onNewTokensObtained(token);
    }

    /** The connection is closed; forget what was kept for it. */
    default void onOwnerClosed(String owner) {}
}

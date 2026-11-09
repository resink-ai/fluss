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

package org.apache.fluss.client.table.scanner;

import org.apache.fluss.fs.FsPath;
import org.apache.fluss.fs.FsPathAndFileName;
import org.apache.fluss.fs.token.TokenOwner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/** Tests that a connection's downloads run bound to that connection's token owner. */
class RemoteFileDownloaderTokenOwnerTest {

    @Test
    void testDownloadThreadsAreBoundToTheirConnection(@TempDir Path dir) throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        try (RemoteFileDownloader a = recording(seen, "conn-a");
                RemoteFileDownloader b = recording(seen, "conn-b");
                RemoteFileDownloader unbound = recording(seen, null)) {
            FsPathAndFileName file = new FsPathAndFileName(new FsPath("s3://b/x"), "x");
            a.downloadFileAsync(file, dir).get();
            b.downloadFileAsync(file, dir).get();
            unbound.downloadFileAsync(file, dir).get();
        }
        assertThat(seen).containsExactly("conn-a", "conn-b", "none");
        assertThat(TokenOwner.current()).isNull();
    }

    private static RemoteFileDownloader recording(List<String> seen, String owner) {
        return new RemoteFileDownloader(1, owner) {
            @Override
            protected long downloadFile(Path target, FsPath remote) {
                String current = TokenOwner.current();
                seen.add(current == null ? "none" : current);
                return 0;
            }
        };
    }
}

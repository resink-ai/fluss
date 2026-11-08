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

package org.apache.fluss.flink.catalog;

import org.apache.fluss.testutils.common.MultiVersionTest;

import org.apache.flink.api.common.JobID;
import org.apache.flink.table.catalog.CatalogMaterializedTable;
import org.apache.flink.table.catalog.ObjectIdentifier;
import org.apache.flink.table.gateway.api.operation.OperationHandle;
import org.apache.flink.table.refresh.ContinuousRefreshHandler;
import org.apache.flink.table.refresh.ContinuousRefreshHandlerSerializer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.apache.flink.table.gateway.service.utils.SqlGatewayServiceTestUtil.awaitOperationTermination;
import static org.apache.flink.test.util.TestUtils.waitUntilAllTasksAreRunning;
import static org.assertj.core.api.Assertions.assertThat;

/** IT case for materialized table in Flink 2.3. */
public class Flink23MaterializedTableITCase extends MaterializedTableITCase {

    @Test
    @MultiVersionTest
    void testAlterMaterializedTableAsQuery(@TempDir Path temporaryPath) throws Exception {
        execute(
                String.format(
                        "SET 'execution.checkpointing.savepoint-dir' = 'file://%s'",
                        temporaryPath));
        ObjectIdentifier id = ObjectIdentifier.of(CATALOG_NAME, DEFAULT_DB, "shop_detail");
        execute(
                "CREATE MATERIALIZED TABLE shop_detail\n"
                        + " FRESHNESS = INTERVAL '3' SECOND\n"
                        + " AS SELECT user_id, shop_id FROM datagenSource");

        ContinuousRefreshHandler handler =
                ContinuousRefreshHandlerSerializer.INSTANCE.deserialize(
                        ((CatalogMaterializedTable) service.getTable(sessionHandle, id))
                                .getSerializedRefreshHandler(),
                        getClass().getClassLoader());
        waitUntilAllTasksAreRunning(restClusterClient, JobID.fromHexString(handler.getJobId()));

        // a new nullable column at the end is an allowed change of the query
        execute(
                "ALTER MATERIALIZED TABLE shop_detail AS "
                        + "SELECT user_id, shop_id, payment_amount_cents FROM datagenSource");

        CatalogMaterializedTable table =
                (CatalogMaterializedTable) service.getTable(sessionHandle, id);
        assertThat(table.getExpandedQuery()).contains("payment_amount_cents");
        assertThat(table.getOriginalQuery()).contains("payment_amount_cents");
        assertThat(table.getUnresolvedSchema().getColumns()).hasSize(3);
        assertThat(table.getRefreshStatus())
                .isEqualTo(CatalogMaterializedTable.RefreshStatus.ACTIVATED);

        dropMaterializedTable(id);
    }

    private void execute(String statement) throws Exception {
        OperationHandle handle =
                service.executeStatement(
                        sessionHandle,
                        statement,
                        -1,
                        new org.apache.flink.configuration.Configuration());
        awaitOperationTermination(service, sessionHandle, handle);
    }
}

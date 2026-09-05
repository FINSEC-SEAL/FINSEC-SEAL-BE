package com.finsecseal.sandbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
@SpringBootTest
class Fa04SandboxExfilSchemaContractIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:17.11-alpine");

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Test
    void sandboxExfilEventsCarriesMandatoryCaseRunProvenance() {
        List<Map<String, Object>> columns = jdbcTemplate.queryForList("""
                select column_name, is_nullable
                  from information_schema.columns
                 where table_schema = 'public'
                   and table_name = 'sandbox_exfil_events'
                   and column_name = 'test_case_run_id'
                """);

        assertThat(columns)
                .singleElement()
                .satisfies(column ->
                        assertThat(column.get("is_nullable")).isEqualTo("NO")
                );

        Integer foreignKeyCount = jdbcTemplate.queryForObject("""
                select count(*)
                  from pg_constraint constraint_row
                  join pg_class source_table
                    on source_table.oid = constraint_row.conrelid
                  join pg_class target_table
                    on target_table.oid = constraint_row.confrelid
                 where constraint_row.contype = 'f'
                   and source_table.relname = 'sandbox_exfil_events'
                   and target_table.relname = 'test_case_runs'
                """, Integer.class);

        assertThat(foreignKeyCount).isEqualTo(1);
    }
}

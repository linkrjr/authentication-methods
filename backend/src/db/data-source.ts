import "reflect-metadata";
import { DataSource } from "typeorm";
import { BunSqliteDatabase } from "./bun-sqlite-driver";
import { entities } from "./entities";

export function createDataSource(databasePath: string): DataSource {
  return new DataSource({
    type: "better-sqlite3",
    driver: BunSqliteDatabase,
    database: databasePath,
    entities,
    // Demo convenience: schema is derived from the entities. A real deployment would use migrations.
    synchronize: true,
    logging: false,
  });
}

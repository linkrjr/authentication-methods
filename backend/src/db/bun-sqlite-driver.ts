import { Database, type Statement } from "bun:sqlite";

/**
 * Bun cannot load the native `better-sqlite3` addon, but `bun:sqlite` exposes a
 * near-identical synchronous API. TypeORM's better-sqlite3 driver accepts a
 * custom `driver` constructor, so this adapter implements exactly the surface
 * TypeORM uses: `new (file, opts)`, `prepare`, `pragma`, `close`, and
 * statements with `reader` / `all` / `run`.
 */
type Param = string | number | bigint | boolean | null | Uint8Array;

class BunStatement {
  readonly reader: boolean;

  constructor(private readonly stmt: Statement) {
    this.reader = stmt.columnNames.length > 0;
  }

  all(...params: Param[]): unknown[] {
    return this.stmt.all(...params);
  }

  run(...params: Param[]): { changes: number; lastInsertRowid: number | bigint } {
    return this.stmt.run(...params);
  }
}

export class BunSqliteDatabase {
  private readonly db: Database;

  constructor(filename: string, options: { readonly?: boolean; fileMustExist?: boolean } = {}) {
    this.db = new Database(filename, {
      readonly: options.readonly ?? false,
      create: !options.fileMustExist,
    });
  }

  prepare(sql: string): BunStatement {
    return new BunStatement(this.db.prepare(sql));
  }

  pragma(source: string): unknown[] {
    return this.db.prepare(`PRAGMA ${source}`).all();
  }

  close(): void {
    this.db.close();
  }
}

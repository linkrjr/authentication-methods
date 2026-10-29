import { config } from "../config";
import { createDataSource } from "./data-source";
import { AuthEvent } from "./entities";

export const db = createDataSource(config.databasePath);

export async function recordEvent(event: {
  type: string;
  success: boolean;
  userId?: string | null;
  detail?: string | null;
  ip?: string | null;
  userAgent?: string | null;
}): Promise<void> {
  await db.getRepository(AuthEvent).insert({
    type: event.type,
    success: event.success,
    userId: event.userId ?? null,
    detail: event.detail ?? null,
    ip: event.ip ?? null,
    userAgent: event.userAgent ?? null,
    createdAt: new Date(),
  });
}

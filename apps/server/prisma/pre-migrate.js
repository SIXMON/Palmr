/**
 * Pre-migration cleanup script.
 *
 * Runs BEFORE `prisma db push` on every container start so existing
 * databases can be upgraded to the current schema without --force-reset.
 *
 * Why it exists:
 *   The schema used to declare `Share.creatorId` as optional with
 *   `onDelete: SetNull`. That left orphan shares behind every time a
 *   user got deleted — rows with `creatorId IS NULL`. The current
 *   schema requires `creatorId` and cascades on user delete, so the
 *   migration adds a NOT NULL constraint. SQLite (and Postgres) refuse
 *   to add NOT NULL on a column that already holds NULLs, so prisma db
 *   push aborts with:
 *
 *     ⚠️ We found changes that cannot be executed:
 *       • Made the column `creatorId` on table `shares` required,
 *         but there are N existing NULL values.
 *
 *   Those orphan shares were already permanently inert (every
 *   ownership check in the codebase fails when creatorId !== userId,
 *   and NULL never matches), so dropping them is a safe upgrade path.
 *
 * The script is idempotent — re-running it on an already-clean
 * database is a no-op.
 */
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function main() {
  // Use $executeRawUnsafe so the query is sent verbatim to SQLite,
  // bypassing the (now NOT NULL) typing on the model. Order matters:
  // delete the linked ShareSecurity rows first to avoid leaving them
  // dangling, then the orphan shares themselves.
  await prisma.$executeRawUnsafe(
    `DELETE FROM share_security WHERE id IN (SELECT securityId FROM shares WHERE creatorId IS NULL)`
  );
  const sharesDeleted = await prisma.$executeRawUnsafe(`DELETE FROM shares WHERE creatorId IS NULL`);

  if (sharesDeleted > 0) {
    console.log(`🧹 [pre-migrate] removed ${sharesDeleted} orphan share(s) with creatorId IS NULL`);
  }
}

main()
  .catch((err) => {
    // Surface the error but don't abort: the user's existing DB may not
    // even have the `shares` table yet (very old install, or first boot
    // after a wipe). prisma db push will then create it from scratch.
    console.warn("[pre-migrate] cleanup skipped:", err.message || err);
  })
  .finally(() => prisma.$disconnect());

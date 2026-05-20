import { randomBytes } from "crypto";
import { NextResponse } from "next/server";

// Generates a 64-character alphanumeric key for the doc site's "JWT
// secret" helper. The previous implementation shelled out to
// `openssl | tr | head` via execSync — which depended on the PATH
// resolving to the expected binaries (Sonar S4036) and added a fork
// per request for no gain. crypto.randomBytes is a syscall-backed
// CSPRNG and skips the shell entirely.
//
// We over-sample (48 bytes → 64 base64 chars → filter non-alphanum →
// retry if too short) so the output is always exactly 64 chars even
// after stripping `+`/`/`/`=`.
export async function GET() {
  try {
    let key = "";
    while (key.length < 64) {
      key += randomBytes(48).toString("base64").replace(/[^A-Za-z0-9]/g, "");
    }
    return NextResponse.json({ key: key.slice(0, 64) });
  } catch (error) {
    console.error("Failed to generate key:", error);
    return NextResponse.json({ error: "Failed to generate key" }, { status: 500 });
  }
}

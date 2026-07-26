// Drive the streamed review against Speculos, the way a host must: send one
// chunk, wait for the human to read that page, send the next.
//
//   node tests/drive_streaming.mjs [body-length]
//
// It prints every screen the device shows, so you can see the whole message go
// past — and it verifies the returned ed25519 signature covers exactly the
// bytes that were streamed in.
import { createHash } from "node:crypto";

const BASE = process.env.APP_URL || "http://127.0.0.1:5002";
const CLA = 0xe0, INS_PK = 0x05, INS_SIGN = 0x06;
const PATH = [0x8000002c, 0x80000001, 0x80000000, 0, 0];
const CHUNK = 255;
const BODY_LEN = Number(process.argv[2] || 900);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const post = (p, b) => fetch(BASE + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(b) });
const screen = async () => {
  const j = await (await fetch(BASE + "/events?currentscreenonly=true")).json();
  return (j.events || []).map((e) => ({ t: e.text, x: e.x, y: e.y }));
};
const swipe = async () => { await post("/finger", { action: "press", x: 340, y: 400 }); await sleep(100); await post("/finger", { action: "release", x: 60, y: 400 }); };

// Speculos speaks raw APDUs over its /apdu endpoint.
async function apdu(bytes) {
  const r = await post("/apdu", { data: Buffer.from(bytes).toString("hex") });
  return Buffer.from((await r.json()).data, "hex");
}
const frame = (ins, p1, p2, data) => Buffer.concat([Buffer.from([CLA, ins, p1, p2, data.length]), data]);
function pathChunk() {
  const b = Buffer.alloc(1 + PATH.length * 4);
  b[0] = PATH.length;
  PATH.forEach((e, i) => b.writeUInt32BE(e >>> 0, 1 + i * 4));
  return b;
}
const text = (s) => { const b = Buffer.from(s, "ascii"); return Buffer.concat([Buffer.from([b.length]), b]); };

// Read pages until the device answers the APDU we are waiting on.
async function readPagesUntilDone(pending, label) {
  let last = "";
  for (let i = 0; i < 60; i++) {
    const done = await Promise.race([pending.then(() => true), sleep(400).then(() => false)]);
    if (done) return;
    const s = await screen();
    const t = s.map((e) => e.t).join(" | ");
    if (t && t !== last) { console.log(`   [${label}] ${t}`); last = t; }
    const hold = s.find((e) => /hold to (sign|approve)/i.test(e.t));
    if (hold) {
      await post("/finger", { action: "press", x: hold.x, y: hold.y });
      await sleep(3500);
      await post("/finger", { action: "release", x: hold.x, y: hold.y });
      await sleep(600);
    } else {
      await swipe();
    }
  }
  throw new Error("device never answered");
}

async function main() {
  const body = Array.from({ length: BODY_LEN }, (_, i) => (i % 60 === 59 ? "\n" : String.fromCharCode(97 + (i % 26)))).join("");
  const header = Buffer.concat([
    Buffer.alloc(16, 0x11),                       // challenge
    text("agent@hardmail.local"),
    text("boss@example.com"),
    text("Q3 report is ready for review"),
    Buffer.from([0]),                             // no attachment
    (() => { const b = Buffer.alloc(4); b.writeUInt32BE(body.length); return b; })(),
  ]);
  const framed = Buffer.concat([(() => { const b = Buffer.alloc(2); b.writeUInt16BE(header.length); return b; })(), header]);

  const pieces = [];
  for (let i = 0; i < framed.length; i += CHUNK) pieces.push(framed.subarray(i, i + CHUNK));
  const headerPieces = pieces.length;
  const bodyBuf = Buffer.from(body, "ascii");
  for (let i = 0; i < bodyBuf.length; i += CHUNK) pieces.push(bodyBuf.subarray(i, i + CHUNK));

  console.log(`streaming an email with a ${body.length}-byte body`);
  console.log(`  header ${header.length}B in ${headerPieces} chunk(s), body in ${pieces.length - headerPieces} chunk(s)\n`);

  const pk = await apdu(frame(INS_PK, 0, 0, pathChunk()));
  if (pk.slice(-2).toString("hex") !== "9000") throw new Error("get_public_key failed");
  const rawKey = pk.slice(1, 1 + pk[0]).slice(1, 33);

  await apdu(frame(INS_SIGN, 0, 0x80, pathChunk()));  // path

  let resp;
  for (let i = 0; i < pieces.length; i++) {
    const isLast = i === pieces.length - 1;
    // P1 just has to be non-zero for a payload chunk; it wraps freely.
    const pending = apdu(frame(INS_SIGN, (i % 255) + 1, isLast ? 0x00 : 0x80, pieces[i]));
    // Chunks before the header is complete come back at once; from the last
    // header chunk onward the device waits for the human.
    if (i + 1 >= headerPieces) await readPagesUntilDone(pending, isLast ? "sign" : `chunk ${i + 1}`);
    resp = await pending;
    const sw = resp.slice(-2).toString("hex");
    if (!isLast && sw !== "9000") throw new Error(`chunk ${i + 1} -> SW=${sw}`);
    if (isLast && sw !== "9000") throw new Error(`final chunk -> SW=${sw}`);
  }

  const sig = resp.slice(1, 1 + resp[0]);
  const digest = createHash("sha256").update(Buffer.concat(pieces)).digest();
  const { createPublicKey, verify } = await import("node:crypto");
  const key = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawKey]),
    format: "der",
    type: "spki",
  });
  const ok = verify(null, digest, key, sig);
  console.log(`\nsignature ${sig.length}B over sha256(streamed bytes): ${ok ? "VERIFIES ✔" : "DOES NOT VERIFY ✗"}`);
  process.exit(ok ? 0 : 1);
}

main().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });

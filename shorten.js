import crypto from "crypto";
import { redis } from "./_redis.js";

const rand = () => Math.random().toString(36).slice(2, 8);

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "POST فقط" });
  const { url, alias, password } = req.body || {};

  let u;
  try { u = new URL(url); } catch { return res.status(400).json({ error: "الرابط غير صالح" }); }
  if (!["http:", "https:"].includes(u.protocol)) return res.status(400).json({ error: "الرابط يجب أن يبدأ بـ http أو https" });
  if (alias && !/^[a-zA-Z0-9_-]{3,30}$/.test(alias)) return res.status(400).json({ error: "الاسم المخصص: حروف إنجليزية وأرقام، من 3 إلى 30" });
  if (password !== undefined && (typeof password !== "string" || password.length < 4 || password.length > 64))
    return res.status(400).json({ error: "كلمة المرور من 4 إلى 64 حرفاً" });

  const record = { u: u.href };
  if (password) {
    record.s = crypto.randomBytes(16).toString("hex");
    record.h = crypto.scryptSync(password, record.s, 32).toString("hex");
  }

  for (let i = 0; i < 5; i++) {
    const code = alias || rand();
    const ok = await redis(["SET", "l:" + code, JSON.stringify(record), "NX"]);
    if (ok === "OK") {
      const host = req.headers["x-forwarded-host"] || req.headers.host;
      return res.status(200).json({ short: `https://${host}/${code}`, locked: !!password });
    }
    if (alias) return res.status(409).json({ error: "هذا الاسم مستخدم، جرّب غيره" });
  }
  res.status(500).json({ error: "تعذّر إنشاء الرابط، أعد المحاولة" });
}

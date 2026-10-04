import crypto from "crypto";
import { redis } from "./_redis.js";

const CODE_RE = /^[a-zA-Z0-9_-]{3,30}$/;

async function load(code) {
  const raw = await redis(["GET", "l:" + code]);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return { u: raw }; }
}

const lockPage = code => `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>رابط مقفول | اختصار روابط</title>
<style>
:root{--bg:#f3f5f2;--card:#fff;--ink:#16221c;--mute:#5d6b63;--line:#d5ddd7;--accent:#0f6b4f;--accent-ink:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#101612;--card:#18211b;--ink:#e8efe9;--mute:#97a69c;--line:#2a372e;--accent:#4cc79a;--accent-ink:#06130d}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:var(--bg);color:var(--ink);font-family:Tahoma,system-ui,sans-serif}
.box{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px}
h1{font-size:1.2rem;margin:0 0 6px}p{margin:0 0 14px;color:var(--mute);font-size:.9rem}
input{width:100%;padding:11px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
button{font:inherit;cursor:pointer;width:100%;margin-top:12px;padding:12px;border:0;border-radius:8px;background:var(--accent);color:var(--accent-ink);font-weight:700}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}.err{color:#b3261e;font-size:.88rem;margin-top:10px;min-height:1.2em}
</style></head><body><div class="box">
<h1>هذا الرابط مقفول</h1><p>ادخل كلمة المرور للمتابعة.</p>
<input id="pw" type="password" placeholder="كلمة المرور" autocomplete="off">
<button id="ok" type="button">فتح الرابط</button><div class="err" id="err" role="alert"></div>
</div><script>
const go=async()=>{
  const b=document.getElementById("ok"),e=document.getElementById("err");e.textContent="";b.disabled=true;
  try{
    const r=await fetch("/api/go?code=${code}",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:document.getElementById("pw").value})});
    const d=await r.json();if(!r.ok)throw new Error(d.error||"خطأ");location.href=d.url;
  }catch(x){e.textContent=x.message;b.disabled=false}
};
document.getElementById("ok").onclick=go;
document.getElementById("pw").onkeydown=e=>{if(e.key==="Enter")go()};
</script></body></html>`;

export default async function handler(req, res) {
  const code = String(req.query.code || "");
  if (!CODE_RE.test(code)) return res.status(404).send("الرابط غير موجود");
  const rec = await load(code);
  if (!rec) return res.status(404).send("الرابط غير موجود");
  res.setHeader("Cache-Control", "no-store");

  // فتح الصفحة
  if (req.method === "GET") {
    if (!rec.h) return res.redirect(302, rec.u);
    return res.status(200).setHeader("Content-Type", "text/html; charset=utf-8").send(lockPage(code));
  }

  // التحقق من كلمة المرور
  if (req.method === "POST") {
    if (!rec.h) return res.status(200).json({ url: rec.u });

    const ip = (req.headers["x-forwarded-for"] || "x").split(",")[0].trim();
    const key = `a:${code}:${ip}`;
    const tries = await redis(["INCR", key]);
    if (tries === 1) await redis(["EXPIRE", key, 600]);
    if (tries > 10) return res.status(429).json({ error: "محاولات كثيرة، انتظر 10 دقائق" });

    const pw = String((req.body || {}).password || "");
    const h = crypto.scryptSync(pw, rec.s, 32);
    const ok = crypto.timingSafeEqual(h, Buffer.from(rec.h, "hex"));
    if (!ok) return res.status(401).json({ error: "كلمة المرور غير صحيحة" });
    return res.status(200).json({ url: rec.u });
  }

  res.status(405).end();
}

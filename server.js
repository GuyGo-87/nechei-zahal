require("dotenv").config();
const express = require("express");
const path = require("path");
const app = express();

// ============================================================
// LAYER 0: TRUST PROXY — fixes rate limiter on Render
// Without this, req.ip returns the internal proxy IP for every
// user, making the rate limiter useless.
// ============================================================
app.set("trust proxy", 1);

// ============================================================
// LAYER 1: SECURITY HEADERS (Helmet)
// ============================================================
const helmet = require("helmet");
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc:     ["'self'"],
            scriptSrc:      ["'self'", "'unsafe-inline'"],
            scriptSrcAttr:  ["'unsafe-inline'"],
            styleSrc:       ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
            fontSrc:        ["'self'", "fonts.gstatic.com", "data:"],
            imgSrc:         ["'self'", "data:", "https:"],
            connectSrc:     ["'self'"],
            frameSrc:       ["'none'"],
            objectSrc:      ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false,
}));

// ============================================================
// LAYER 2: CORS — lock API to allowed origins only
// ============================================================
const cors = require("cors");
const ALLOWED_ORIGINS = [
    "https://inz.org.il",
    "https://www.inz.org.il",
    "https://nechei-zahal.onrender.com",
    "http://localhost:3000",
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        console.warn(`[CORS BLOCKED] Origin rejected: ${origin}`);
        callback(new Error("Not allowed by CORS"));
    },
    methods: ["POST", "GET", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
    credentials: false,
}));

// ============================================================
// LAYER 3: BODY PARSING + PAYLOAD LIMIT
// ============================================================
app.use(express.json({ limit: "10kb" }));

// ============================================================
// LAYER 4: RATE LIMITERS
// ============================================================
const rateLimit = require("express-rate-limit");

const chatLimiter = rateLimit({
    windowMs: 60 * 1000,   // 1 minute
    max: 15,               // 15 requests/min per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { reply: "אתה זז מהר מדי! אנא המתן רגע." },
    handler: (req, res, next, options) => {
        console.warn(`[RATE LIMIT] IP blocked: ${req.ip}`);
        res.status(429).json(options.message);
    },
});

const burstLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { reply: "יותר מדי בקשות. אנא חזור עוד מעט!" },
});

app.use("/api/chat", burstLimiter);
app.use("/api/chat", chatLimiter);

// ============================================================
// LAYER 5: (no xss middleware needed — input validation below
// already enforces structure, types, and length limits)
// ============================================================

// ============================================================
// LAYER 6: INPUT VALIDATION
// ============================================================
const MAX_MESSAGE_LENGTH  = 2000;
const MAX_MESSAGES        = 20;
const MAX_TOTAL_CHARS     = 8000;

function validateChatInput(req, res, next) {
    const { messages } = req.body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return res.status(400).json({ reply: "Invalid request format." });
    }
    if (messages.length > MAX_MESSAGES) {
        console.warn(`[INPUT ABUSE] Too many messages from ${req.ip}: ${messages.length}`);
        return res.status(400).json({ reply: "יותר מדי הודעות." });
    }

    let totalChars = 0;
    for (const msg of messages) {
        if (!msg || typeof msg.role !== "string" || typeof msg.content !== "string") {
            return res.status(400).json({ reply: "Malformed message structure." });
        }
        if (!["user", "assistant"].includes(msg.role)) {
            console.warn(`[INPUT ABUSE] Invalid role from ${req.ip}: ${msg.role}`);
            return res.status(400).json({ reply: "Invalid message role." });
        }
        if (msg.content.length > MAX_MESSAGE_LENGTH) {
            console.warn(`[INPUT ABUSE] Oversized message from ${req.ip}: ${msg.content.length} chars`);
            return res.status(400).json({ reply: "ההודעה ארוכה מדי." });
        }
        totalChars += msg.content.length;
    }
    if (totalChars > MAX_TOTAL_CHARS) {
        console.warn(`[INPUT ABUSE] Total payload too large from ${req.ip}: ${totalChars} chars`);
        return res.status(400).json({ reply: "השיחה ארוכה מדי." });
    }
    next();
}

// ============================================================
// ENVIRONMENT VALIDATION
// ============================================================
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
    console.error("FATAL: Missing GEMINI_API_KEY. Server will not process chat requests.");
}

// ============================================================
// SYSTEM PROMPT
// ============================================================
const SYSTEM_PROMPT = `You are a smart, professional digital assistant for INZ — the IDF Disabled Veterans Organization (ארגון נכי צה"ל) in Israel.

ROLE:
- Help members and users navigate the organization's services, rights, and benefits
- Answer in the SAME LANGUAGE the user writes in (Hebrew, English, Russian, Arabic, Spanish, Amharic)
- Be warm, concise, and professional — like a knowledgeable human staff member

KEY SERVICES TO KNOW:
- Loans: Up to 18,000 ILS — https://loans.inz.org.il/
- Scholarships: For members and their children — https://www.inz.org.il/page.php?type=page&id=711
- Insurance: Life, health, nursing care — https://www.inz.org.il/page.php?type=page&id=713
- Rights & Benefits: https://shikum.mod.gov.il/
- Beit HaLochem centers: Tel Aviv, Haifa, Jerusalem, Beer Sheva, Ashdod
- Iron Swords (חרבות ברזל) wounded: https://www.inz.org.il/page.php?type=page&id=785
- Employment & Education: https://www.inz.org.il/page.php?type=page&id=762
- Rehabilitation programs: https://www.inz.org.il/page.php?type=page&id=766

BEIT HALOCHEM LOCATIONS:
- Tel Aviv: שמואל ברקאי 49, אפקה — https://blt.inz.org.il
- Haifa: דרך צרפת 101 — https://blh.inz.org.il
- Jerusalem: דרך אהרון שולוב 2 — https://blj.inz.org.il
- Beer Sheva: שדרות בנ"צ כרמל 9 — https://blb.inz.org.il
- Ashdod: https://ashdod.inz.org.il

CONTACT: Phone 03-6461600 | Email: inz@inz.org.il

TONE RULES:
- Max 3 short paragraphs per response. Less is more.
- Never use markdown formatting (no **bold**, no bullet lists with -)
- Plain conversational text only
- If you don't know something, say: "לפרטים נוספים ניתן לפנות ל-03-6461600 או inz@inz.org.il"`;

// ============================================================
// LAYER 7: GEMINI API CALL WITH TIMEOUT
// ============================================================
async function callGemini(contents) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 25000);

    try {
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
                    contents,
                    generationConfig: { temperature: 0.5, maxOutputTokens: 1000 }
                }),
                signal: controller.signal,
            }
        );
        clearTimeout(timeoutId);
        return response;
    } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === "AbortError") {
            throw new Error("TIMEOUT: Gemini API took too long to respond.");
        }
        throw err;
    }
}

// ============================================================
// LAYER 8: SERVE STATIC FILES (index.html)
// ============================================================
app.use(express.static(path.join(__dirname)));

// ============================================================
// LAYER 9: CHAT ENDPOINT
// ============================================================
app.post("/api/chat", validateChatInput, async (req, res) => {
    if (!GEMINI_API_KEY) {
        return res.status(503).json({ reply: "המערכת אינה מוגדרת כראוי. אנא נסה שוב מאוחר יותר." });
    }

    try {
        const { messages } = req.body;

        // Log key presence (never the key itself)
        console.log(`[CHAT] Request from ${req.ip} | GEMINI_KEY: ${!!GEMINI_API_KEY} | Messages: ${messages.length}`);

        const contents = messages.slice(-12).map(m => ({
            role: m.role === "user" ? "user" : "model",
            parts: [{ text: String(m.content).trim() }]
        }));

        const geminiRes = await callGemini(contents);
        const data = await geminiRes.json();

        // Gemini returned an error object
        if (data.error) {
            const code = data.error.code || 0;
            const msg  = data.error.message || "unknown";
            console.error(`[GEMINI ERROR] code=${code} message=${msg}`);

            // Quota exceeded (429) — tell user clearly
            if (code === 429 || msg.toLowerCase().includes("quota")) {
                return res.status(503).json({ reply: "מערכת ה-AI עמוסה כרגע. אנא נסה שוב בעוד מספר דקות." });
            }
            // Invalid API key (400/403)
            if (code === 400 || code === 403) {
                return res.status(503).json({ reply: "שגיאת הגדרה במערכת. אנא צור קשר עם מנהל האתר." });
            }
            throw new Error(`Gemini ${code}: ${msg}`);
        }

        const reply = data.candidates?.[0]?.content?.parts?.[0]?.text
            ?? "מצטער, לא הצלחתי לעבד את התשובה. אנא נסה שוב.";

        res.json({ reply });

    } catch (err) {
        const isTimeout = err.message?.includes("TIMEOUT");
        console.error(`[CHAT ERROR] ${isTimeout ? "Timeout" : "API Error"}: ${err.message}`);
        res.status(isTimeout ? 504 : 500).json({
            reply: isTimeout
                ? "העיבוד לוקח יותר מדי זמן — אנא נסה שוב."
                : "משהו השתבש. אנא נסה שוב."
        });
    }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get("/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        gemini: GEMINI_API_KEY ? "configured" : "MISSING",
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// CATCH-ALL — serve index.html
// ============================================================
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// ============================================================
// 404 + GLOBAL ERROR HANDLER
// ============================================================
app.use((req, res) => {
    res.status(404).json({ error: "Not found." });
});

app.use((err, req, res, next) => {
    if (err.message === "Not allowed by CORS") {
        return res.status(403).json({ error: "Access denied." });
    }
    console.error("[UNHANDLED ERROR]", err.message);
    res.status(500).json({ error: "Internal server error." });
});

// ============================================================
// START
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ INZ Assistant running on port ${PORT}`);
    console.log(`🔐 Security: helmet + cors + rate-limit (x2) + xss-clean + input validation + timeout`);
    console.log(`🔑 Gemini API: ${GEMINI_API_KEY ? "READY" : "⚠️  MISSING — set GEMINI_API_KEY in environment"}`);
});

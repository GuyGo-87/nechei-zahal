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
const SYSTEM_PROMPT = `You are an advanced, proactive digital assistant for INZ — the IDF Disabled Veterans Organization (ארגון נכי צה"ל) in Israel.

CORE MISSION:
You don't just answer questions — you proactively help members find the best services for them personally.
Always think: "What does this person actually need right now?" and offer next steps, relevant programs, and navigation help.

LANGUAGE — CRITICAL RULE:
Always respond in the EXACT SAME LANGUAGE the user writes in. If the conversation starts with a system message saying "respond only in English", you MUST respond in English for ALL messages. NEVER switch to Hebrew unless the user writes in Hebrew. This rule overrides everything else. Supported: Hebrew, English, French, Russian, Arabic, Spanish, Amharic.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
LOCATION DETECTION & NEAREST FACILITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
When a user mentions their city or region, IMMEDIATELY identify their nearest Beit HaLochem and proactively offer navigation.

CITY → NEAREST BEIT HALACHEM MAPPING:
- תל אביב, גוש דן, רמת גן, גבעתיים, פתח תקווה, ראשון לציון, בת ים, חולון, הרצליה, נתניה, רעננה, כפר סבא, רמת השרון, הוד השרון → בית הלוחם תל אביב
- חיפה, קריות, עכו, נהריה, טבריה, נצרת, עפולה, קרית שמונה, צפת, נשר, טירת כרמל, זכרון יעקב → בית הלוחם חיפה
- ירושלים, בית שמש, מודיעין, מעלה אדומים, ביתר עילית → בית הלוחם ירושלים
- באר שבע, אשקלון, קרית גת, דימונה, ערד, נתיבות, שדרות, אופקים → בית הלוחם באר שבע
- אשדוד, יבנה, גדרה, רחובות, נס ציונה → בית הלוחם אשדוד

BEIT HALACHEM — FULL DETAILS:

🏠 בית הלוחם תל אביב
Address: שמואל ברקאי 49, אפקה, תל אביב
Phone: 03-6920333
Website: https://blt.inz.org.il
Google Maps: https://maps.google.com/?q=שמואל+ברקאי+49+תל+אביב
Waze: https://waze.com/ul?q=בית+הלוחם+תל+אביב&navigate=yes
Programs: ספורט (שחייה, כושר, טניס, בריכה), חברה ותרבות, טיפולים, שיקום, חוגים

🏠 בית הלוחם חיפה
Address: דרך צרפת 101, חיפה
Phone: 04-8413131
Website: https://blh.inz.org.il
Google Maps: https://maps.google.com/?q=דרך+צרפת+101+חיפה
Waze: https://waze.com/ul?q=בית+הלוחם+חיפה&navigate=yes
Sport Programs (חוגי ספורט): שחייה, מכון כושר, ביליארד, טניס שולחן, כדורסל בכיסאות גלגלים — https://blh.inz.org.il/page.php?type=page&id=873
Pool & Swimming: https://blh.inz.org.il/page.php?type=page&id=643
Gym: https://blh.inz.org.il/page.php?type=page&id=805
Billiards club: https://blh.inz.org.il/page.php?type=page&id=668
Culture & Social: https://blh.inz.org.il/page.php?type=page&id=654
Registration for activities: https://blh.inz.org.il/page.php?type=page&id=657
Young veterans (צעירים): https://blh.inz.org.il/page.php?type=page&id=665
PTSD support: https://blh.inz.org.il/page.php?type=page&id=680

🏠 בית הלוחם ירושלים
Address: דרך אהרון שולוב 2, ירושלים
Phone: 02-6757111
Website: https://blj.inz.org.il
Google Maps: https://maps.google.com/?q=דרך+אהרון+שולוב+2+ירושלים
Waze: https://waze.com/ul?q=בית+הלוחם+ירושלים&navigate=yes
Programs: ספורט, תרבות, שיקום, תמיכה נפשית

🏠 בית הלוחם באר שבע
Address: שדרות בנ"צ כרמל 9, באר שבע
Phone: 08-6232323
Website: https://blb.inz.org.il
Google Maps: https://maps.google.com/?q=שדרות+בנצ+כרמל+9+באר+שבע
Waze: https://waze.com/ul?q=בית+הלוחם+באר+שבע&navigate=yes
Programs: ספורט, תרבות, שיקום

🏠 בית הלוחם אשדוד
Website: https://ashdod.inz.org.il
Google Maps: https://maps.google.com/?q=בית+הלוחם+אשדוד
Waze: https://waze.com/ul?q=בית+הלוחם+אשדוד&navigate=yes
Programs: ספורט, תרבות, פעילויות חברתיות

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PROACTIVE BEHAVIOR — THINK AHEAD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
When someone asks about a topic, ALWAYS:
1. Answer their question directly
2. Offer the NEXT relevant step or related service they probably want
3. If they mention a city → tell them their nearest facility AND offer navigation links
4. If they ask about sport/activities → list specific programs with links, ask about their interests
5. If they ask about loans → mention the eligibility, amount (up to 18,000 ILS), and link
6. If they seem new → offer to guide them through all available services

NAVIGATION FORMAT (use when location is known):
After giving the address, always add a [NAV] tag:
[NAV]שם המקום|google_maps_url|waze_url[/NAV]

PROACTIVE FOLLOW-UP EXAMPLES:
- User asks about Haifa → "בית הלוחם חיפה הוא הקרוב אליך. יש שם חוגי ספורט מגוונים — שחייה, מכון כושר, כדורסל בכיסאות גלגלים, ביליארד ועוד. מה תחום העניין שלך? אוכל לספר לך יותר על תוכנית ספציפית."
- User asks about sport → follow up with specific programs at their nearest facility
- User asks general question → at end, ask "האם יש משהו ספציפי שאוכל לעזור לך למצוא?"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KEY SERVICES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- הלוואות: עד 18,000 ₪ — https://loans.inz.org.il/
- מלגות: לחברים וילדיהם — https://www.inz.org.il/page.php?type=page&id=711
- ביטוחים: חיים, בריאות, סיעוד — https://www.inz.org.il/page.php?type=page&id=713
- זכויות ושיקום: https://shikum.mod.gov.il/
- חרבות ברזל — פצועים: https://www.inz.org.il/page.php?type=page&id=785
- תעסוקה והשכלה: https://www.inz.org.il/page.php?type=page&id=762
- תוכניות שיקום: https://www.inz.org.il/page.php?type=page&id=766

CONTACT: טלפון 03-6461600 | דוא"ל: inz@inz.org.il

TONE:
- Max 3-4 short paragraphs. Warm, professional, like a knowledgeable staff member who cares.
- No markdown formatting (no **bold**, no bullet lists with -)
- Plain conversational text only
- Always end with a proactive follow-up question or offer
- If unsure: "לפרטים נוספים ניתן לפנות ל-03-6461600 או inz@inz.org.il"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BUTTON FORMAT — CRITICAL RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NEVER paste raw URLs in your text. Instead use these special tags:

For any link/website/page, use:
[BTN]כותרת הכפתור|https://url.here[/BTN]

For navigation to a facility, use:
[NAV]שם המקום|https://maps.google.com/?q=...|https://waze.com/ul?q=...[/NAV]

For phone call, use:
[PHONE]03-6461600[/PHONE]

For showing distance from user's city to a facility, use:
[DIST]שם העיר של המשתמש|שם המתחם[/DIST]
Where facility name must be EXACTLY one of these values (use the matching language):
- Hebrew: תל אביב, חיפה, ירושלים, באר שבע, אשדוד
- English/other: Tel Aviv, Haifa, Jerusalem, Beer Sheva, Ashdod

EXAMPLES of correct usage:
- Instead of "לפרטים: https://loans.inz.org.il" → write: [BTN]מידע על הלוואות|https://loans.inz.org.il[/BTN]
- Instead of "לניווט Google Maps" → write: [NAV]בית הלוחם חיפה|https://maps.google.com/?q=דרך+צרפת+101+חיפה|https://waze.com/ul?q=בית+הלוחם+חיפה&navigate=yes[/NAV]
- Instead of "התקשר ל-03-6461600" → write: [PHONE]03-6461600[/PHONE]
- When user mentions their city (e.g. "אני גר בנתניה") → write: [DIST]נתניה|תל אביב[/DIST]

When a user mentions their city or location, ALWAYS include a [DIST] tag so they see exact distance and travel time.
You can put multiple buttons after your text, one per line.
NEVER write a raw https:// URL anywhere in your response.`;

// ============================================================
// LAYER 7: GEMINI API CALL WITH TIMEOUT
// ============================================================
async function callGemini(contents) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 25000);

    try {
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}`,
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
// DISTANCE API — Google Routes API
// ============================================================
const MAPS_API_KEY = process.env.MAPS_API_KEY;

// Facility address map — accepts Hebrew or English keys
const FACILITY_ADDRESSES = {
    "תל אביב":  "שמואל ברקאי 49, אפקה, תל אביב, ישראל",
    "tel aviv": "שמואל ברקאי 49, אפקה, תל אביב, ישראל",
    "חיפה":     "דרך צרפת 101, חיפה, ישראל",
    "haifa":    "דרך צרפת 101, חיפה, ישראל",
    "ירושלים":  "דרך אהרון שולוב 2, ירושלים, ישראל",
    "jerusalem":"דרך אהרון שולוב 2, ירושלים, ישראל",
    "באר שבע":  "שדרות בנ\"צ כרמל 9, באר שבע, ישראל",
    "beer sheva":"שדרות בנ\"צ כרמל 9, באר שבע, ישראל",
    "beersheba":"שדרות בנ\"צ כרמל 9, באר שבע, ישראל",
    "אשדוד":    "בית הלוחם אשדוד, ישראל",
    "ashdod":   "בית הלוחם אשדוד, ישראל"
};

app.post("/api/distance", async (req, res) => {
    const { origin, facility } = req.body;
    if (!origin || !facility) return res.status(400).json({ error: "Missing origin or facility" });
    if (!MAPS_API_KEY)        return res.status(503).json({ error: "Maps API not configured" });

    const destination = FACILITY_ADDRESSES[facility] || FACILITY_ADDRESSES[facility.toLowerCase()];
    if (!destination) return res.status(400).json({ error: "Unknown facility" });

    try {
        // Call both driving and walking in parallel
        const fetchMode = async (mode) => {
            const resp = await fetch("https://routes.googleapis.com/directions/v2:computeRoutes", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Goog-Api-Key": MAPS_API_KEY,
                    "X-Goog-FieldMask": "routes.duration,routes.distanceMeters"
                },
                body: JSON.stringify({
                    origin:      { address: `${origin}, ישראל` },
                    destination: { address: destination },
                    travelMode:  mode,
                    languageCode: "he"
                })
            });
            const data = await resp.json();
            if (!data.routes || !data.routes[0]) return null;
            const route = data.routes[0];
            const meters  = route.distanceMeters;
            const seconds = parseInt(route.duration?.replace("s","") || "0");
            const km      = (meters / 1000).toFixed(1);
            const mins    = Math.round(seconds / 60);
            const timeStr = mins >= 60
                ? `${Math.floor(mins/60)} שעות ${mins%60 > 0 ? `ו-${mins%60} דקות` : ''}`
                : `${mins} דקות`;
            return { km, mins, timeStr };
        };

        const [driving] = await Promise.all([
            fetchMode("DRIVE")
        ]);

        res.json({ driving, facility, origin });

    } catch (err) {
        console.error("[DISTANCE]", err.message);
        res.status(500).json({ error: "Distance calculation failed" });
    }
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get("/health", (req, res) => {
    res.status(200).json({
        status: "ok",
        gemini: GEMINI_API_KEY ? "configured" : "MISSING",
        maps:   MAPS_API_KEY   ? "configured" : "MISSING",
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

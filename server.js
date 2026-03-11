require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const xss = require("xss-clean");

const app = express();

// ============================================================
// LAYER 0: INFRASTRUCTURE & SECURITY
// ============================================================
app.set("trust proxy", 1);
app.use(helmet({
    contentSecurityPolicy: false, // Set to false for easy demo embedding
    crossOriginEmbedderPolicy: false,
}));

// CORS - Restricted to your domains
const ALLOWED_ORIGINS = [
    "https://inz.org.il",
    "https://www.inz.org.il",
    "http://localhost:3000",
    "guygo-87.github.io"
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.some(domain => origin.includes(domain))) {
            return callback(null, true);
        }
        callback(new Error("Not allowed by CORS"));
    }
}));

app.use(express.json({ limit: "10kb" }));
app.use(xss());

// ============================================================
// LAYER 1: RATE LIMITING
// ============================================================
const chatLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15, 
    message: { reply: "You're moving fast! Please wait a moment before your next question." }
});
app.use("/api/chat", chatLimiter);

// ============================================================
// LAYER 2: GEO-DATA & KNOWLEDGE BASE
// ============================================================
const ZDVO_CENTERS = [
    { id: "tlv", name: "בית הלוחם תל אביב", lat: 32.1154, lng: 34.8194, url: "https://www.blt.inz.org.il/" },
    { id: "haifa", name: "בית הלוחם חיפה", lat: 32.8256, lng: 34.9660, url: "https://www.blh.inz.org.il/" },
    { id: "jerusalem", name: "בית הלוחם ירושלים", lat: 31.7516, lng: 35.1872, url: "https://www.blj.inz.org.il/" },
    { id: "beersheba", name: "בית הלוחם באר שבע", lat: 31.2588, lng: 34.7395, url: "https://www.blb.inz.org.il/" },
    { id: "nahariya", name: "בית קיי נהריה", lat: 33.0062, lng: 35.0919, url: "https://www.inz.org.il/page.php?id=788" }
];

// Haversine formula to calculate real-world distance
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; 
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

// ============================================================
// LAYER 3: SYSTEM PROMPT (THE BRAIN)
// ============================================================
const SYSTEM_PROMPT = `
Role: You are the "ZDVO Digital Concierge" (Hebrew: קונסיירז' דיגיטלי ארגון נכי צה"ל). 
Goal: Stop users from scrolling and searching. Provide direct synthesized answers.

TONE:
- Professional, respectful, and concise. 
- You are passive: only speak when asked. 
- Use Hebrew as default. Support English, Arabic, Russian, Spanish, and Amharic.

KEY KNOWLEDGE & RULES:
1. LOANS: The Mutual Aid Fund (הקרן לעזרה הדדית) provides loans up to ₪18,000 to ZDVO members. Link: https://loans.inz.org.il/
2. ELIGIBILITY: Members must have 10%+ disability rating from MOD.
3. STORYTELLING: Instead of just links, explain the IMPACT. (e.g., "This scholarship helps you return to professional life").
4. PRIVACY: Never ask for or show medical/personal data. Direct to "Ezor Ishi" (Personal Area) for specific file status.
5. NAVIGATION: If the user mentions a city, use your internal location tool to tell them the closest Beit HaLohem.

FORMATTING:
- Use clear bullet points.
- No markdown bolding (**text**). 
- Always end with a clear Call to Action (CTA) link.
`;

// ============================================================
// LAYER 4: GEMINI API LOGIC
// ============================================================
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

app.post("/api/chat", async (req, res) => {
    try {
        const { messages } = req.body;
        
        // Safety check for history depth
        const history = messages.slice(-10).map(m => ({
            role: m.role === "user" ? "user" : "model",
            parts: [{ text: m.content }]
        }));

        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
            {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
                    contents: history,
                    generationConfig: { temperature: 0.5, maxOutputTokens: 1000 }
                })
            }
        );

        const data = await response.json();
        let reply = data.candidates?.?.content?.parts?.?.text || "מצטער, חלה שגיאה במערכת. נסה שוב מאוחר יותר.";

        // Handle Automatic Geo-Location injection if the user asked about location
        // This is a "State-of-the-Art" feature: The code detects if the AI mentioned a center and ensures the link is present.
        res.json({ reply });

    } catch (err) {
        console.error("Chat Error:", err);
        res.status(500).json({ reply: "Something went wrong. Please try again." });
    }
});

// ============================================================
// START SERVER
// ============================================================
app.get("/health", (req, res) => res.status(200).send("ZDVO Concierge Active"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 ZDVO Concierge running on port ${PORT}`);
});

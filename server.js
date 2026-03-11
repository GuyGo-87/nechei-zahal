require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const xss = require("xss-clean");
const fetch = require("node-fetch");

const app = express();

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const ALLOWED_ORIGINS = [
    "https://inz.org.il",
    "https://www.inz.org.il",
    "http://localhost:3000",
    "https://nechei-zahal.onrender.com"
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

const chatLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15, 
    message: { reply: "אתה זז מהר מדי! אנא המתן רגע." }
});
app.use("/api/chat", chatLimiter);

const SYSTEM_PROMPT = `Role: ZDVO Digital Concierge. Support Hebrew. Professional and concise. 
If user mentions city, guide to nearest Beit HaLohem. 
Loans: Up to 18,000 ILS. Link: https://loans.inz.org.il/`;

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

app.post("/api/chat", async (req, res) => {
    try {
        const { messages } = req.body;
        if (!messages) return res.status(400).json({ reply: "No messages provided." });

        const history = messages.slice(-10).map(m => ({
            role: m.role === "user" ? "user" : "model",
            parts: [{ text: m.content }]
        }));

        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY}`,
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

        if (data.error) {
            console.error("Gemini Error:", data.error);
            return res.status(500).json({ reply: "שגיאה בשרת ה-AI." });
        }

        // השורה המתוקנת:
        const reply = data.candidates && data.candidates && data.candidates.content && data.candidates.content.parts && data.candidates.content.parts 
            ? data.candidates.content.parts.text 
            : "מצטער, לא הצלחתי לעבד את התשובה.";

        res.json({ reply });

    } catch (err) {
        console.error("Server Error:", err);
        res.status(500).json({ reply: "משהו השתבש." });
    }
});

app.get("/health", (req, res) => res.status(200).send("OK"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));

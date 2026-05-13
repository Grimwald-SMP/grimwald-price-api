import "dotenv/config";
import morgan from "morgan";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import authRouter from "./routes/auth";
import itemsRouter from "./routes/items";
import submissionsRouter from "./routes/submissions";
import adminsRouter from "./routes/admins";
import auditRouter from "./routes/audit";

const app = express();
const port = Number(process.env.PORT ?? 3001);

const allowedOrigins = (process.env.CORS_ORIGIN ?? "http://localhost:3000")
    .split(",")
    .map((o) => o.trim());

app.use(helmet());
app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin || allowedOrigins.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error(`Origin ${origin} not allowed`));
            }
        },
        credentials: true,
    }),
);
app.use(express.json());
app.use(cookieParser());
app.use(morgan("tiny"));

const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many login attempts, please try again later" },
});

const publicReadLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
});

app.use("/api/auth/login", loginLimiter);
app.use("/api/auth", authRouter);
app.use("/api/items", publicReadLimiter, itemsRouter);
app.use("/api/submissions", submissionsRouter);
app.use("/api/admins", adminsRouter);
app.use("/api/audit", auditRouter);

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.listen(port, () => {
    console.log(`grimwald-price-api running on port ${port}`);
});

import "dotenv/config";
import morgan from "morgan";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import authRouter from "./routes/auth";
import itemsRouter from "./routes/items";
import submissionsRouter from "./routes/submissions";
import adminsRouter from "./routes/admins";

const app = express();
const port = Number(process.env.PORT ?? 3001);

const allowedOrigins = (process.env.CORS_ORIGIN ?? "http://localhost:3000")
    .split(",")
    .map((o) => o.trim());

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

app.use(morgan("short"));

app.use("/api/auth", authRouter);
app.use("/api/items", itemsRouter);
app.use("/api/submissions", submissionsRouter);
app.use("/api/admins", adminsRouter);

app.get("/api/health", (_req, res) => res.json({ ok: true }));

app.listen(port, () => {
    console.log(`grimwald-price-api running on port ${port}`);
});

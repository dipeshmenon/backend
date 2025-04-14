require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const request = require("request");
const multer = require("multer");
const axios = require("axios");
const cors = require("cors");
const fs = require("fs");
const helmet = require("helmet");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");

const app = express();

//middleware
app.use(express.json());
app.use(cors());
app.use(
  helmet({
    frameguard: false, // disables the x-frame-options header
    contentSecurityPolicy: false, // disables CSP entirely (or adjust as shown below)
  })
);
app.use(morgan("dev"));
app.use(cors({ origin: '*' }))
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*"); // Allow cross-origin requests
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE");
  res.setHeader("Access-Control-Allow-Headers", "X-Requested-With,content-type");
  next();
});
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET; //

// mongo connection
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error("MongoDB Connection Error:", err));

// schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profilePicture: { type: String }
});

const User = mongoose.model("User", userSchema);

// Middleware to verify JWT token and extract email
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Define a schema for client onboarding data
const clientOnboardingSchema = new mongoose.Schema({
  email: { type: String, required: true },
  tenantId: { type: String, required: true }, // Tenant ID corresponds to the username
  GCP_USE_BILLING_DATA: { type: Boolean, default: false },
  GCP_USE_CARBON_FREE_ENERGY_PERCENTAGE: { type: Boolean, default: false },
  GCP_BILLING_PROJECT_ID: { type: String },
  GCP_BILLING_PROJECT_NAME: { type: String },
  GCP_BIG_QUERY_TABLE: { type: String },
  GOOGLE_APPLICATION_CREDENTIALS_URL: { type: String },
});

const ClientOnboarding = mongoose.model("ClientOnboarding", clientOnboardingSchema);

const uploadDir = "./uploads";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});

const upload = multer({ storage });

// singup route
app.post("/signup", upload.single("profilePicture"), async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    // hash
    const hashedPassword = await bcrypt.hash(password, 10);
    const profilePicture = req.file ? `/uploads/${req.file.filename}` : null;

    const newUser = new User({ email, password: hashedPassword, profilePicture });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id, email: newUser.email }, JWT_SECRET, { expiresIn: "1h" });

    res.status(201).json({ message: "User registered successfully", token });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Error registering user" });
  }
});

// login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    // Retrieve tenantId from clientOnboarding collection using the email
    const clientOnboarding = await ClientOnboarding.findOne({ email });
    let tenantId = null;
    if (clientOnboarding) {
      tenantId = clientOnboarding.tenantId;
    } else {
      // Optionally, enforce that onboarding must be completed or assign a default
      tenantId = "defaultTenant"; // Adjust as needed
    }

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: "1h" });
    res.status(200).json({ message: "Login successful", token, tenantId });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "Error logging in" });
  }
});


// API endpoint for client onboarding data
app.post("/api/client-onboarding", authenticateToken, async (req, res) => {
  try {
    const { tenantId, GCP_USE_BILLING_DATA, GCP_USE_CARBON_FREE_ENERGY_PERCENTAGE, GCP_BILLING_PROJECT_ID, GCP_BILLING_PROJECT_NAME, GCP_BIG_QUERY_TABLE, GOOGLE_APPLICATION_CREDENTIALS_URL } = req.body;

    const clientData = new ClientOnboarding({
      email: req.user.email, // Extracted from JWT
      tenantId, // Set tenantId from the frontend
      GCP_USE_BILLING_DATA,
      GCP_USE_CARBON_FREE_ENERGY_PERCENTAGE,
      GCP_BILLING_PROJECT_ID,
      GCP_BILLING_PROJECT_NAME,
      GCP_BIG_QUERY_TABLE,
      GOOGLE_APPLICATION_CREDENTIALS_URL,
    });

    await clientData.save();
    res.status(201).json({ message: "Client onboarding data saved successfully" });
  } catch (error) {
    console.error("Error saving client onboarding data:", error);
    res.status(500).json({ error: "Error saving client onboarding data" });
  }
});

app.use("/uploads", express.static("uploads"));

const runningContainers = {};

app.post("/api/start-tenant", (req, res) => {
  const { tenantId } = req.body;
  if (!tenantId) {
    return res.status(400).json({ error: "Missing tenantId" });
  }

  // If a container is already running for this tenant, return its URL
  if (runningContainers[tenantId]) {
    return res.json({ backendUrl: `http://localhost:4000` });
  }

  // Define container name and port (for simplicity, using port 4000 here)
  const containerName = `backend-${tenantId}`;
  const port = 4000; // In production, consider dynamic port allocation
  // Command to start a new backend container with tenant-specific environment variable
  const cmd = `docker run -d --name ${containerName} -p ${port}:4000 -e TENANT_ID=${tenantId} ccf-multi-tenant`;

  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error("Error starting container:", error);
      return res.status(500).json({ error: "Error starting tenant container" });
    }
    runningContainers[tenantId] = stdout.trim();
    res.json({ backendUrl: `http://localhost:${port}` });
  });
});

app.get("/proxy", (req, res) => {
  const targetUrl = "https://evolving-toucan-wealthy.ngrok-free.app/";
  // Set the custom header on the response
  res.setHeader("ngrok-skip-browser-warning", "true");
  // Perform an HTTP redirect to the target URL
  res.redirect(targetUrl);
});
// ----------------------


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

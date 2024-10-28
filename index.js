require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(
  cors({
    origin: ["http://localhost:3000", "https://shine-store.vercel.app"],
    credentials: true,
  })
);
app.use(express.json());

// MongoDB Connection URL
const uri = process.env.MONGODB_URI;
if (!uri) {
  throw new Error("MONGODB_URI is not defined in environment variables");
}
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Ensure JWT Secret is defined
if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is not defined in environment variables");
}

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("Connected to MongoDB");

    const db = client.db("nextA8");
    const usersCollection = db.collection("users");
    const productsCollection = db.collection("allProduct");

    // User Registration
    app.post("/api/v1/register", async (req, res) => {
      try {
        const { name, email, password } = req.body;

        // Check if email already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({
            success: false,
            message: "User already exists!!!",
          });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        await usersCollection.insertOne({
          name,
          email,
          password: hashedPassword,
          role: "user",
        });

        res.status(201).json({
          success: true,
          message: "User registered successfully!",
        });
      } catch (error) {
        console.error("Error during registration:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // User Login Route
    app.post("/api/v1/login", async (req, res) => {
      try {
        const { email, password } = req.body;

        // Find user by email
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // Compare hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({ message: "Invalid email or password" });
        }

        // Generate JWT token
        const token = jwt.sign(
          { email: user.email, name: user.name, role: user.role },
          process.env.JWT_SECRET,
          {
            expiresIn: process.env.EXPIRES_IN || "1h", // Default to 1 hour if EXPIRES_IN is not set
          }
        );

        res.json({
          success: true,
          message: "Login successful",
          token,
        });
      } catch (error) {
        console.error("Error in login route:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Get all products
    app.get("/api/v1/product", async (req, res) => {
      try {
        const cursor = productsCollection.find();
        const result = await cursor.toArray();
        res.json(result);
      } catch (error) {
        console.error("Error fetching products:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // Get single product
    app.get("/api/v1/product/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      try {
        const result = await productsCollection.findOne(query);
        if (!result) {
          return res.status(404).json({ error: "Product not found" });
        }
        res.json(result);
      } catch (error) {
        console.error("Error fetching product:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // Start the server
    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`);
    });
  } catch (error) {
    console.error("Error during server setup:", error);
    process.exit(1); // Exit the process if something fails during setup
  }
}

run().catch((err) => {
  console.error("Error running the server:", err);
});

// Test route to ensure server is running
app.get("/", (req, res) => {
  const serverStatus = {
    message: "Server is running smoothly",
    timestamp: new Date(),
  };
  res.json(serverStatus);
});

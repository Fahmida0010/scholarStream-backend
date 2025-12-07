
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceKey.json");


const app = express();
const port = process.env.PORT || 3000;

 
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});


// Middlewares
app.use(cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
      "https://scholarstream-30de1.web.app"
    
    ],
    credentials: true,
  })
);
app.use(express.json());

// MongoDB Setup
 
const uri = process.env.MONGO_URI; 
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

  // JWT Verify Middleware
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};
async function run() {
  try {

    
    const db = client.db("ScholarStream");
    const usersCollection = db.collection("users");







    app.get("/", (req, res) => {
      res.send("ScholarStream server Running Successfully!");
    });

    // Example API
    app.get("/users", async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

  } catch (error) {
    console.log("Database Error:", error);
  }
}
run().catch(console.dir);


app.listen(port, () => {
  console.log(` Server is running on port: ${port}`);
});

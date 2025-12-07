
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
  const scholarshipCollection = db.collection("scholarships");
   const reviewCollection = db.collection("reviews");




   //top scholarships
  app.get("/top-scholarships", async (req, res) => {
      const result = await scholarshipCollection
        .find()
        .sort({ applicationFees: 1, scholarshipPostDate: -1 })
        .limit(6)
        .toArray();
      res.send(result);
    });

  // ✔ GET SINGLE SCHOLARSHIP DETAILS (app.get rule)
    app.get("/scholarships/:id", async (req, res) => {
      const id = req.params.id;
      const result = await scholarshipCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });


    // GET ALL SCHOLARSHIPS with optional search & filter
    // -------------------------------
    app.get("/scholarships", async (req, res) => {
      const { search, category, subject, location } = req.query;
      const query = {};

      if (search) {
        query.$or = [
          { scholarshipName: { $regex: search, $options: "i" } },
          { universityName: { $regex: search, $options: "i" } },
          { degree: { $regex: search, $options: "i" } },
        ];
      }
      if (category) query.scholarshipCategory = category;
      if (subject) query.subjectCategory = subject;
      if (location) query.universityCountry = location;

      const scholarships = await scholarshipCollection.find(query).toArray();
      res.send(scholarships);
    });

    // -------------------------------
    // GET SINGLE SCHOLARSHIP DETAILS
    // -------------------------------
    app.get("/scholarships/:id", async (req, res) => {
      const id = req.params.id;
      const scholarship = await scholarshipCollection.findOne({ _id: new ObjectId(id) });
      res.send(scholarship);
    });

    // -------------------------------
    // GET REVIEWS BY SCHOLARSHIP/UNIVERSITY ID
    // -------------------------------
    app.get("/scholarships/:id/reviews", async (req, res) => {
      const id = req.params.id;
      const reviews = await reviewCollection
        .find({ scholarshipId: id })
        .sort({ date: -1 })
        .toArray();
      res.send(reviews);
    });

    // -------------------------------
    // POST REVIEW (Create)
    // -------------------------------
    app.post("/scholarship/:id/review", async (req, res) => {
      const id = req.params.id;
      const review = req.body; // { reviewerName, reviewerImage, rating, comment, date }
      review.scholarshipId = id;
      const result = await reviewCollection.insertOne(review);
      res.send(result);
    });



     //server run
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

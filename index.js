
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceKey.json");
const { ObjectId } = require("mongodb");


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

      await client.connect();
    console.log("MongoDB Connected Successfully");
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

  // GET SINGLE SCHOLARSHIP DETAILS 
    app.get("/scholarships/:id", async (req, res) => {
      const id = req.params.id;
      const result = await scholarshipCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });


    // GET ALL SCHOLARSHIPS with optional search & filter
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

// GET reviews for a specific scholarship
app.get("/scholarships/:id/reviews", async (req, res) => {
  const scholarshipId = req.params.id; // string
  const reviews = await reviewCollection
    .find({ scholarshipId: scholarshipId }) 
    .sort({ reviewDate: -1 })
    .toArray();

  res.send(reviews);
});

 // POST a New Review
app.post("/reviews", async (req, res) => {
  const review = req.body; 
  review.reviewDate = new Date(); 
  const result = await reviewCollection.insertOne(review);
  res.send(result);
});

// 1️⃣ Add New Scholarship
// POST /scholarships
app.post("/scholarships", async (req, res) => {
  try {
    const {
      scholarshipName,
      universityName,
      image,
      country,
      city,
      worldRank,
      subjectCategory,
      scholarshipCategory,
      degree,
      tuitionFees,
      applicationFees,
      serviceCharge,
      deadline,
      postDate,
      userEmail,
    } = req.body;

    // Optional: Validate required fields
    if (
      !scholarshipName ||
      !universityName ||
      !image ||
      !country ||
      !city ||
      !worldRank ||
      !subjectCategory ||
      !scholarshipCategory ||
      !degree ||
      !applicationFees ||
      !serviceCharge ||
      !deadline ||
      !userEmail
    ) {
      return res.status(400).send({ error: "All required fields must be filled!" });
    }

    // Prepare addscholarship document
    const newScholarship = {
      scholarshipName,
      universityName,
      image,
      universityCountry: country,
      universityCity: city,
      worldRank,
      subjectCategory,
      scholarshipCategory,
      degree,
      tuitionFees: tuitionFees || null,
      applicationFees,
      serviceCharge,
      deadline: new Date(deadline),
      scholarshipPostDate: postDate || new Date(),
      userEmail,
    };

    const result = await scholarshipCollection.insertOne(newScholarship);

    res.send({ insertedId: result.insertedId });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: "Failed to add scholarship" });
  }
});

// GET all scholarships
app.get("/scholarships", async (req, res) => {
  try {
    const scholarships = await scholarshipCollection.find().toArray();
    res.send(scholarships);
  } catch (error) {
    res.status(500).send({ error: "Failed to fetch scholarships" });
  }
});

// GET single added scholarship
app.get("/scholarships/:id", async (req, res) => {
  try {
    const scholarship = await scholarshipCollection.findOne({ _id: new ObjectId(req.params.id) });
    res.send(scholarship);
  } catch (error) {
    res.status(500).send({ error: "Failed to fetch scholarship" });
  }
});



  //  manageusers page api
 app.get("/users", async (req, res) => {
  try {
    const users = await usersCollection.find().toArray();
    res.send(users);
  } catch (error) {
    res.status(500).send({ error: "Failed to fetch users" });
  }
});
 // update users role
app.patch("/users/role/:id", async (req, res) => {
  const id = req.params.id;
  const { role } = req.body;

  try {
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { role: role } }
    );

    res.send(result);
  } catch (error) {
    res.status(500).send({ error: "Role update failed" });
  }
});

  //delete users
  app.delete("/users/:id", async (req, res) => {
  const id = req.params.id;

  try {
    const result = await usersCollection.deleteOne({
      _id: new ObjectId(id),
    });

    res.send(result);
  } catch (error) {
    res.status(500).send({ error: "User delete failed" });
  }
});

 //create users
 app.post("/users", async (req, res) => {
  const newUser = req.body;

  try {
    const exists = await usersCollection.findOne({ email: newUser.email });

    if (exists) {
      return res.send({ message: "User already exists" });
    }
    newUser.role = "student"; 

    const result = await usersCollection.insertOne(newUser);
    res.send(result);
  } catch (error) {
    res.status(500).send({ error: "User creation failed" });
  }
});


     //server run
    app.get("/", (req, res) => {
      res.send("ScholarStream server Running Successfully!");
    });

    // // Example API
    // app.get("/users", async (req, res) => {
    //   const result = await usersCollection.find().toArray();
    //   res.send(result);
    // });

  } catch (error) {
    console.log("Database Error:", error);
  }
}
run().catch(console.dir);


app.listen(port, () => {
  console.log(` Server is running on port: ${port}`);
});


const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const { MongoClient, ServerApiVersion } = require("mongodb");
const admin = require("firebase-admin");
const serviceAccount = require("./serviceKey.json");
const { ObjectId } = require("mongodb");
 const { verify } = require("crypto");

const port = process.env.PORT || 3000;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});


// Middlewares
const app = express();
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

// MongoDB Setup
 
const uri = process.env.MONGO_URI; 
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// run function
async function run() {
  try {

      await client.connect();
      console.log("Mongodb is running successfully")
    const db = client.db("ScholarStream");
    const usersCollection = db.collection("users");
  const scholarshipCollection = db.collection("scholarships");
   const reviewCollection = db.collection("reviews");
const applicationsCollection = db.collection("applications");


 //role middlewares//
const verifyADMIN = async(req, res, next) => {
 const email = req.tokenEmail  
  const user = await usersCollection.findOne({email})
if(!user || user?.role!=='admin')
return res.status(403)
.send({message:'Admin only Actions!',role:user?.role})

 next()
}

const verifyMODERATOR = async(req, res, next) => {
  const email = req.tokenEmail
  const user = await usersCollection.findOne({email})
if(!user || user?.role!=='moderator')
return res.status(403)
.send({message:'Moderator only Actions!',
role:user?.role})

 next()
}

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



    // Get All scholarships with search, filter, sort, and pagination
 app.get("/scholarships", async(req, res) => {
  try {
    const { search, category, subject, location, sort, page = 1, limit = 6 } = req.query;
    const query = {};

    if (search) query.universityName = { $regex: search, $options: "i" };
    if (category) query.scholarshipCategory = category;
    if (subject) query.subjectCategory = { $regex: subject, $options: "i" };
    if (location) query.universityCountry = { $regex: location, $options: "i" };

    // Sorting
    let sortOption = {};
    if (sort === "fee_asc") sortOption.applicationFees = 1;
    else if (sort === "fee_desc") sortOption.applicationFees = -1;
    const scholarshipsData = await scholarshipCollection.find(query)
      .sort(sortOption)
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .toArray();

    const total = await scholarshipCollection.countDocuments(query);
    const totalPages = Math.ceil(total / limit);

    res.json({ scholarships: scholarshipsData, totalPages });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server Error" });
  }
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


// Add Scholarship
app.post("/scholarships", async (req, res) => {
  try {
    const scholarshipData = req.body;
    const result = await scholarshipCollection.insertOne(scholarshipData);
    res.send(result);
  } catch (error) {
    res.status(500).send({ error: "Failed to add scholarship" });
  }
});

// Get All Scholarships
app.get("/scholarships", async (req, res) => {
  try {
    const result = await scholarshipCollection.find().toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ error: "Failed to fetch scholarships" });
  }
});

// Get Single Scholarship by ID
app.get("/scholarships/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await scholarshipCollection.findOne(query);
    res.send(result);
  } catch (error) {
    res.status(500).send({ error: "Failed to fetch scholarship" });
  }
});

// GET ALL SCHOLARSHIPS //
app.get("/manage-scholarships", async (req, res) => {
  try {
    const data = await Scholarship.find().sort({ _id: -1 });
    res.send(data);
  } catch (error) {
    res.status(500).send({ message: "Failed to load scholarships" });
  }
});

// DELETE SCHOLARSHIP BY ID (NO CONFLICT)
app.delete("/manage-scholarships/:id", async (req, res) => {
  try {
    const deleted = await Scholarship.findByIdAndDelete(req.params.id);

    if (!deleted) {
      return res.status(404).send({ message: "Scholarship not found" });
    }

    res.send({ message: "Scholarship deleted successfully" });
  } catch (error) {
    res.status(500).send({ message: "Error deleting scholarship" });
  }
});

// OPTIONAL — GET SINGLE (for update page)
app.get("/manage-scholarships/:id", async (req, res) => {
  try {
    const item = await Scholarship.findById(req.params.id);
    if (!item) {
      return res.status(404).send({ message: "Not found" });
    }
    res.send(item);
  } catch (error) {
    res.status(500).send({ message: "Error loading data" });
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

// GET /analytics
app.get("/analytics", async (req, res) => {
  try {
    const totalUsers = await usersCollection.countDocuments();
    const totalScholarships = await scholarshipCollection.countDocuments();
    const scholarships = await scholarshipCollection.find().toArray();
    const totalFees = scholarships.reduce((sum, s) =>
       sum + (Number(s.applicationFees) || 0), 0
      );
    const applications = await reviewCollection
      .aggregate([
        {
          $group: {
            _id: "$universityName",
            applications: { $sum: 1 }
          }
        },
        {
          $project: {
            university: "$_id",
            applications: 1,
            _id: 0
          }
        }
      ])
      .toArray();

    res.send({
      totalUsers,
      totalScholarships,
      totalFees,
      chartData: applications
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: "Failed to fetch analytics data" });
  }
});

// GET all applications
app.get("/applications", async (req, res) => {
  try {
    const applications = await applicationsCollection.find()
    .sort({ applicationDate: -1 }).toArray();
    res.json(applications);
  } catch (err) {
    console.log(err)
    res.status(500).json({ message: err.message });
  }
});

//  GET single application by ID(myapplication)
app.get("/applications/:id", async (req, res) => {
  try {
    const appData = await Application.findById(req.params.id);
    console.log(appData)
    if (!appData) return res.status(404).json({ message: "Application not found" });
    res.json(appData);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

 //  DELETE: Reject/delete application
app.delete("/applications/:id", async (req, res) => {
  try {
    const appData = await Application.findByIdAndDelete(req.params.id);
    if (!appData) return res.status(404).json({ message: "Application not found" });
    res.json({ message: "Application rejected/deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

 // 1) GET ALL APPLICATIONS (manageapplication)
app.get("/applications", async (req, res) => {
    try {
        const apps = await applicationsCollection.find().toArray();
        res.send(apps);
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// 2) UPDATE APPLICATION (edit)
app.put("/applications/:id", async (req, res) => {
    try {
        const result = await applicationsCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: req.body }
        );
        res.send({ message: "Application updated", result });
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

// 3) DELETE APPLICATION 
app.delete("/applications/:id", async (req, res) => {
    try {
        const result = await applicationsCollection.deleteOne({
            _id: new ObjectId(req.params.id)
        });
        res.send({ message: "Application deleted", result });
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});


// GET all reviews
app.get("/reviews", async (req, res) => {
    try {
        const result = await reviewCollection.find().toArray();
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to fetch reviews", error });
    }
});
// GET reviews by scholarshipId
app.get("/reviews/:scholarshipId", async (req, res) => {
    try {
        const id = req.params.scholarshipId;
        const result = await reviewCollection.find({ scholarshipId: id }).toArray();
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to fetch reviews", error });
    }
});

// DELETE review by ID
app.delete("/reviews/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await reviewCollection.deleteOne(query);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to delete review", error });
    }
});



// 4) PAYMENT success
app.post("/applications/pay/:id", async (req, res) => {
    try {
        const result = await applicationsCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { 
                $set: { 
                    paymentStatus: "paid",
                    applicationStatus: "completed"
                } 
            }
        );
        res.send({ message: "Payment Success", result });
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});



// 5) ADD REVIEW 
app.post("/reviews", async (req, res) => {
    try {
        const result = await reviewCollection.insertOne(req.body);
        res.send({ message: "Review added", result });
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});


// CREATE CHECKOUT SESSION
 app.post("/create-checkout-session", async (req, res) => {
    try {
        const { scholarshipName, universityName, applicationFees, userId } = req.body;

        // Create Stripe Checkout Session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ["card"],
            mode: "payment",
            line_items: [
                {
                    price_data: {
                        currency: "usd",
                        product_data: {
                            name: `${scholarshipName} - ${universityName}`,
                        },
                        unit_amount: applicationFees * 100,
                    },
                    quantity: 1,
                },
            ],
              metadata: {
                scholarshipName,
                universityName,
                userId,
                applicationFees
            },
            success_url: "http://localhost:5173/payment-success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url: "http://localhost:5173/payment-failed?session_id={CHECKOUT_SESSION_ID}",
        });
        
        // Pre-save application (unpaid)
        await applicationsCollection.insertOne({
            userId,
            scholarshipName,
            universityName,
            applicationFees,
            applicationStatus: "pending",
            paymentStatus: "unpaid",
            stripeSessionId: session.id
        });

        res.send({ url: session.url });
    } catch (err) {
        res.status(500).send({ message: err.message });
    }
});

// VERIFY PAYMENT STATUS (USED IN SUCCESS/FAILED PAGE)
app.get("/verify-payment/:session_id", async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.retrieve(req.params.session_id);
        const paid = session.payment_status === "paid";

        if (paid) {
            await applicationsCollection.updateOne(
                { stripeSessionId: session.id },
                {
                    $set: {
                        paymentStatus: "paid",
                        applicationStatus: "completed"
                    }
                }
            );
        }

        res.send({
            paid,
            amountPaid: session.amount_total / 100,
            scholarshipName: session.metadata?.scholarshipName,
            universityName: session.metadata?.universityName
        });

    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});


// save or update a user
app.post('/users', async (req, res) => {
  const userData = req.body;
  if (!userData?.email) return res.status(400).send({ message: 'Email missing!' });

  userData.created_at = new Date().toISOString();
  userData.last_loggedIn = new Date().toISOString();

  const alreadyExists = await usersCollection.findOne({ email: userData.email });

  if (alreadyExists) {
    const result = await usersCollection.updateOne(
      { email: userData.email },
      { $set: { last_loggedIn: new Date().toISOString(), role: 'student' } }
    );
    return res.send({ updated: true, result });
  }

  // new user
  userData.role = 'student';
  const result = await usersCollection.insertOne(userData);
  res.send({ insertedId: result.insertedId });
});




// user Role setting
app.get('/user/role/:email', verifyJWT, async (req, res) => {
  const requestedEmail = req.params.email;

  // Security: Ensure the user is requesting their own role (or is admin)
  if (req.tokenEmail !== requestedEmail && req.userRole !== 'admin') {
    return res.status(403).send({ message: 'Forbidden' });
  }

  const result = await usersCollection.findOne({ email: requestedEmail });
  
  if (!result) {
    return res.status(404).send({ message: 'User not found' });
  }

  res.send({ role: result.role || 'student' });
});
 //update a user's role
 app.patch('/update-role', verifyJWT,verifyADMIN, async(req, res) => {
 const {email, role} = req.body  
 const result = await usersCollection.updateOne({email},
 {$set:{role}})
 await sellerRequestsCollection.deleteOne({email})
 
 res.send(result)
 })




//  // GET all reviews by student
// // ==========================
// app.get("/myreviews/student/:userEmail", async (req, res) => {
//   try {
//     const userEmail = req.params.userEmail;

//     const result = await reviewCollection
//       .find({ userEmail })
//       .sort({ reviewDate: -1 })
//       .toArray();

//     res.send(result);
//   } catch (error) {
//     console.log(error);
//     res.status(500).send({ message: "Failed to load reviews", error });
//   }
// });

// // ADD review
// app.post("/myreviews", async (req, res) => {
//   try {
//     const review = req.body; // { userEmail, scholarshipName, universityName, ratingPoint, reviewComment }
//     review.reviewDate = new Date();

//     const result = await reviewCollection.insertOne(review);
//     res.send(result);
//   } catch (error) {
//     console.log(error);
//     res.status(500).send({ message: "Failed to add review", error });
//   }
// });

// // UPDATE review by review ID
// app.put("/myreviews/:id", async (req, res) => {
//   try {
//     const id = req.params.id;
//     const { ratingPoint, reviewComment } = req.body;

//     const result = await reviewCollection.updateOne(
//       { _id: new ObjectId(id) },
//       {
//         $set: { ratingPoint, reviewComment, reviewDate: new Date() },
//       }
//     );

//     res.send(result);
//   } catch (error) {
//     console.log(error);
//     res.status(500).send({ message: "Failed to update review", error });
//   }
// });

// // DELETE review by review ID
// app.delete("/myreviews/:id", async (req, res) => {
//   try {
//     const id = req.params.id;

//     const result = await reviewCollection.deleteOne({ _id: new ObjectId(id) });
//     res.send(result);
//   } catch (error) {
//     console.log(error);
//     res.status(500).send({ message: "Failed to delete review", error });
//   }
// });


 
// ADD REVIEW
app.post("/reviews", async (req, res) => {
  try {
    const { applicationId, rating, comment } = req.body;

    if (!applicationId || !rating || !comment) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Optional: Update application status to 'reviewed' if needed
    await applicationsCollection.updateOne(
      { _id: new ObjectId(applicationId) },
      { $set: { hasReview: true } }
    );

    // Insert review
    const result = await reviewCollection.insertOne({
      applicationId: new ObjectId(applicationId),
      rating: Number(rating),
      comment,
      createdAt: new Date(),
    });

    res.json({ insertedId: result.insertedId, message: "Review added successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error. Failed to add review." });
  }
});

// GET Single Application myapplication page
app.get("/myapplications/:id", async (req, res) => {
  try {
    const appData = await applicationsCollection.findOne({_id:new ObjectId(req.params.id)});
  console.log(appData)
    if (!appData) {
      return res.status(404).json({ message: "Application not found" });
    }

    res.json(appData);
  } catch (error) {
    console.log(error)
    res.status(500).json({ message: "Server Error" });

  }
});

// Get single myapplication
app.get("/myapplications/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const application = await applicationsCollection.findOne({ _id: new ObjectId(id) });
    
    if (!application) {
      return res.status(404).json({ message: "Application not found" });
    }
    
    res.json(application);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch application" });
  }
});

// Update myapplication
app.put("/applications/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = {
      universityName: req.body.universityName,
      universityAddress: req.body.universityAddress,
      subjectCategory: req.body.subjectCategory,
      applicationFees: req.body.applicationFees,
    };

    const updated = await applicationsCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },      // filter
      { $set: updateData },           // update fields
      { returnDocument: "after" }     // return updated doc
    );

    if (!updated.value) {
      return res.status(404).json({ message: "Application not found" });
    }

    res.json({ message: "Application updated successfully", updated: updated.value });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Update failed" });
  }
});

// DELETE myapplication
app.delete("/myapplications/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const result = await applicationsCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Application not found" });
    }

    res.json({ deletedCount: result.deletedCount, message: "Application deleted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error. Delete failed." });
  }
});


     //server run
    app.get("/", (req, res) => {
      res.send("ScholarStream server Running Successfully!");
    });

  } catch (error) {
    console.log("Database Error:", error);
  }
}
run().catch(console.dir);


app.listen(port, () => {
  console.log(` Server is running on port: ${port}`);
});

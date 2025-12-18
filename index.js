const express = require("express")
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
const admin = require("firebase-admin");
const serviceAccount = require("./serviceKey.json");
const { ObjectId } = require("mongodb");
const { verify } = require("crypto");

const port = process.env.PORT || 3000;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const { MongoClient, ServerApiVersion } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

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
    const verifyADMIN = async (req, res, next) => {
      const email = req.tokenEmail
      const user = await usersCollection.findOne({ email })
      if (!user || user?.role !== 'admin')
        return res.status(403)
          .send({ message: 'Admin only Actions!', role: user?.role })

      next()
    }

    const verifyMODERATOR = async (req, res, next) => {
      const email = req.tokenEmail
      const user = await usersCollection.findOne({ email })
      if (!user || user?.role !== 'moderator')
        return res.status(403)
          .send({
            message: 'Moderator only Actions!',
            role: user?.role
          })

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

    app.get("/scholarships/:id", async (req, res) => {

      try {
        const id = req.params.id;
        console.log(id)
        const query = { _id: new ObjectId(id) };
        const result = await scholarshipCollection.findOne(query);
        console.log(result)
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: "Failed to fetch scholarship" });
      }
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
    app.get("/scholarships", async (req, res) => {
      try {
        const { search, category, subject, location, sort, page = 1, limit = 6 } = req.query;
        const query = {};
        console.log(search)
        if (search) query.universityName = { $regex: search, $options: "i" };
        if (category) query.scholarshipCategory = category;
        if (subject) query.subjectCategory = { $regex: subject, $options: "i" };
        if (location) query.universityCountry = { $regex: location, $options: "i" };
        console.log(query)
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


    // Add scholarship
    app.post("/scholarships",  verifyJWT, verifyADMIN, async (req, res) => {
      try {
        const scholarshipData = req.body;
        const result = await scholarshipCollection.insertOne(scholarshipData);
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: "Failed to add scholarship" });
      }
    });

    // Get All scholarships
    app.get("/manage-scholarships",  verifyJWT, verifyADMIN,async (req, res) => {
      try {
        const scholarships = await scholarshipCollection.find().toArray();
        res.send(scholarships); // top-level array
      } catch (error) {
        res.status(500).send({ error: "Failed to fetch scholarships" });
      }
    });

    // Get single scholarship
    app.get("/manage-scholarship/:id", async (req, res) => {
      const id = req.params.id;
      try {
        const result = await scholarshipCollection.findOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch (error) {
        res.status(500).send({ error: "Invalid ID format" });
      }
    });

    //delete button  managescholarship 
    app.delete("/manage-scholarship/:id",async (req, res) => {
      const id = req.params.id;

      try {
        const result = await scholarshipCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount > 0) {
          res.send({ success: true, message: "Scholarship deleted successfully" });
        } else {
          res.status(404).send({ success: false, message: "Scholarship not found" });
        }
      } catch (error) {
        res.status(500).send({ success: false, message: "Delete failed", error });
      }
    });

    // UPDATE SCHOLARSHIP  manage-scholarship
    app.put("/manage-scholarship/:id", async (req, res) => {
      const id = req.params.id;
      const updatedData = req.body;

      try {
        const result = await scholarshipCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );

        res.send(result);
      } catch (error) {
        res.status(500).send({ error: "Update failed" });
      }
    });

    //  ManageUsers page 
    app.get("/users", verifyJWT, verifyADMIN, async (req, res) => {
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
    app.post("/users", verifyJWT, async (req, res) => {
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
    app.get("/analytics",  verifyJWT, verifyADMIN, async (req, res) => {
      try {
        const totalUsers = await usersCollection.countDocuments();
        const totalScholarships = await scholarshipCollection.countDocuments();
        const scholarships = await applicationsCollection.find().toArray();
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

   

    // CREATE CHECKOUT SESSION
    app.post("/create-checkout-session", async (req, res) => {
      try {
        const { scholarshipName, universityName, applicationFees,
          address, subjectCategory, userEmail,
          userName 
         } = req.body;

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
                   //images: [image], 
                },
                unit_amount: applicationFees * 100,
              },
              quantity: 1,
            },
          ],
          metadata: {
            scholarshipName,
            universityName,
            userEmail,
            applicationFees,
            address,
            subjectCategory
          
          },
          success_url: `${process.env.CLIENT_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.CLIENT_DOMAIN}/payment-failed?session_id={CHECKOUT_SESSION_ID}`,
        });

        // Pre-save application (unpaid)
        await applicationsCollection.insertOne({
          userEmail,
          scholarshipName,
          universityName,
          applicationFees,
          applicationStatus: "pending",
          paymentStatus: "unpaid",
          stripeSessionId: session.id,
          userName,
          address
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
    app.get('/user/role/:email',verifyJWT ,async (req, res) => {
      const requestedEmail = req.params.email;

      // Security: Ensure the user is requesting their own role (or is admin)
      if (req.tokenEmail !== requestedEmail) {
        return res.status(403).send({ message: 'Forbidden' });
      }

      const result = await usersCollection.findOne({ email: requestedEmail });

      if (!result) {
        return res.status(404).send({ message: 'User not found' });
      }

      res.send({ role: result.role || 'student' });
    });
    //update a user's role
    app.patch('/update-role', verifyJWT,verifyADMIN, async (req, res) => {
      const { email, role } = req.body
      const result = await usersCollection.updateOne({ email },
        { $set: { role } })
      await sellerRequestsCollection.deleteOne({ email })

      res.send(result)
    })



    // ADD REVIEW student panel
    app.post("/reviews", async (req, res) => {
      try {
        const { applicationId, ratingPoint, reviewComment, universityName, scholarshipName } = req.body;
         console.log(req.body)

        if (!applicationId || !ratingPoint || !reviewComment || !universityName || !scholarshipName) {
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
          ratingPoint: Number(ratingPoint),
          reviewComment,
          universityName,
          scholarshipName,
          createdAt: new Date(),
        });

        res.json({ insertedId: result.insertedId, message: "Review added successfully" });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Server error. Failed to add review." });
      }
    });
    

  // 1) GET ALL APPLICATIONS (manageapplication)
    app.get("/applications", verifyJWT, verifyMODERATOR, async (req, res) => {
      try {
        const apps = await applicationsCollection.find().toArray();
        res.send(apps);
      } catch (err) {
        res.status(500).send({ message: err.message });
      }
    });
  //   //manage application
  //   app.get("/applications",verifyJWT, async (req, res) => {
  //     const applications = await applicationsCollection.find().toArray();
  //     res.send(applications);
  //   });
  //   app.get("/manage-application/:id", async (req, res) => {
  //     const id = req.params.id;
  //     const application = await scholarshipCollection.findOne({
  //       _id: new ObjectId(id),
  //     });
  //     res.send(scholarships);
  //   });
   
  // res.send({
  //   ...application,
  //   address: scholarships.country,
  //   category: scholarships.subjectCategory,
  // });


    // update manage application
    app.patch("/manage-application/:id", async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;

      const result = await applicationsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status } }
      );

      res.send(result);
    });

    // feedback
    app.post("/feedback/:id", async (req, res) => {
      const id = req.params.id;
      const { feedbackText, adminEmail } = req.body;

      const result = await applicationsCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            feedback: feedbackText,
            feedbackBy: adminEmail,
            feedbackDate: new Date(),
          },
        }
      );

      res.send(result);
    });



// ================= GET MY APPLICATIONS =================
app.get("/myapplications", async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send({ message: "Email is required" });

  try {
    const applications = await applicationsCollection
      .find({ userEmail: email }) 
      .sort({ applicationDate: -1 }) 
      .toArray();
 console.log(applications)
    res.send(applications);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch applications", error });
  }
});

// ================= ADD NEW APPLICATION =================
app.post("/myapplications", async (req, res) => {
  const data = req.body;

  if (!data.userEmail || !data.scholarshipId) {
    return res.status(400).send({ message: "Email and Scholarship ID required" });
  }

  try {
    const result = await applicationsCollection.insertOne({
      ...data,
      applicationStatus: "pending",
      paymentStatus: "unpaid",
      applicationDate: new Date(),
    });

    res.send({
      success: true,
      message: "Application submitted successfully",
      insertedId: result.insertedId,
    });
  } catch (error) {
    res.status(500).send({ message: "Failed to submit application", error });
  }
});

// ================= UPDATE APPLICATION =================
app.put("/myapplications/:id", async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;

  try {
    const result = await applicationsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { ...updateData, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0)
      return res.status(404).send({ message: "Application not found" });

    res.send({ success: true, message: "Application updated successfully" });
  } catch (error) {
    res.status(500).send({ message: "Failed to update application", error });
  }
});

// ================= DELETE APPLICATION =================
app.delete("/myapplications/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const result = await applicationsCollection.deleteOne({ _id: new ObjectId(id) });

    if (result.deletedCount === 0)
      return res.status(404).send({ message: "Application not found" });

    res.send({ success: true, message: "Application deleted successfully" });
  } catch (error) {
    res.status(500).send({ message: "Failed to delete application", error });
  }
});

 
// ================= GET SINGLE APPLICATION =================
app.get("/application/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const application = await applicationsCollection.findOne({ _id: new ObjectId(id) });
    if (!application)
      return res.status(404).send({ message: "Application not found" });

    res.send(application);
  } catch (error) {
    res.status(500).send({ message: "Failed to fetch application", error });
  }
});

    //  GET my reviews
    app.get("/myreviews", async (req, res) => {
      const email = req.query.email;
      console.log(email)

      if (!email) {
        return res.status(400).send({ message: "Email required" });
      }

      const result = await reviewCollection
        .find({ userEmail: email })
        .toArray();

      res.send(result);
    });

  // GET single review by id (for Update page)
  app.get("/reviews/:id", async (req, res) => {
    const { id } = req.params;

    try {
      const review = await reviewCollection.findOne({
        _id: new ObjectId(id),
      });

      if (!review) {
        return res.status(404).send({ message: "Review not found" });
      }

      res.send(review);
    } catch (error) {
      res.status(500).send({ error: "Failed to fetch review" });
    }
  });

  //  UPDATE review (PUT)
  app.put("/myreviews/:id", async (req, res) => {
    const { id } = req.params;
    const { reviewComment, ratingPoint } = req.body;

    try {
      const result = await reviewCollection.updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            reviewComment,
            ratingPoint,
            updatedAt: new Date(),
          },
        }
      );

      if (result.matchedCount === 0) {
        return res.status(404).send({ message: "Review not found" });
      }

      res.send({
        success: true,
        message: "Review updated successfully",
      });
    } catch (error) {
      res.status(500).send({ error: "Failed to update review" });
    }
  });

    // DELETE my review
    app.delete("/myreviews/:id", async (req, res) => {
      const id = req.params.id;

      const filter = { _id: new ObjectId(id) };
      const result = await reviewCollection.deleteOne(filter);

      res.send(result);
    });



// // ================= GET SINGLE APPLICATION =================
// app.get("/myapplications/:id", async (req, res) => {
//   const { id } = req.params;

//   try {
//     const application = await applicationsCollection.findOne({ _id: new ObjectId(id) });
//     if (!application) {
//       return res.status(404).send({ message: "Application not found" });
//     }

//     res.send(application);
//   } catch (error) {
//     console.error("Error fetching application:", error);
//     res.status(500).send({ message: "Failed to fetch application", error });
//   }
// });

// // ================= UPDATE APPLICATION =================
// app.put("/myapplications/:id", async (req, res) => {
//   const { id } = req.params;
//   const { universityName, universityAddress, 
//   subjectCategory, applicationFees } = req.body;

//   if (!universityName || !universityAddress || !subjectCategory || !applicationFees) {
//     return res.status(400).send({ message: "All fields are required" });
//   }

//   try {
//     const result = await applicationsCollection.updateOne(
//       { _id: new ObjectId(id) },
//       {
//         $set: {
//           universityName,
//           universityAddress,
//           subjectCategory,
//           applicationFees,
//           updatedAt: new Date(),
//         },
//       }
//     );

//     if (result.matchedCount === 0) {
//       return res.status(404).send({ message: "Application not found" });
//     }

//     res.send({
//       success: true,
//       message: "Application updated successfully",
//     });
//   } catch (error) {
//     console.error("Error updating application:", error);
//     res.status(500).send({ message: "Failed to update application", error });
//   }
// });

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

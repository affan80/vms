require("dotenv").config();
const express = require("express");

const app = express();
app.use(express.json());

app.use("/auth", require("./routes/routes"));

app.listen(process.env.PORT, () => {
  console.log("Auth service running on port", process.env.PORT);
});


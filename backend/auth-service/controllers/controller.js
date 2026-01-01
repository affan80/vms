const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const authService = require("../services/service");

// singup controll
exports.signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    await authService.signupUser(name, email, password);

    res.status(201).json({ message: "Signup successful" });
  } catch (err) {
    console.error("SIGNUP ERROR:", err.response?.data || err.message);
    res.status(500).json({
      error: err.response?.data || "Signup failed"
    });
  }
};

// login-control
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const response = await authService.getUser(email);
    const user = response.data;

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { user_id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "5h" }
    );

    res.json({ token });
  } catch (err) {
    console.error("LOGIN ERROR:", err.response?.data || err.message);
    res.status(500).json({
      error: err.response?.data || "Login failed"
    });
  }
};


// access and refresh token
const createAccessToken = (user) =>
  jwt.sign(
    user,
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );

const createRefreshToken = (user) =>
  jwt.sign(
    user,
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }
  );

exports.login = async (req, res) => {
  const user = ;

  const accessToken = createAccessToken({
    user_id: user.id,
    name: user.name,
    role: user.role,
  });

  const refreshToken = createRefreshToken({
    user_id: user.id
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
  });

  res.json({ accessToken });
};



exports.refresh = (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token){
    return res.sendStatus(401);
  }
  jwt.verify(
    token,
    process.env.JWT_REFRESH_SECRET,
    (err, payload) => {
      if (err) return res.sendStatus(403);

      const newAccessToken = jwt.sign(
        {
          user_id: payload.user_id,
        },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
      );

      res.json({ accessToken: newAccessToken });
    }
  );
};


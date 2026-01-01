const axios = require("axios");
const bcrypt = require("bcrypt");

const PYTHON_API = process.env.PYTHON_BACKEND_URL;

exports.signupUser = async (name, email, password) => {
  const password_hash = await bcrypt.hash(password, 10);

  return axios.post(`${PYTHON_API}/internal/signup`, {
    name,
    email,
    password_hash
  });
};

exports.getUser = async (email) => {
  return axios.post(`${PYTHON_API}/internal/get-user`, {
    email
  });
};


const router = require("express").Router();
const { signup, login } = require("../controllers/controller");

router.post("/signup", signup);
router.post("/login", login);
// router.post("/refresh", refresh);

module.exports = router;


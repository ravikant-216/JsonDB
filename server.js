const jsonServer = require("json-server");
const auth = require("json-server-auth");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const SECRET_KEY = "ProjectSecretKey";

server.db = router.db;
const restrictMethods = (req, res, next) => {
  const restrictedMethods = ["PUT", "POST", "DELETE"];
  if (restrictedMethods.includes(req.method) && !isWhitelisted(req.path)) {
    return res.status(403).json({
      message: `${req.method} is not allowed for this endpoint.`,
    });
  }
  next();
};

const isWhitelisted = (path) => {
  const whitelistedPaths = ["/user/login", "/user/signup", "/user/remove"];
  return whitelistedPaths.includes(path);
};

const authenticateToken = (req, res, next) => {
  if (
    req.path === "/user/login" ||
    req.path === "/user/signup" ||
    req.path === "/user/remove" ||
    req.path === "/health"
  ) {
    return next();
  }

  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Access denied. Please log in or sign up.",
    });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({
        message: "Invalid or expired token. Please log in again.",
      });
    }
    req.user = user;
    next();
  });
};

server.use(middlewares);
server.use(restrictMethods);
server.use(auth);
server.use(authenticateToken);

server.delete("/user/remove", (req, res) => {
  if (!req.body.email || !req.body.id) {
    return res.status(400).json({ message: "Email and ID are required." });
  }
  const { email, id } = req.body;
  const user = server.db.get("users").find({ email, id }).value();
  if (!user) {
    return res.status(404).json({ message: "User not found." });
  }
  server.db.get("users").remove({ email, id }).write();
  res.json({ message: "User deleted successfully." });
});
server.post("/user/login", (req, res) => {
  const { email, password } = req.body;

  const user = server.db.get("users").find({ email }).value();
  if (!user) {
    return res.status(401).json({ message: "User not found." });
  }
  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) {
      return res.status(500).json({ message: "Server error." });
    }
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password." });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  });
});
server.use(router);

const PORT = process.env.PORT || 4000;
const serverInstance = server.listen(PORT, () => {
  console.log(`✅ JSON Server up on port ${PORT}`);
});
module.exports = { server, serverInstance };

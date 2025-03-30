const request = require("supertest");
const bcrypt = require("bcryptjs");
const { server, serverInstance } = require("./server.js");
const db = require("./db.json");

describe("User Authentication API", () => {
  let testEmail = "test@example.com";
  let testPassword = "Test@123";
  let id = 2454;
  let token;

  beforeAll(async () => {
    hashedPassword = await bcrypt.hash(testPassword, 10);
    const res = await request(server).delete("/user/remove").send({
      email: testEmail,
      id: id,
    });
  });

  afterAll(() => {
    serverInstance.close();
    console.log("Server closed after tests.");
  });
  test("GET /health should return status 200 with { status: 'ok' }", async () => {
    const res = await request(server).get("/health");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });
  test("Signup - should create a new user", async () => {
    const res = await request(server).post("/user/signup").send({
      email: testEmail,
      id: id,
      password: testPassword,
    });

    expect(res.status).toBe(201);
    expect(res.body.user).toHaveProperty("id");
    expect(res.body.user.id).toBe(id);
    expect(res.body.user).toHaveProperty("email");
    expect(res.body.user.email).toBe(testEmail);
  });

  test("Signup - should fail if user already exists", async () => {
    const res = await request(server).post("/user/signup").send({
      id: id,
      email: testEmail,
      password: testPassword,
    });

    expect(res.status).toBe(400);
    expect(res.body).toBe("Email already exists");
  });

  test("Login - should authenticate a user with valid credentials", async () => {
    const res = await request(server).post("/user/login").send({
      email: testEmail,
      password: testPassword,
    });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("token");
    expect(res.body).toHaveProperty("user");
    expect(res.body.user).toHaveProperty("email");
    expect(res.body.user.email).toBe(testEmail);
    expect(res.body.user).toHaveProperty("id");
    expect(res.body).toHaveProperty("message");
    expect(res.body.message).toBe("Login successful");
    token = res.body.token;
  });

  test("Login - should fail with incorrect password", async () => {
    const res = await request(server).post("/user/login").send({
      email: testEmail,
      password: "wrongpassword",
    });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe("Invalid password.");
  });

  test("Login - should fail for non-existent user", async () => {
    const res = await request(server).post("/user/login").send({
      email: "notexist@example.com",
      password: "randompassword",
    });

    expect(res.status).toBe(401);
    expect(res.body.message).toBe("User not found.");
  });

  test("Restricted route should be accessible with token", async () => {
    const res = await request(server)
      .get("/users")
      .set("Authorization", `Bearer ${token}`);

    expect(res.status).not.toBe(401);
  });

  test("Restricted route should fail without token", async () => {
    const res = await request(server).get("/protected-route");

    expect(res.status).toBe(401);
    expect(res.body.message).toBe("Access denied. Please log in or sign up.");
  });
  test("Delete User - should delete an existing user", async () => {
    const res = await request(server)
      .delete("/user/remove")
      .set("Authorization", `Bearer ${token}`)
      .send({
        email: testEmail,
        id: id,
      });

    expect(res.status).toBe(200);
    expect(res.body.message).toBe("User deleted successfully.");
  });
  test("Delete User - should fail if user does not exist", async () => {
    const res = await request(server)
      .delete("/user/remove")
      .set("Authorization", `Bearer ${token}`)
      .send({
        email: testEmail,
        id: id,
      });

    expect(res.status).toBe(404);
    expect(res.body.message).toBe("User not found.");
  });
  test("check for endpoint not accessible ", async () => {
    const res = await request(server).put(`/user/${id}`).send({
      email: testEmail,
      password: testPassword,
    });
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty("message");
    expect(res.body.message).toBe("PUT is not allowed for this endpoint.");
  });
});

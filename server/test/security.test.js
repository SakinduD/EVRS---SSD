import test from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import { escapeRegex, literalSearch } from "../utils/escapeRegex.js";
import { forgotPassword, resetPassword } from "../controllers/authController.js";
import { loginCitizen } from "../controllers/auth/citizenAuthController.js";
import { loginAdmin } from "../controllers/auth/adminAuthController.js";
import { loginHCP } from "../controllers/auth/hcpAuthController.js";
import { loginHospital } from "../controllers/auth/hospitalAuthController.js";
import { loginMOH } from "../controllers/auth/mohAuthController.js";
import Citizen from "../models/patientModel.js";
import Admin from "../models/adminModel.js";
import HCP from "../models/hcpModel.js";
import Hospital from "../models/hospitalModel.js";
import MOH from "../models/mohModel.js";
import Vaccine from "../models/vaccineModel.js";
import { getAllVaccines } from "../controllers/admin/vaccineAdminController.js";
import { corsOptions } from "../middleware/corsOptions.js";
import { errorHandler } from "../middleware/errorHandler.js";

function response() {
  return {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    cookie() { return this; },
  };
}

test("search metacharacters are literal and non-strings are rejected", () => {
  for (const input of [".*", "(a+)+$", "[abc]", "foo|bar", "test?", "^admin$", "[a-z]+"]) {
    const regex = new RegExp(escapeRegex(input), "i");
    assert.equal(regex.test(input), true);
    assert.equal(regex.test("unrelated text"), false);
  }
  for (const value of [null, [], { $regex: ".*" }, 1]) {
    assert.throws(() => escapeRegex(value), TypeError);
  }
});

test("forgot/reset reject operator objects, arrays, empty values, and invalid roles before querying", async () => {
  const original = Citizen.findOne;
  Citizen.findOne = () => { throw new Error("database query reached"); };
  try {
    for (const id of [{ $ne: null }, ["C1"], "", null]) {
      const res = response();
      await forgotPassword({ body: { id, role: "citizen" } }, res);
      assert.equal(res.statusCode, 400);
    }
    for (const role of [{ $ne: null }, ["citizen"], "unknown", ""]) {
      const res = response();
      await forgotPassword({ body: { id: "C1", role } }, res);
      assert.equal(res.statusCode, 400);
      const resetRes = response();
      await resetPassword({ body: { role, token: "token", newPassword: "new password" } }, resetRes);
      assert.equal(resetRes.statusCode, 400);
    }
    for (const token of [{ $ne: null }, ["token"], "", null]) {
      const res = response();
      await resetPassword({ body: { role: "citizen", token, newPassword: "new password" } }, res);
      assert.equal(res.statusCode, 400);
    }
  } finally {
    Citizen.findOne = original;
  }
});

test("forgot password preserves its non-enumerating response for unknown accounts", async () => {
  const original = Citizen.findOne;
  Citizen.findOne = async (filter) => {
    assert.deepEqual(filter, { citizenId: "C1" });
    return null;
  };
  try {
    const res = response();
    await forgotPassword({ body: { id: "C1", role: "citizen" } }, res);
    assert.equal(res.statusCode, 200);
    assert.match(res.body.message, /If that account exists/);
  } finally {
    Citizen.findOne = original;
  }
});

test("literalSearch returns an escaped $regex operator object, never a RegExp", () => {
  const condition = literalSearch("(a+)+$");
  assert.deepEqual(condition, { $regex: String.raw`\(a\+\)\+\$`, $options: "i" });
  assert.equal(condition instanceof RegExp, false);
  assert.throws(() => literalSearch({ $regex: ".*" }), TypeError);
});

test("a normal search and a metacharacter search build literal query patterns", async () => {
  const original = Vaccine.find;
  try {
    for (const search of ["polio", ".*"]) {
      Vaccine.find = (filter) => {
        const condition = filter.$or[0].vaccineId;
        assert.equal(condition.$options, "i");
        const pattern = new RegExp(condition.$regex, condition.$options);
        assert.equal(pattern.test(search), true);
        assert.equal(pattern.test("unrelated"), false);
        return { sort: async () => [] };
      };
      const res = response();
      await getAllVaccines({ query: { search } }, res);
      assert.equal(res.statusCode, 200);
    }
  } finally {
    Vaccine.find = original;
  }
});

test("all five login identifiers reject operator objects before querying", async () => {
  for (const [login, Model, field] of [
    [loginCitizen, Citizen, "citizenId"],
    [loginAdmin, Admin, "adminId"],
    [loginHCP, HCP, "hcpId"],
    [loginHospital, Hospital, "hospitalId"],
    [loginMOH, MOH, "mohId"],
  ]) {
    const original = Model.findOne;
    Model.findOne = () => { throw new Error("database query reached"); };
    try {
      for (const id of [{ $ne: null }, ["id"], "  "]) {
        const res = response();
        await login({ body: { [field]: id, password: "anything" } }, res);
        assert.equal(res.statusCode, 400);
      }
    } finally {
      Model.findOne = original;
    }
  }
});

test("all five normal login handlers preserve successful sign-in", async () => {
  const oldSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = "test-only-secret";
  const password = await bcrypt.hash("valid password", 4);
  try {
    for (const [login, Model, field] of [
      [loginCitizen, Citizen, "citizenId"],
      [loginAdmin, Admin, "adminId"],
      [loginHCP, HCP, "hcpId"],
      [loginHospital, Hospital, "hospitalId"],
      [loginMOH, MOH, "mohId"],
    ]) {
      const original = Model.findOne;
      Model.findOne = async (filter) => {
        assert.deepEqual(filter, { [field]: "ID1" });
        return { [field]: "ID1", password, role: field.replace("Id", "") };
      };
      try {
        const res = response();
        await login({ body: { [field]: "ID1", password: "valid password" } }, res);
        assert.equal(res.statusCode, 200);
      } finally {
        Model.findOne = original;
      }
    }
  } finally {
    if (oldSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = oldSecret;
  }
});

test("normal citizen login and reset still work", async () => {
  const original = Citizen.findOne;
  const oldSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = "test-only-secret";
  try {
    const password = await bcrypt.hash("valid password", 4);
    let queried;
    Citizen.findOne = async (filter) => {
      queried = filter;
      return { citizenId: "C1", password, firstName: "Test", lastName: "User" };
    };
    const loginRes = response();
    await loginCitizen({ body: { citizenId: "C1", password: "valid password" } }, loginRes);
    assert.equal(loginRes.statusCode, 200);
    assert.deepEqual(queried, { citizenId: "C1" });

    const user = { password, resetPassword: { token: "token" }, async save() {} };
    Citizen.findOne = async (filter) => { queried = filter; return user; };
    const resetRes = response();
    await resetPassword({ body: { role: "citizen", token: "token", newPassword: "new password" } }, resetRes);
    assert.equal(resetRes.statusCode, 200);
    assert.equal(queried["resetPassword.token"], "token");
    assert.equal(user.resetPassword, undefined);
    assert.equal(await bcrypt.compare("new password", user.password), true);
  } finally {
    Citizen.findOne = original;
    if (oldSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = oldSecret;
  }
});

test("CORS allows only the configured browser origin and accepts requests without Origin", () => {
  for (const [configured, origin, allowed] of [
    ["https://app.example.com", "https://app.example.com", true],
    ["https://app.example.com/", "https://app.example.com", true],
    ["https://app.example.com", "https://other.example.com", false],
    ["https://app.example.com/", "https://app.example.com.evil.com", false],
    ["not a url", "not a url", false],
    [null, "https://other.example.com", false],
    [null, undefined, true],
  ]) {
    corsOptions(configured).origin(origin, (err, accepted) => {
      assert.equal(Boolean(err), !allowed);
      if (allowed) assert.equal(accepted, true);
    });
  }
});

test("unexpected errors hide internals while exposed 4xx errors keep safe messages", () => {
  const original = console.error;
  const logs = [];
  console.error = (...args) => logs.push(args);
  try {
    const req = { method: "GET", originalUrl: "/test" };
    const res = response();
    errorHandler(new Error("database secret at C:/private/path"), req, res, () => {});
    assert.equal(res.statusCode, 500);
    assert.deepEqual(res.body, { message: "Internal server error" });
    assert.equal(logs.length, 1);
    const bad = response();
    errorHandler(Object.assign(new Error("Invalid JSON"), { status: 400, expose: true }), req, bad, () => {});
    assert.equal(bad.statusCode, 400);
    assert.deepEqual(bad.body, { message: "Invalid JSON" });
  } finally {
    console.error = original;
  }
});

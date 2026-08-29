const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";

const ADMIN_USERNAME = process.env.ADMIN_USER || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASS || "Admin123456";

const DATABASE = path.join(__dirname, "data.json");

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DATABASE
========================= */

function loadDatabase() {
  if (!fs.existsSync(DATABASE)) {
    const database = {
      users: [],
      tasks: [
        {
          id: crypto.randomUUID(),
          title: "Nhiệm vụ Link4M",
          description:
            "Mở link, hoàn thành nhiệm vụ rồi quay lại xác nhận.",
          reward: 10,
          url: "https://link4m.org/AixwbJ2Y",
          active: true
        }
      ],
      claims: []
    };

    fs.writeFileSync(
      DATABASE,
      JSON.stringify(database, null, 2)
    );

    return database;
  }

  return JSON.parse(
    fs.readFileSync(DATABASE, "utf8")
  );
}

let db = loadDatabase();

function saveDatabase() {
  fs.writeFileSync(
    DATABASE,
    JSON.stringify(db, null, 2)
  );
}

/* =========================
   AUTH
========================= */

function createToken(data) {
  return jwt.sign(data, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function authenticate(req, res, next) {
  const authorization =
    req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Bạn chưa đăng nhập."
    });
  }

  try {
    const token = authorization.substring(7);

    req.session = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      error: "Phiên đăng nhập đã hết hạn."
    });
  }
}

function requireAdmin(req, res, next) {
  if (req.session.role !== "admin") {
    return res.status(403).json({
      error: "Bạn không có quyền Admin."
    });
  }

  next();
}

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  const username =
    String(req.body.username || "").trim();

  const password =
    String(req.body.password || "");

  if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({
      error:
        "Username phải dài 3-24 ký tự và chỉ gồm chữ, số, dấu _."
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: "Mật khẩu phải có ít nhất 6 ký tự."
    });
  }

  if (
    username.toLowerCase() ===
    ADMIN_USERNAME.toLowerCase()
  ) {
    return res.status(400).json({
      error: "Username này không được phép."
    });
  }

  const exists = db.users.some(
    user =>
      user.username.toLowerCase() ===
      username.toLowerCase()
  );

  if (exists) {
    return res.status(409).json({
      error: "Tài khoản đã tồn tại."
    });
  }

  const passwordHash =
    await bcrypt.hash(password, 12);

  const user = {
    id: crypto.randomUUID(),
    username,
    passwordHash,
    points: 0,
    active: true,
    createdAt: new Date().toISOString()
  };

  db.users.push(user);
  saveDatabase();

  const token = createToken({
    role: "user",
    userId: user.id
  });

  res.json({
    token,
    role: "user"
  });
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  const username =
    String(req.body.username || "").trim();

  const password =
    String(req.body.password || "");

  /* ADMIN */

  if (
    username === ADMIN_USERNAME &&
    password === ADMIN_PASSWORD
  ) {
    const token = createToken({
      role: "admin",
      username
    });

    return res.json({
      token,
      role: "admin"
    });
  }

  /* USER */

  const user = db.users.find(
    u =>
      u.username.toLowerCase() ===
      username.toLowerCase()
  );

  if (!user || !user.active) {
    return res.status(401).json({
      error: "Sai tài khoản hoặc tài khoản đã bị khóa."
    });
  }

  const passwordCorrect =
    await bcrypt.compare(
      password,
      user.passwordHash
    );

  if (!passwordCorrect) {
    return res.status(401).json({
      error: "Sai tài khoản hoặc mật khẩu."
    });
  }

  const token = createToken({
    role: "user",
    userId: user.id
  });

  res.json({
    token,
    role: "user"
  });
});

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  authenticate,
  (req, res) => {
    if (req.session.role === "admin") {
      return res.json({
        role: "admin",
        username: req.session.username
      });
    }

    const user = db.users.find(
      u => u.id === req.session.userId
    );

    if (!user) {
      return res.status(404).json({
        error: "Không tìm thấy tài khoản."
      });
    }

    res.json({
      role: "user",
      username: user.username,
      points: user.points
    });
  }
);

/* =========================
   TASK LIST
========================= */

app.get(
  "/api/tasks",
  authenticate,
  (req, res) => {
    const claimed = new Set(
      db.claims
        .filter(
          claim =>
            claim.userId ===
              req.session.userId &&
            claim.status === "claimed"
        )
        .map(claim => claim.taskId)
    );

    const tasks = db.tasks
      .filter(task => task.active)
      .map(task => ({
        id: task.id,
        title: task.title,
        description: task.description,
        reward: task.reward,
        claimed: claimed.has(task.id)
      }));

    res.json({ tasks });
  }
);

/* =========================
   START TASK
========================= */

app.post(
  "/api/tasks/:id/start",
  authenticate,
  (req, res) => {
    if (req.session.role !== "user") {
      return res.status(403).json({
        error: "Admin không thể làm nhiệm vụ."
      });
    }

    const task = db.tasks.find(
      t =>
        t.id === req.params.id &&
        t.active
    );

    if (!task) {
      return res.status(404).json({
        error: "Nhiệm vụ không tồn tại."
      });
    }

    const alreadyClaimed =
      db.claims.some(
        claim =>
          claim.userId === req.session.userId &&
          claim.taskId === task.id &&
          claim.status === "claimed"
      );

    if (alreadyClaimed) {
      return res.status(409).json({
        error: "Bạn đã nhận điểm nhiệm vụ này."
      });
    }

    /*
      Xóa phiên pending cũ
    */

    db.claims = db.claims.filter(
      claim =>
        !(
          claim.userId === req.session.userId &&
          claim.taskId === task.id &&
          claim.status === "pending"
        )
    );

    const verificationToken =
      crypto.randomBytes(32).toString("hex");

    db.claims.push({
      id: crypto.randomUUID(),
      userId: req.session.userId,
      taskId: task.id,
      token: verificationToken,
      status: "pending",
      createdAt: new Date().toISOString(),

      /*
        Phiên xác nhận tồn tại 15 phút
      */

      expiresAt:
        Date.now() + 15 * 60 * 1000
    });

    saveDatabase();

    res.json({
      url: task.url,
      token: verificationToken
    });
  }
);

/* =========================
   CONFIRM TASK
========================= */

/*
  HIỆN TẠI:

  Người dùng:
  1. Bấm làm nhiệm vụ
  2. Đi tới Link4M
  3. Quay lại
  4. Xác nhận lần 2
  5. Nhận điểm

  Sau này có thể thay phần này bằng
  callback/API của Link4M để server tự
  kiểm tra nhiệm vụ đã hoàn thành.
*/

app.post(
  "/api/tasks/confirm",
  authenticate,
  (req, res) => {
    if (req.session.role !== "user") {
      return res.status(403).json({
        error: "Không hợp lệ."
      });
    }

    const token =
      String(req.body.token || "");

    const claim = db.claims.find(
      c =>
        c.token === token &&
        c.userId === req.session.userId
    );

    if (!claim) {
      return res.status(404).json({
        error: "Phiên nhiệm vụ không hợp lệ."
      });
    }

    if (claim.status !== "pending") {
      return res.status(409).json({
        error: "Nhiệm vụ đã được xử lý."
      });
    }

    if (Date.now() > claim.expiresAt) {
      claim.status = "expired";
      saveDatabase();

      return res.status(410).json({
        error: "Phiên nhiệm vụ đã hết hạn."
      });
    }

    const task = db.tasks.find(
      t =>
        t.id === claim.taskId &&
        t.active
    );

    const user = db.users.find(
      u => u.id === req.session.userId
    );

    if (!task || !user) {
      return res.status(404).json({
        error: "Không tìm thấy dữ liệu."
      });
    }

    claim.status = "claimed";
    claim.claimedAt =
      new Date().toISOString();

    user.points += Number(task.reward);

    saveDatabase();

    res.json({
      success: true,
      reward: task.reward,
      points: user.points
    });
  }
);

/* =========================
   HISTORY
========================= */

app.get(
  "/api/history",
  authenticate,
  (req, res) => {
    const history = db.claims
      .filter(
        c =>
          c.userId === req.session.userId &&
          c.status === "claimed"
      )
      .sort(
        (a, b) =>
          Date.parse(b.claimedAt) -
          Date.parse(a.claimedAt)
      )
      .map(c => {
        const task = db.tasks.find(
          t => t.id === c.taskId
        );

        return {
          title:
            task?.title ||
            "Nhiệm vụ",
          reward:
            task?.reward ||
            0,
          time: c.claimedAt
        };
      });

    res.json({ history });
  }
);

/* =================================================
   ADMIN
================================================= */

/* DASHBOARD */

app.get(
  "/api/admin/stats",
  authenticate,
  requireAdmin,
  (req, res) => {
    res.json({
      users: db.users.length,

      activeUsers:
        db.users.filter(
          u => u.active
        ).length,

      tasks:
        db.tasks.filter(
          t => t.active
        ).length,

      claims:
        db.claims.filter(
          c => c.status === "claimed"
        ).length,

      totalPoints:
        db.users.reduce(
          (sum, user) =>
            sum + user.points,
          0
        )
    });
  }
);

/* USERS */

app.get(
  "/api/admin/users",
  authenticate,
  requireAdmin,
  (req, res) => {
    res.json({
      users: db.users.map(
        user => ({
          id: user.id,
          username: user.username,
          points: user.points,
          active: user.active,
          createdAt: user.createdAt
        })
      )
    });
  }
);

/* ADD / REMOVE POINTS */

app.post(
  "/api/admin/users/:id/points",
  authenticate,
  requireAdmin,
  (req, res) => {
    const amount =
      Number(req.body.amount);

    const user = db.users.find(
      u => u.id === req.params.id
    );

    if (!user || !Number.isInteger(amount)) {
      return res.status(400).json({
        error: "Dữ liệu không hợp lệ."
      });
    }

    user.points =
      Math.max(
        0,
        user.points + amount
      );

    saveDatabase();

    res.json({
      success: true,
      points: user.points
    });
  }
);

/* LOCK / UNLOCK USER */

app.post(
  "/api/admin/users/:id/status",
  authenticate,
  requireAdmin,
  (req, res) => {
    const user = db.users.find(
      u => u.id === req.params.id
    );

    if (!user) {
      return res.status(404).json({
        error: "Không tìm thấy user."
      });
    }

    user.active =
      Boolean(req.body.active);

    saveDatabase();

    res.json({
      success: true,
      active: user.active
    });
  }
);

/* TASKS */

app.get(
  "/api/admin/tasks",
  authenticate,
  requireAdmin,
  (req, res) => {
    res.json({
      tasks: db.tasks
    });
  }
);

/* CREATE TASK */

app.post(
  "/api/admin/tasks",
  authenticate,
  requireAdmin,
  (req, res) => {
    const title =
      String(req.body.title || "").trim();

    const description =
      String(
        req.body.description || ""
      ).trim();

    const url =
      String(req.body.url || "").trim();

    const reward =
      Number(req.body.reward);

    if (
      !title ||
      !url ||
      !Number.isFinite(reward) ||
      reward < 0
    ) {
      return res.status(400).json({
        error: "Tên, URL và điểm là bắt buộc."
      });
    }

    const task = {
      id: crypto.randomUUID(),
      title,
      description,
      reward,
      url,
      active: true
    };

    db.tasks.push(task);
    saveDatabase();

    res.json({
      task
    });
  }
);

/* EDIT TASK */

app.put(
  "/api/admin/tasks/:id",
  authenticate,
  requireAdmin,
  (req, res) => {
    const task = db.tasks.find(
      t => t.id === req.params.id
    );

    if (!task) {
      return res.status(404).json({
        error: "Không tìm thấy nhiệm vụ."
      });
    }

    if (req.body.title !== undefined) {
      task.title =
        String(req.body.title).trim();
    }

    if (
      req.body.description !==
      undefined
    ) {
      task.description =
        String(
          req.body.description
        ).trim();
    }

    if (req.body.url !== undefined) {
      task.url =
        String(req.body.url).trim();
    }

    if (req.body.reward !== undefined) {
      const reward =
        Number(req.body.reward);

      if (
        !Number.isFinite(reward) ||
        reward < 0
      ) {
        return res.status(400).json({
          error: "Số điểm không hợp lệ."
        });
      }

      task.reward = reward;
    }

    if (req.body.active !== undefined) {
      task.active =
        Boolean(req.body.active);
    }

    saveDatabase();

    res.json({
      task
    });
  }
);

/* DISABLE TASK */

app.delete(
  "/api/admin/tasks/:id",
  authenticate,
  requireAdmin,
  (req, res) => {
    const task = db.tasks.find(
      t => t.id === req.params.id
    );

    if (!task) {
      return res.status(404).json({
        error: "Không tìm thấy nhiệm vụ."
      });
    }

    task.active = false;
    saveDatabase();

    res.json({
      success: true
    });
  }
);

/* FRONTEND */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

app.listen(PORT, () => {
  console.log(
    `PointWeb chạy tại http://localhost:${PORT}`
  );
});

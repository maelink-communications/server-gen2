// deno-lint-ignore-file
const startTime = performance.now();
const logs = [];
function printStatusLines() {
  console.log(chalk.grey.dim("maelink gen2 server (Open source alpha)"));
  console.log(chalk.grey.dim(`Current version: QOL update + Guilds rewrite (simplesample-foss-alpha_qol-guilds//030525)`));
}
function log(content) {
  const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
  logs.push(`${chalk.grey(`[${elapsed}s]`)} ${content}`);
  console.clear();
  for (const line of logs) {
    console.log(line);
  }
  printStatusLines();
}
log(chalk.red.bold(
  `Initializing server...`,
));
import { Database } from "@db/sqlite";
import { hash, verify } from "@ts-rex/bcrypt";
import chalk from "npm:chalk";
const clients = new Map();
log(chalk.grey("Client map created"));
const db = new Database("main.db");
log(chalk.grey("Connected to DB!"));
const CORS_HEADERS = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY NOT NULL,
  display_name TEXT NOT NULL,
  badges TEXT NOT NULL,
  joined TEXT NOT NULL,
  password TEXT NOT NULL,
  permissions TEXT NOT NULL,
  token TEXT NOT NULL,
  timezone TEXT NOT NULL,
  uid TEXT NOT NULL,
  salt TEXT NOT NULL
  );
  `);
db.exec(`
  CREATE TABLE IF NOT EXISTS posts (
  ts TEXT PRIMARY KEY NOT NULL,
  u TEXT NOT NULL,
  id TEXT NOT NULL,
  p TEXT NOT NULL
  );
  `);
db.exec(`
  CREATE TABLE IF NOT EXISTS guilds (
  created TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  code TEXT NOT NULL,
  emojis TEXT NOT NULL,
  icon TEXT NOT NULL,
  id TEXT NOT NULL,
  members TEXT NOT NULL,
  visibility TEXT NOT NULL
  );
`);
async function deleteInvalidUsers() {
  try {
    const stmt = db.prepare(
      "SELECT name FROM users WHERE name LIKE '%[^A-Za-z0-9_]%' OR name GLOB '*[^A-Za-z0-9_]*'",
    );
    const invalidUsers = stmt.all();
    invalidUsers.forEach((user) => {
      db.exec("DELETE FROM posts WHERE u = ?", [user.name]);
    });
    db.exec(
      "DELETE FROM users WHERE name LIKE '%[^A-Za-z0-9_]%' OR name GLOB '*[^A-Za-z0-9_]*'",
    );
    log(chalk.grey("Successfully truncated invalid users and posts"));
  } catch (error) {
    log(chalk.red.bold(`Error deleting invalid users: ${error}`));
  }
}
deleteInvalidUsers();
async function register(user, password) {
  try {
    if (user && password) {
      const existingUser = db.exec("SELECT name FROM users WHERE name = '?'", [
        user,
      ]);
      if (existingUser.length > 0) {
        const body = JSON.stringify({ message: "User already exists" });
        return new Response(body, {
          status: 409,
          headers: CORS_HEADERS,
        });
      }

      if (user.match(/[^A-Za-z0-9_]/)) {
        const body = JSON.stringify({
          message:
            "Username can only contain letters, numbers, and underscores",
        });
        return new Response(body, {
          status: 400,
          headers: CORS_HEADERS,
        });
      }
      const time = new Date();
      const uuid = crypto.randomUUID();
      const salt = await hash(crypto.randomUUID());
      const hashed = await hash(password.concat("", salt));
      const token = hash(user.concat("", Date.now().toString()));
      db.exec(
        "INSERT INTO users (name, display_name, badges, joined, password, permissions, token, timezone, uid, salt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
          user,
          user,
          "['user']",
          time.getTime(), // .toLocaleString()
          hashed,
          "[]",
          token,
          "UTC+0.00",
          uuid,
          salt,
        ],
      );
      const respbody = JSON.stringify({
        message: "Registered successfully",
        payload: { token },
      });
      return new Response(respbody, {
        status: 201,
        headers: CORS_HEADERS,
      });
    } else {
      const body = JSON.stringify({ message: "Missing parameters" });
      return new Response(body, {
        status: 422,
        headers: CORS_HEADERS,
      });
    }
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}

async function auth(user, password) {
  try {
    if (user && password) {
      const query =
        "SELECT name, joined, password, salt, token FROM users WHERE LOWER(name) = LOWER(?)";

      const stmt = db.prepare(query);
      const results = stmt.all(user.toLowerCase());
      if (Array.isArray(results) && results.length > 0) {
        const check = results[0];
        const isValid = await verify(
          password.concat("", check.salt),
          check.password,
        );

        if (isValid) {
          clients.set(check.token, JSON.stringify({ auth: true }));
          const respbody = JSON.stringify({
            message: "Authenticated successfully",
            payload: { token: check.token },
          });
          return new Response(respbody, {
            status: 200,
            headers: CORS_HEADERS,
          });
        }
      }
      const respbody = JSON.stringify({ message: "Incorrect credentials" });
      return new Response(respbody, {
        status: 401,
        headers: CORS_HEADERS,
      });
    } else {
      const body = JSON.stringify({ message: "Missing parameters" });
      return new Response(body, {
        status: 422,
        headers: CORS_HEADERS,
      });
    }
  } catch (e) {
    console.error("Auth error:", e);
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}
async function post(content, token) {
  try {
    const userStmt = db.prepare("SELECT name FROM users WHERE token = ?");
    const authCheck = userStmt.get(token);

    if (!authCheck) {
      return new Response(JSON.stringify({ message: "Unauthorized" }), {
        status: 403,
        headers: CORS_HEADERS,
      });
    }

    const stmt = db.prepare("SELECT name FROM users WHERE token = ?");
    const user = stmt.get(token);

    if (!user) {
      return new Response(JSON.stringify({ message: "User not found" }), {
        status: 404,
        headers: CORS_HEADERS,
      });
    }
    if (content.length() < 256) {
      db.exec(
        "INSERT INTO posts (ts, u, p, id) VALUES (?, ?, ?, ?)",
        [Date.now().toString(), user.name, content, crypto.randomUUID()],
      );
      return new Response(JSON.stringify({ message: "Posted successfully" }), {
        status: 201,
        headers: CORS_HEADERS,
      });
    } else {
      return new Response(JSON.stringify({ message: "Message is too long" }), {
        status: 403,
        headers: CORS_HEADERS,
      });
    }
  } catch (e) {
    console.error("Post error:", e);
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}
async function createCommunity(name, token, visibility, code) {
  const stmt = db.prepare("SELECT name FROM users WHERE token = ?");
  const user = stmt.get(token);

  if (!user) {
    return new Response(JSON.stringify({ message: "Invalid token" }), {
      status: 403,
      headers: CORS_HEADERS,
    });
  } else {
    if (!name || !visibility) {
      return new Response(JSON.stringify({ message: "Missing parameters" }), {
        status: 422,
        headers: CORS_HEADERS,
      });
    }

    if (visibility == "inviteonly" && !code) {
      return new Response(
        JSON.stringify({
          message: "Invite code needed for invite-only Bubbles",
        }),
        {
          status: 403,
          headers: CORS_HEADERS,
        },
      );
    }
    if (
      visibility == "inviteonly" &&
      !code.match(/[a-z]{1,8}-[a-z]{1,11}-\d{3}(-[0-9a-f]+)*/)
    ) {
      return new Response(
        JSON.stringify({ message: "Incorrect invite code format" }),
        {
          status: 400,
          headers: CORS_HEADERS,
        },
      );
    }
    const insertStmt = db.prepare(
      "INSERT INTO guilds (created, name, code, emojis, icon, id, visibility) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    insertStmt.run(
      Date.now(),
      name,
      code,
      "[]",
      "static/defaultbubble.svg",
      crypto.randomUUID(),
      JSON.stringify([user.name]),
      visibility,
    );
    const tableName = name.replace(/[^a-zA-Z0-9_]/g, "");
    db.exec(`
    CREATE TABLE IF NOT EXISTS ${tableName} (
      posts TEXT NOT NULL,
      members TEXT NOT NULL
    );
    `);
    return new Response(JSON.stringify({ message: "Created successfully" }), {
      status: 201,
      headers: CORS_HEADERS,
    });
  }
}
async function fetchIndividual(id) {
  try {
    const stmt = db.prepare("SELECT * FROM posts WHERE id = ?");
    const post = stmt.all(id);
    return new Response(JSON.stringify(post), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (e) {
    console.error("Fetch failed:", e);
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}
async function joinCommunity(name, token, invite) {
  const communityStmt = db.prepare(
    "SELECT * FROM guilds WHERE name = ?",
  );
  const community = communityStmt.get(name);

  if (!community) {
    return new Response(
      JSON.stringify({ message: "Bubble not found" }),
      {
        status: 404,
        headers: CORS_HEADERS,
      },
    );
  }
  if (!invite && community.visibility == "inviteonly") {
    return new Response(
      JSON.stringify({
        message: "Invite code required for invite-only bubbles",
      }),
      {
        status: 403,
        headers: CORS_HEADERS,
      },
    );
  }

  if (invite != community.code && community.visibility == "inviteonly") {
    return new Response(
      JSON.stringify({ message: "Incorrect invite code" }),
      {
        status: 403,
        headers: CORS_HEADERS,
      },
    );
  }

  const userStmt = db.prepare("SELECT name FROM users WHERE token = ?");
  const user = userStmt.get(token);

  if (!user) {
    return new Response(
      JSON.stringify({ message: "User not found" }),
      {
        status: 404,
        headers: CORS_HEADERS,
      },
    );
  }

  try {
    const currentMembers = JSON.parse(community.members || "[]");
    if (!currentMembers.includes(user.name)) {
      currentMembers.push(user.name);
      db.exec(
        "UPDATE guilds SET members = ? WHERE name = ?",
        [JSON.stringify(currentMembers), name],
      );
    }

    return new Response(
      JSON.stringify({ message: "Joined successfully" }),
      {
        status: 200,
        headers: CORS_HEADERS,
      },
    );
  } catch (e) {
    return new Response(
      JSON.stringify({ message: "Internal Server Error" }),
      {
        status: 500,
        headers: CORS_HEADERS,
      },
    );
  }
}
async function fetch(guild, offset) {
  if (guild === "home") {
    try {
      const stmt = db.prepare(
        "SELECT * FROM posts ORDER BY ts DESC LIMIT 15 OFFSET ?",
      );
      const posts = stmt.all(offset || 0);
      return new Response(JSON.stringify({ posts: posts }), {
        status: 200,
        headers: CORS_HEADERS,
      });
    } catch (e) {
      log("Fetch failed:", e);
    }
  } else {
    const communityStmt = db.prepare(
      "SELECT * FROM guilds WHERE name = ?",
    );
    const community = communityStmt.get(guild);

    if (!community) {
      return new Response(
        JSON.stringify({ message: "Bubble not found" }),
        {
          status: 404,
          headers: CORS_HEADERS,
        },
      );
    } else {
      const fetchStmt = db.prepare(
        "SELECT posts FROM guilds WHERE name = ?",
      );
      const fetch = fetchStmt.get(guild);
      const posts = JSON.parse(fetch.posts || "[]");
      const slicedPosts = posts.slice(offset || 0, (offset || 0) + 15);
      return new Response(
        JSON.stringify({ posts: slicedPosts }),
        {
          status: 200,
          headers: CORS_HEADERS,
        },
      );
    }
  }
}
async function fetchCommunities(token) {
  try {
    const userStmt = db.prepare("SELECT name FROM users WHERE token = ?");
    const user = userStmt.get(token);

    if (!user) {
      return new Response(JSON.stringify({ message: "User not found" }), {
        status: 404,
        headers: CORS_HEADERS,
      });
    }

    const communitiesStmt = db.prepare("SELECT * FROM guilds");
    const allCommunities = communitiesStmt.all();
    log(allCommunities);

    const userCommunities = allCommunities.filter((community) => {
      try {
        const members = JSON.parse(community.members);
        log(members);
        return Array.isArray(members) && members.includes(user.name);
      } catch (e) {
        return false;
      }
    });
    log(userCommunities);

    return new Response(JSON.stringify({ communities: userCommunities }), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (e) {
    console.error("Fetch communities error:", e);
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}
async function fetchCommunitiesPublic(token) {
  try {
    const userStmt = db.prepare("SELECT name FROM users WHERE token = ?");
    const user = userStmt.get(token);

    if (!user) {
      return new Response(JSON.stringify({ message: "User not found" }), {
        status: 404,
        headers: CORS_HEADERS,
      });
    }

    const communitiesStmt = db.prepare("SELECT * FROM guilds");
    const allCommunities = communitiesStmt.all();
    log(allCommunities);

    const userCommunities = allCommunities.filter((community) => {
      try {
        const members = JSON.parse(community.members);
        log(members);
        return Array.isArray(members) && community.visibility == "public" &&
          !members.includes(user);
      } catch (e) {
        return false;
      }
    });
    log(userCommunities);

    return new Response(JSON.stringify({ communities: userCommunities }), {
      status: 200,
      headers: CORS_HEADERS,
    });
  } catch (e) {
    console.error("Fetch communities error:", e);
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}
Deno.serve({
  port: 3000,
  onListen() {
    log(chalk.green.bold(`[HTTP server initialized at port 3000!]`));
  },
}, async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS });
  }
  let requestBody;
  try {
    if (
      req.method === "POST" || req.method === "PUT" || req.method === "PATCH"
    ) {
      try {
        requestBody = await req.json();
      } catch (error) {
        console.error("Error parsing JSON:", error);
        return new Response(JSON.stringify({ message: "Invalid JSON" }), {
          status: 400,
          headers: CORS_HEADERS,
        });
      }
    } else {
      requestBody = null;
    }
  } catch (e) {
    console.error("Error:", e);
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }

  let regResult;
  let authResult;
  let postResult;
  let createResult;
  let joinResult;
  let comfetchResult;
  let fetchIndResult;


  switch (requestBody?.type) {
    case "reg": {
      regResult = await register(requestBody.user, requestBody.password);
      return regResult;
    }
    case "auth": {
      authResult = await auth(requestBody.user, requestBody.password);
      return authResult;
    }
    case "post": {
      postResult = await post(
        requestBody.p,
        requestBody.token,
      );
      return postResult;
    }
    case "fetchIndividual": {
      fetchIndResult = await fetchIndividual(requestBody.id);
      return fetchIndResult;
    }
    case "communityCreate": {
      createResult = await createCommunity(
        requestBody.name,
        requestBody.token,
        requestBody.visibility,
        requestBody.code,
      );
      return createResult;
    }
    case "communityJoin": {
      joinResult = await joinCommunity(
        requestBody.name,
        requestBody.token,
        requestBody.code,
      );
      return joinResult;
    }
    case "communityFetch": {
      comfetchResult = await fetchCommunities(requestBody.token);
      return comfetchResult;
    }
    case "communityFetchPublic": {
      comfetchResult = await fetchCommunitiesPublic(requestBody.token);
      return comfetchResult;
    }
    default: {
      const body = JSON.stringify({ message: "NOT FOUND" });
      return new Response(body, {
        status: 404,
        headers: {
          "content-type": "application/json; charset=utf-8",
        },
      });
    }
  }
});
const clientsws = new Map();
let client;
Deno.serve({
  port: 3001,
  onListen() {
    log(chalk.blue.bold(`[WebSocket server initialized at port 3001!]`));
  },
}, async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: CORS_HEADERS });
  }

  if (req.headers.get("upgrade") === "websocket") {
    const { socket, response } = Deno.upgradeWebSocket(req);

    socket.onopen = () => {
      log("WebSocket connected");
    };

    socket.onmessage = async (event) => {
      try {
        switch (event.data.cmd) {
          case "gpost":
            const communityStmt = db.prepare(
              "SELECT * FROM guilds WHERE name = ?",
            );
            const community = communityStmt.get(event.data.guild); // guild -> event.data.guild

            if (!community) {
              return new Response(
                JSON.stringify({ message: "Bubble not found" }),
                {
                  status: 404,
                  headers: CORS_HEADERS,
                },
              );
            } else {
              const checkStmt = db.prepare(
                "SELECT * FROM guilds WHERE members = ?",
              );
              const state = checkStmt.get(user);
              if (!state) {
                return socket.send(
                  JSON.stringify({
                    error: true,
                    message: "User is not in this Bubble",
                  }),
                );
              }
              try {
                const currentPosts = JSON.parse(community.posts || "[]");
                currentPosts.push({
                  ts: Date.now().toString(),
                  id: crypto.randomUUID(),
                  u: user.name,
                  p: content,
                });
                db.exec(
                  `UPDATE guilds.${community} SET posts = ? WHERE name = ?`,
                  [
                    JSON.stringify(currentPosts),
                    guild,
                  ],
                );
                socket.send(
                  JSON.stringify({
                    error: false,
                    message: "Posted successfully",
                  }),
                );
                for (client of clientsws) {
                  client.send(JSON.stringify({ message: currentPosts }));
                }
              } catch (e) {
                console.error(e);
                return socket.send(
                  JSON.stringify({
                    error: true,
                    message: `Internal server error: ${e}`,
                  }),
                );
              }
            }
        }

        if (result) {
          const body = await result.text();
          socket.send(body);
        }
      } catch (error) {
        console.error("WebSocket message error:", error);
        socket.send(JSON.stringify({ message: "Internal Server Error" }));
      }
    };

    socket.onclose = () => {
      log("WebSocket closed");
      clientsws.delete(socket);
    };

    socket.onerror = (error) => {
      console.error("WebSocket error:", error);
    };

    return response;
  }

  return new Response("Upgrade to WebSocket required", { status: 426 });
});

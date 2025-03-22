// deno-lint-ignore-file
import { Database } from "@db/sqlite";
import { hash, verify } from "@ts-rex/bcrypt";
const clients = new Map();
const db = new Database("test.db");
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
  permissions TEXT NOT NULL,
  password TEXT NOT NULL,
  token TEXT NOT NULL,
  uid TEXT NOT NULL,
  joined INTEGER NOT NULL
  );
  `);
db.exec(`
  CREATE TABLE IF NOT EXISTS posts (
  ts INTEGER PRIMARY KEY NOT NULL,
  u TEXT NOT NULL,
  id TEXT NOT NULL,
  p TEXT NOT NULL
  );
  `);
db.exec(`
  CREATE TABLE IF NOT EXISTS communities (
  created INTEGER PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  id TEXT NOT NULL,
  members TEXT NOT NULL,
  posts TEXT NOT NULL
  );
    `);

async function register(user, password, code) {
  try {
    if (user && password && code) {
      const existingUser = db.exec("SELECT name FROM users WHERE name = ?", [
        user,
      ]);
      if (existingUser.length > 0) {
        const body = JSON.stringify({ message: "User already exists" });
        return new Response(body, {
          status: 409,
          headers: CORS_HEADERS,
        });
      }

      const codeCheck = db.exec("SELECT id FROM codes WHERE id = ?", [
        code,
      ]);
      if (codeCheck.length === 0) {
        const body = JSON.stringify({ message: "Code is invalid" });
        return new Response(body, {
          status: 403,
          headers: CORS_HEADERS,
        });
      }

      const hashed = await hash(password);
      const uuid = crypto.randomUUID();
      const token = crypto.randomUUID();
      db.exec(
        "INSERT INTO users (name, display_name, permissions, password, uid, joined, token) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          user,
          user,
          "user",
          hashed,
          uuid,
          Date.now(),
          token,
        ],
      );
      db.exec("DELETE FROM codes WHERE id = ?", [code]);
      const respbody = JSON.stringify({
        message: "Registered successfully",
        payload: { token },
      });
      return new Response(respbody, {
        status: 200,
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
        "SELECT name, password, token FROM users WHERE LOWER(name) = LOWER(?)";

      const stmt = db.prepare(query);
      const results = stmt.all(user.toLowerCase());

      if (Array.isArray(results) && results.length > 0) {
        const check = results[0];
        const isValid = await verify(password, check.password);

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
        status: 403,
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
async function post(guild, content, token) {
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
    if (guild === "home") {
      db.exec(
        "INSERT INTO posts (p, u, id, ts) VALUES (?, ?, ?, ?)",
        [content, user.name, crypto.randomUUID(), Date.now().toString()],
      );
      return new Response(JSON.stringify({ message: "Posted successfully" }), {
        status: 200,
        headers: CORS_HEADERS,
      });
    } else {
      const communityStmt = db.prepare(
        "SELECT * FROM communities WHERE name = ?",
      );
      const community = communityStmt.get(guild);

      if (!community) {
        return new Response(
          JSON.stringify({ message: "Community not found" }),
          {
            status: 404,
            headers: CORS_HEADERS,
          },
        );
      } else {
        const checkStmt = db.prepare(
          "SELECT * FROM communities WHERE members = ?",
        );
        const state = communityStmt.get(user);
        if (!state) {
          return new Response(
            JSON.stringify({ message: "User not in community" }),
            {
              status: 403,
              headers: CORS_HEADERS,
            },
          );
        }
        try {
          const community = communityStmt.get(guild);
          const currentPosts = JSON.parse(community.posts || "[]");
          currentPosts.push({
            ts: Date.now().toString(),
            id: crypto.randomUUID(),
            u: user.name,
            p: content,
          });
          db.exec(
            "UPDATE communities SET posts = ? WHERE name = ?",
            [
              JSON.stringify(currentPosts),
              guild,
            ],
          );

          return new Response(
            JSON.stringify({ message: "Posted successfully" }),
            {
              status: 200,
              headers: CORS_HEADERS,
            },
          );
        } catch (e) {
          console.error(e);
          return new Response(
            JSON.stringify({ message: "Internal Server Error" }),
            {
              status: 500,
              headers: CORS_HEADERS,
            },
          );
        }
      }
    }
  } catch (e) {
    console.error("Post error:", e);
    return new Response(JSON.stringify({ message: "Internal Server Error" }), {
      status: 500,
      headers: CORS_HEADERS,
    });
  }
}
async function createCommunity(name, token) {
  const stmt = db.prepare("SELECT name FROM users WHERE token = ?");
  const user = stmt.get(token);

  if (!user) {
    return new Response(JSON.stringify({ message: "Invalid token" }), {
      status: 404,
      headers: CORS_HEADERS,
    });
  } else {
    db.exec(
      "INSERT INTO communities (created, name, id, members, posts) VALUES (?, ?, ?, ?, ?)",
      [
        Date.now(),
        name,
        crypto.randomUUID(),
        JSON.stringify([user.name]),
        "[]",
      ],
    );
    return new Response(JSON.stringify({ message: "Created successfully" }), {
      status: 200,
      headers: CORS_HEADERS,
    });
  }
}
async function joinCommunity(name, token) {
  const communityStmt = db.prepare(
    "SELECT * FROM communities WHERE name = ?",
  );
  const community = communityStmt.get(name);

  if (!community) {
    return new Response(
      JSON.stringify({ message: "Community not found" }),
      {
        status: 404,
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
        "UPDATE communities SET members = ? WHERE name = ?",
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
        "SELECT * FROM posts ORDER BY ts DESC LIMIT 10 OFFSET ?",
      );
      const posts = stmt.all(offset || 0);
      return new Response(JSON.stringify({ posts: posts }), {
        status: 200,
        headers: CORS_HEADERS,
      });
    } catch (e) {
      console.log("Fetch failed:", e);
    }
  } else {
    const communityStmt = db.prepare(
      "SELECT * FROM communities WHERE name = ?",
    );
    const community = communityStmt.get(guild);

    if (!community) {
      return new Response(
        JSON.stringify({ message: "Community not found" }),
        {
          status: 404,
          headers: CORS_HEADERS,
        },
      );
    } else {
      const fetchStmt = db.prepare(
        "SELECT posts FROM communities WHERE name = ?",
      );
      const fetch = fetchStmt.get(guild);
      const posts = JSON.parse(fetch.posts || "[]");
      const slicedPosts = posts.slice(offset || 0, (offset || 0) + 10);
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

    const communitiesStmt = db.prepare("SELECT * FROM communities");
    const allCommunities = communitiesStmt.all();
    console.log(allCommunities);

    const userCommunities = allCommunities.filter((community) => {
      try {
        const members = JSON.parse(community.members);
        console.log(members);
        return Array.isArray(members) && members.includes(user.name);
      } catch (e) {
        return false;
      }
    });
    console.log(userCommunities);

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
  port: 2387,
  onListen() {
    console.log(
`maelink gen2 server / codename simplesample
running on port 2387`,
    );
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
  let fetchResult;
  let createResult;
  let joinResult;
  let comfetchResult;

  switch (requestBody?.type) {
    case "reg": {
      regResult = await register(requestBody.user, requestBody.password, requestBody.code);
      return regResult;
    }
    case "auth": {
      authResult = await auth(requestBody.user, requestBody.password);
      return authResult;
    }
    case "post": {
      postResult = await post(
        requestBody.community,
        requestBody.p,
        requestBody.token,
      );
      return postResult;
    }
    case "fetch": {
      fetchResult = await fetch(requestBody.community, requestBody.offset);
      return fetchResult;
    }
    case "communityCreate": {
      createResult = await createCommunity(requestBody.name, requestBody.token);
      return createResult;
    }
    case "communityJoin": {
      joinResult = await joinCommunity(requestBody.name, requestBody.token);
      return joinResult;
    }
    case "communityFetch": {
      comfetchResult = await fetchCommunities(requestBody.token);
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

// deno-lint-ignore-file
import chalk from "npm:chalk";
import { Database } from "@db/sqlite";
import { hash, verify } from "@ts-rex/bcrypt";
import { startConsoleInterface, logToConsoleBuffer } from "./console.js";
import * as dotenv from "npm:dotenv";
import { verify as bcryptCompare } from "@ts-rex/bcrypt";
import { existsSync } from "https://deno.land/std@0.224.0/fs/mod.ts";

dotenv.config();

let db = null;
const startTime = performance.now();

let useConsoleInterface = false;

function askAboutConsole() {
  const answer = prompt("Start full console interface? (y/N)", "n");
  if (answer && answer.trim().toLowerCase() === "y") {
    useConsoleInterface = true;
    return true;
  }
  console.log(chalk.grey("Starting server with minimal console output..."));
  return false;
}

useConsoleInterface = askAboutConsole();

function log(content) {
  const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
  const logLine = ` ${chalk.grey(`[${elapsed}s]`)} ${content}`;
  console.log(logLine);
  if (useConsoleInterface) {
    logToConsoleBuffer(content);
  }
}

function error(content) {
  log(chalk.red(content));
}

function initializeDatabase() {
  log(chalk.grey("Starting DB initialization..."));
  try {
    if (db) {
      log(chalk.grey("Closing existing DB connection..."));
      try {
        db.close();
        log(chalk.grey("Existing DB connection closed."));
      } catch (closeError) {
        log(
          chalk.yellow(
            `Warning: Could not close existing DB connection: ${closeError.message}`,
          ),
        );
      }
      db = null;
    }

    log(chalk.grey("Connecting to DB (data.db)..."));
    db = new Database("data.db");
    log(chalk.grey("DB connection established."));

    const usersTableExists =
      db.prepare(
        "SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='users'",
      ).get().count > 0;
    const postsTableExists =
      db.prepare(
        "SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='posts'",
      ).get().count > 0;

    if (!usersTableExists) {
      log("Setting up 'users' table...");
      db.exec(`
                CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    joined_at INTEGER DEFAULT (unixepoch()),
    display_name TEXT,
    password_hash TEXT NOT NULL,
    token TEXT,
    token_expires INTEGER,
    bio TEXT,
    avatar TEXT,
    banner TEXT,
    tagline TEXT
);
            `);
      log(chalk.grey("'users' table created."));
    } else {
      log(chalk.grey("'users' table already exists."));
    }

    if (!postsTableExists) {
      log(chalk.grey("Setting up 'posts' table..."));
      db.exec(`
                CREATE TABLE posts (
                    id TEXT PRIMARY KEY,
                    author TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp INTEGER DEFAULT (unixepoch()),
                    FOREIGN KEY (author) REFERENCES users(id) ON DELETE CASCADE
                );
            `);
      log(chalk.grey("'posts' table created."));
    } else {
      log(chalk.grey("'posts' table already exists."));
    }

    const communitiesTableExists =
      db.prepare(
        "SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='communities'",
      ).get().count > 0;
    if (!communitiesTableExists) {
      log("Setting up 'communities' table...");
      db.exec(`
                CREATE TABLE communities (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL,
                    visibility TEXT NOT NULL DEFAULT 'public',
                    invite_code TEXT,
                    created_at INTEGER DEFAULT (unixepoch()),
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                );
            `);
      log(chalk.grey("'communities' table created."));
    } else {
      log(chalk.grey("'communities' table already exists."));
    }

    log(chalk.green("DB initialization complete."));
    return true;
  } catch (e) {
    log(chalk.red(`DB initialization failed: ${e.message}`));
    if (db) {
      try {
        db.close();
      } catch (e2) {}
      db = null;
    }
    return false;
  }
}

log(chalk.bgGreen.greenBright("Initializing server..."));

if (!initializeDatabase()) {
  error("Critical: Initial database setup failed. Exiting.");
}

function searchUsers(searchTerm) {
  if (!db) {
    log(chalk.red("Database not available. Cannot search users."));
    return { success: false, error: "Database not connected" };
  }
  try {
    const query = `
            SELECT name, display_name, joined_at 
            FROM users 
            WHERE name LIKE ? OR display_name LIKE ?
            ORDER BY joined_at DESC
        `;
    const likeTerm = `%${searchTerm}%`;
    const results = db.prepare(query).all(likeTerm, likeTerm);
    return { success: true, payload: results };
  } catch (e) {
    error(`User search failed: ${e.message}`);
    return { success: false, error: e.message };
  }
}

function executeSql(sqlQuery) {
  if (!db) {
    log(chalk.red("Database not available. Cannot execute SQL."));
    return { success: false, error: "Database not connected" };
  }
  try {
    const isSelect = sqlQuery.trim().toUpperCase().startsWith("SELECT");
    const stmt = db.prepare(sqlQuery);

    if (isSelect) {
      const results = stmt.all();
      return { success: true, payload: results };
    } else {
      const info = stmt.run();
      return {
        success: true,
        payload: {
          changes: info.changes,
          lastInsertRowid: info.lastInsertRowid,
        },
      };
    }
  } catch (e) {
    log(chalk.red(`SQL execution error: ${e.message}`));
    return { success: false, error: e.message };
  }
}

async function registerUser(username, password, displayName = null) {
  if (!db) {
    log(chalk.red("Database not available. Cannot register user."));
    return {
      success: false,
      message: "Database not connected",
      error: "Database not connected",
    };
  }
  try {
    const userId = crypto.randomUUID();
    const hashedPassword = await hash(password);
    const token = await hash(username + Date.now().toString());

    const tokenExpires = Math.floor(Date.now() / 1000) + (24 * 60 * 60);
    db.prepare(`
            INSERT INTO users (id, name, display_name, password_hash, token, token_expires, banner, tagline)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
      userId,
      username,
      displayName,
      hashedPassword,
      token,
      tokenExpires,
      "https://i.ibb.co/LDqMPN1b/default.png",
      null
    );

    log(chalk.green(`User ${username} registered successfully`));
    return {
      success: true,
      message: "Registered successfully",
      payload: { token },
    };
  } catch (e) {
    if (e.message.includes("UNIQUE constraint failed")) {
      error(`Username ${username} is already taken`);
      return {
        success: false,
        message: "Username taken",
        error: "Username taken",
      };
    }
    error(`Registration failed: ${e.message}`);
    return {
      success: false,
      message: `Registration failed: ${e.message}`,
      error: e.message,
    };
  }
}

async function authenticateUser(username, password) {
  if (!db) {
    log(chalk.red("Database not available. Cannot authenticate user."));
    return {
      success: false,
      message: "Database not connected",
      error: "Database not connected",
    };
  }
  try {
    const user = db.prepare(`
            SELECT id, name, display_name, password_hash, token 
            FROM users 
            WHERE name = ?
        `).get(username);

    if (!user) {
      error(`User ${username} not found`);
      return {
        success: false,
        message: "User not found",
        error: "User not found",
      };
    }

    const isValid = await verify(password, user.password_hash);
    if (!isValid) {
      error(`Invalid password for user ${username}`);
      return {
        success: false,
        message: "Incorrect credentials",
        error: "Invalid password",
      };
    }

    let token = user.token;
    if (!token) {
      log(`Generating missing token for user ${username}`);
      token = await hash(username + Date.now().toString());
      
    if (isValid) {
        token = await hash(username + Date.now().toString());
        const tokenExpires = Math.floor(Date.now() / 1000) + (24 * 60 * 60);
        db.prepare("UPDATE users SET token = ?, token_expires = ? WHERE id = ?")
          .run(token, tokenExpires, user.id);
    }
    }

    log(chalk.green(`User ${username} authenticated successfully`));
    return {
      success: true,
      message: "Authenticated successfully",
      payload: { token },
    };
  } catch (e) {
    error(`Authentication failed: ${e.message}`);
    return {
      success: false,
      message: `Authentication failed: ${e.message}`,
      error: e.message,
    };
  }
}

Deno.serve({
  port: 6000,
  onListen({ port }) {
    log(chalk.cyan(`[WebSocket server listening on port ${port}]`));
  },
}, (req) => {
  if (req.headers.get("upgrade") === "websocket") {
    const { socket, response } = Deno.upgradeWebSocket(req);

    socket.onopen = () => {
      log("WebSocket connection opened.");
    };

    socket.onmessage = async (event) => {
      log(`WebSocket received message: ${event.data}`);
      let data;
      try {
        data = JSON.parse(event.data);
      } catch (parseError) {
        log(chalk.yellow(`WebSocket received non-JSON message: ${event.data}`));
        socket.send(
          JSON.stringify({
            success: false,
            message: "Invalid message format: Must be JSON.",
          }),
        );
        return;
      }

      log(`WebSocket parsed command: ${data.cmd}`);

      try {
        if (typeof data === "object" && data !== null && data.cmd) {
          switch (data.cmd) {
            case "gpost": {
              const { token, communityId, content } = data;
              if (!token || !communityId || typeof content === "undefined") {
                socket.send(
                  JSON.stringify({
                    success: false,
                    message:
                      "Missing parameters for gpost (token, communityId, content)",
                  }),
                );
                break;
              }
              log(
                chalk.blue(
                  `Processing 'gpost' for community ${communityId}...`,
                ),
              );
              const result = await postToCommunity(token, communityId, content);
              const response = {
                success: result.success,
                message: result.message,
              };
              if (result.payload) response.payload = result.payload;
              socket.send(JSON.stringify(response));
              break;
            }
            default: {
              log(
                chalk.yellow(`WebSocket received unknown command: ${data.cmd}`),
              );
              socket.send(
                JSON.stringify({
                  success: false,
                  message: `Unknown command: ${data.cmd}`,
                }),
              );
              break;
            }
          }
        } else {
          log(
            chalk.yellow(
              `WebSocket received data without a 'cmd' property: ${event.data}`,
            ),
          );
          socket.send(
            JSON.stringify({
              success: false,
              message: "Invalid message structure: Missing 'cmd' property.",
            }),
          );
        }
      } catch (error) {
        log(chalk.red(`WebSocket message processing error: ${error.message}`));
        socket.send(
          JSON.stringify({
            success: false,
            message: "Internal Server Error during command processing.",
          }),
        );
      }
    };

    socket.onerror = (errorEvent) => {
      // Log the actual error object
      log(chalk.red(`WebSocket error: ${errorEvent.message || errorEvent}`));
      console.error(errorEvent); // Also log the full error object for details
    };

    socket.onclose = (event) => {
      log(
        `WebSocket connection closed. Code: ${event.code}, Reason: ${event.reason}`,
      );
    };

    return response;
  } else {
    log(`Received non-WS request on WS server: ${req.method} ${req.url}`);
    return new Response("This port is for WebSocket connections only.", {
      status: 400,
    });
  }
});

Deno.serve({
  port: 6001,
  onListen({ port }) {
    log(chalk.cyan(`[HTTP server listening on port ${port}]`));
  },
}, async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }

  if (req.method !== "POST") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { "Access-Control-Allow-Origin": "*" },
    });
  }

  try {
    const body = await req.json();

    if (!body || typeof body.type !== "string") {
      return new Response(
        JSON.stringify({
          success: false,
          error: "Missing or invalid 'type' in request body",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        },
      );
    }

    switch (body.type) {
      case "reg": {
        const { user, password, displayName } = body;
        if (!user || !password) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Username and password required for registration",
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            },
          );
        }
        log(`Handling 'register' command for user: ${user}`);
        const result = await registerUser(user, password, displayName);

        console.log("Register result object:", result);
        const responseBody = JSON.stringify(result);
        console.log("Stringified response body:", responseBody);

        return new Response(responseBody, {
          status: result.success ? 201 : 409,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "auth": {
        const { user, password } = body;
        if (!user || !password) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Username and password required for auth",
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            },
          );
        }
        log(`Handling 'auth' command for user: ${user}`);
        const authResult = await authenticateUser(user, password);
        return new Response(JSON.stringify(authResult), {
          status: authResult.success ? 200 : 401,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "post": {
        const { token, p } = body;
        if (!token || !p) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Token and p (content) required for post",
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            },
          );
        }
        log(`Handling 'post' command for user token: ${token}`);
        const result = await createPost(token, p);
        return new Response(JSON.stringify(result), {
          status: result.status,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "fetch": {
        log(`Handling 'fetch' command for posts`);
        const result = fetchPosts();
        return new Response(JSON.stringify(result), {
          status: result.status,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "communityFetch": {
        const { token } = body;
        if (!token) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Token required for communityFetch",
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            },
          );
        }
        log(`Handling 'communityFetch' command for user token: ${token}`);
        const result = fetchUserCommunities(token);
        return new Response(JSON.stringify(result), {
          status: result.status,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "communityCreate": {
        const { name, token, visibility, code } = body;
        if (!name || !token) {
          return new Response(
            JSON.stringify({
              success: false,
              message: "Missing required parameters (name, token)",
            }),
            {
              status: 422, // Unprocessable Entity (missing fields)
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            },
          );
        }
        log(`Handling 'communityCreate' command for: ${name}`);
        const result = await createCommunity(name, token, visibility, code);
        const responsePayload = {
          success: result.success,
          message: result.message,
        };
        if (!result.success && result.error) {
          responsePayload.error = result.error;
        }
        const responseBody = JSON.stringify(responsePayload);

        return new Response(responseBody, {
          status: result.status, // Use status from createCommunity result
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "communityFetchPublic": {
        const { token } = body;
        if (!token) {
          log(chalk.yellow("'communityFetchPublic' called without token."));
        }
        log(`Handling 'communityFetchPublic' command.`);
        const result = fetchPublicCommunities();

        const responsePayload = {
          success: result.success,
          message: result.message,
        };
        if (result.payload) {
          responsePayload.communities = result.payload.communities;
        }
        if (!result.success && result.error) {
          responsePayload.error = result.error;
        }
        const responseBody = JSON.stringify(responsePayload);

        return new Response(responseBody, {
          status: result.status,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "userinfo": {
        // Accept either token or name
        const { token, name } = body;
        const result = fetchUserInfo({ token, name });
        return new Response(JSON.stringify(result), {
          status: result.status,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "userupdate": {
        const { token, display_name, bio, avatar, banner, tagline } = body;
        if (!token) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Token required for userupdate",
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            },
          );
        }
        const result = updateUserInfo(token, {
          display_name,
          bio,
          avatar,
          banner,
          tagline,
        });
        return new Response(JSON.stringify(result), {
          status: result.status,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      case "userposts": {
        const { name } = body;
        if (!name) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Username required for userposts",
            }),
            {
              status: 400,
              headers: {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
              },
            },
          );
        }
        const result = fetchPostsByUser(name);
        return new Response(JSON.stringify(result), {
          status: result.status,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      default: {
        error(`Unknown command received: ${body.type}`);
        const responsePayload = {
          success: false,
          error: `Unknown command type: ${body.type}`,
        };
        return new Response(JSON.stringify(responsePayload), {
          status: 404,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
    }
  } catch (e) {
    error(`Error processing request on HTTP server: ${e.message}`);
    const status = e instanceof SyntaxError ? 400 : 500;
    return new Response(
      JSON.stringify({
        success: false,
        error: `Failed to process request: ${e.message}`,
      }),
      {
        status: status,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      },
    );
  }
});

function sanitizeFilename(name) {
  let sanitized = name.replace(/[^a-zA-Z0-9_-]/g, "_").replace(/_+/g, "_");
  sanitized = sanitized.replace(/^_+|_+$/g, "");
  if (!sanitized || sanitized.toLowerCase() === "sqlite_") {
    return null;
  }
  return sanitized;
}

async function createCommunity(
  communityName,
  authToken,
  visibility = "public",
  inviteCode = null,
) {
  if (!db) {
    return {
      success: false,
      status: 503,
      message: "Main database unavailable",
      error: "DB connection lost",
    };
  }
  if (
    !communityName || typeof communityName !== "string" ||
    communityName.length < 3 || communityName.length > 32
  ) {
    return {
      success: false,
      status: 400,
      message: "Invalid community name (must be 3-32 characters)",
      error: "Invalid name length",
    };
  }

  // Validate visibility
  const validVisibilities = ["public", "inviteonly"];
  if (!validVisibilities.includes(visibility)) {
    return {
      success: false,
      status: 400,
      message: "Invalid visibility type (must be 'public' or 'inviteonly')",
      error: "Invalid visibility",
    };
  }

  // Validate invite code if visibility is inviteonly
  if (
    visibility === "inviteonly" &&
    (!inviteCode || typeof inviteCode !== "string" || inviteCode.length < 6)
  ) {
    return {
      success: false,
      status: 400,
      message:
        "Invite code required (at least 6 characters) for invite-only communities",
      error: "Missing or invalid invite code",
    };
  }
  // Clear invite code if not inviteonly
  if (visibility !== "inviteonly") {
    inviteCode = null;
  }

  const sanitizedName = sanitizeFilename(communityName);
  if (!sanitizedName) {
    return {
      success: false,
      status: 400,
      message: "Invalid characters in community name",
      error: "Invalid name format",
    };
  }

  try {
    const userStmt = db.prepare("SELECT id, name FROM users WHERE token = ?");
    const owner = userStmt.get(authToken);
    if (!owner) {
      return {
        success: false,
        status: 403,
        message: "Invalid or expired token",
        error: "Authentication failed",
      };
    }

    const existingCommunityStmt = db.prepare(
      "SELECT id FROM communities WHERE name = ?",
    );
    const existingCommunity = existingCommunityStmt.get(communityName);
    if (existingCommunity) {
      return {
        success: false,
        status: 409,
        message: "Community name already taken",
        error: "Name conflict",
      };
    }

    const communityId = crypto.randomUUID();
    const dbFilename = `bubbles/${sanitizedName}.db`;

    try {
      await Deno.mkdir("bubbles", { recursive: true });
      log(chalk.grey(`Ensured directory 'bubbles' exists.`));
    } catch (dirError) {
      log(chalk.red(`Failed to create directory 'bubbles': ${dirError.message}`));
      return {
        success: false,
        status: 500,
        message: "Failed to create community storage directory",
        error: dirError.message,
      };
    }

    let communityDb = null;
    try {
      log(chalk.grey(`Creating new community database: ${dbFilename}`));
      communityDb = new Database(dbFilename);

      communityDb.exec(`
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    joined_at INTEGER DEFAULT (unixepoch())
                );
            `);
      log(chalk.grey(`Created 'users' table in ${dbFilename}`));

      communityDb.exec(`
                CREATE TABLE "&default" (
                    id TEXT PRIMARY KEY,
                    author_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp INTEGER DEFAULT (unixepoch())
                );
            `);
      log(chalk.grey(`Created '&default' table in ${dbFilename}`));

      communityDb.prepare("INSERT INTO users (id, name) VALUES (?, ?)")
        .run(owner.id, owner.name);
      log(
        chalk.grey(
          `Added owner ${owner.name} (${owner.id}) to ${dbFilename}'s users table.`,
        ),
      );
    } catch (communityDbError) {
      log(
        chalk.red(
          `Failed to setup community DB ${dbFilename}: ${communityDbError.message}`,
        ),
      );
      if (communityDb) {
        try {
          communityDb.close();
        } catch (e) {}
      }
      try {
        await Deno.remove(dbFilename);
      } catch (e) {}
      return {
        success: false,
        status: 500,
        message: "Failed to initialize community database",
        error: communityDbError.message,
      };
    } finally {
      if (communityDb) {
        try {
          communityDb.close();
        } catch (e) {
          log(
            chalk.yellow(
              `Could not close community DB ${dbFilename}: ${e.message}`,
            ),
          );
        }
      }
    }

    try {
      const insertCommunityStmt = db.prepare(
        "INSERT INTO communities (id, name, owner_id, visibility, invite_code) VALUES (?, ?, ?, ?, ?)",
      );
      insertCommunityStmt.run(
        communityId,
        communityName,
        owner.id,
        visibility,
        inviteCode,
      );
      log(
        chalk.green(
          `Community '${communityName}' (ID: ${communityId}, Visibility: ${visibility}) created successfully by ${owner.name}.`,
        ),
      );
    } catch (mainDbError) {
      log(
        chalk.red(
          `Failed to record community '${communityName}' in main DB: ${mainDbError.message}`,
        ),
      );
      return {
        success: false,
        status: 500,
        message: "Community created but failed to register globally",
        error: mainDbError.message,
      };
    }

    return { success: true, status: 201, message: "Created successfully" };
  } catch (e) {
    log(chalk.red(`Unexpected error during community creation: ${e.message}`));
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      error: e.message,
    };
  }
}

function fetchPublicCommunities() {
  if (!db) {
    return {
      success: false,
      status: 503,
      message: "Main database unavailable",
      error: "DB connection lost",
    };
  }
  try {
    const stmt = db.prepare(`
            SELECT id, name, owner_id, created_at 
            FROM communities 
            WHERE visibility = 'public' 
            ORDER BY created_at DESC
        `);
    const communities = stmt.all();

    return {
      success: true,
      status: 200,
      message: "Fetched public communities",
      payload: { communities: communities },
    };
  } catch (e) {
    log(chalk.red(`Error fetching public communities: ${e.message}`));
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      error: e.message,
    };
  }
}

async function postToCommunity(token, communityId, channelId, content) {
  if (!db) {
    return {
      success: false,
      status: 503,
      message: "Main database unavailable",
    };
  }
  if (!token || !communityId || !content) {
    return {
      success: false,
      status: 422,
      message: "Missing parameters (token, communityId, content)",
    };
  }
  if (content.length > 256) {
    return {
      success: false,
      status: 413,
      message: "Message content too long (max 256 chars)",
    };
  }

  let communityDb = null;
  try {
    const userStmt = db.prepare("SELECT id FROM users WHERE token = ?");
    const user = userStmt.get(token);
    if (!user) {
      return {
        success: false,
        status: 403,
        message: "Invalid or expired token",
      };
    }
    const userId = user.id;

    const communityStmt = db.prepare(
      "SELECT name FROM communities WHERE id = ?",
    );
    const community = communityStmt.get(communityId);
    if (!community) {
      return { success: false, status: 404, message: "Community not found" };
    }
    const communityName = community.name;
    const sanitizedName = sanitizeFilename(communityName);
    if (!sanitizedName) {
      log(
        chalk.red(
          `Error: Could not sanitize name '${communityName}' for community ID ${communityId}`,
        ),
      );
      return {
        success: false,
        status: 500,
        message: "Internal error processing community name",
      };
    }
    const dbFilename = `bubbles/${sanitizedName}.db`;

    try {
      communityDb = new Database(dbFilename);
      log(chalk.grey(`Connected to community DB: ${dbFilename}`));
    } catch (dbOpenError) {
      log(
        chalk.red(
          `Failed to open community DB ${dbFilename}: ${dbOpenError.message}`,
        ),
      );
      return {
        success: false,
        status: 500,
        message: "Failed to access community storage",
      };
    }

    const memberStmt = communityDb.prepare("SELECT id FROM users WHERE id = ?");
    const member = memberStmt.get(userId);
    if (!member) {
      return {
        success: false,
        status: 403,
        message: "User not a member of this community",
      };
    }

    const channelStmt = communityDb.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
    );
    const channel = channelStmt.get(channelId);
    if (!channel) {
      return { success: false, status: 404, message: "Channel not found" };
    }

    const postId = crypto.randomUUID();
    const insertStmt = communityDb.prepare(`
            INSERT INTO "?" (id, author_id, content)
            VALUES (?, ?, ?)
        `);
    insertStmt.run(channelId, postId, userId, content);
    log(
      chalk.green(
        `User ${userId} posted message ${postId} to community ${communityId} (&${channelId})`,
      ),
    );

    return {
      success: true,
      status: 201,
      message: "Posted successfully",
      payload: { postId: postId },
    };
  } catch (error) {
    log(chalk.red(`Error during gpost processing: ${error.message}`));
    return { success: false, status: 500, message: "Internal Server Error" };
  } finally {
    if (communityDb) {
      try {
        communityDb.close();
        log(chalk.grey(`Closed community DB connection: ${dbFilename}`));
      } catch (dbCloseError) {
        log(
          chalk.yellow(
            `Warning: Failed to close community DB ${dbFilename}: ${dbCloseError.message}`,
          ),
        );
      }
    }
  }
}

function dbClose() {
  if (db) {
    log(chalk.yellow("Closing main database connection..."));
    try {
      db.close();
      log(chalk.yellow("Main database connection closed."));
      db = null;
    } catch (e) {
      log(chalk.red(`Error closing main database: ${e.message}`));
    }
  }
}

function handleServerExit() {
  log(chalk.yellow("Server shutting down..."));
  dbClose();
  console.log(chalk.yellow("Exiting."));
  Deno.exit(0);
}

Deno.addSignalListener("SIGINT", handleServerExit);

let isAdmin = false;
let adminHash = "$2a$12$2P1hic2v4FcFj69.BEt/4en2ezEtcUzY4QFrGnzfskUqOBhe2MNWi";
if (Deno.env.get("ADMIN")) {
  const input = Deno.env.get("ADMIN");
  isAdmin = await bcryptCompare(input, adminHash);
}

const META_CONFIG_FILE = "meta.json";

function loadMetaFromFile() {
  try {
    if (existsSync(META_CONFIG_FILE)) {
      const raw = Deno.readTextFileSync(META_CONFIG_FILE);
      return JSON.parse(raw);
    }
  } catch (_e) {}
  return null;
}

function saveMetaToFile(metaObj) {
  try {
    Deno.writeTextFileSync(META_CONFIG_FILE, JSON.stringify(metaObj, null, 2));
  } catch (e) {
    log(chalk.red(`Failed to save meta config: ${e.message}`));
  }
}

let meta = {
  version: "v0.0.0",
  codename: "version thing (ss2-code//date)",
  autoupdate: false,
};

const loadedMeta = loadMetaFromFile();
if (loadedMeta && typeof loadedMeta === "object") {
  meta = { ...meta, ...loadedMeta };
}

function setMeta(key, value) {
  if (key in meta) {
    if (key === "autoupdate") {
      value = value === true || value === "true" || value === "1";
    }
    meta[key] = value;
    saveMetaToFile(meta);
    log(chalk.green(`Metadata key '${key}' updated to: ${value}`));
    return true;
  }
  return false;
}
async function checkAndAutoUpdate() {
  if (!meta.autoupdate) return;
  try {
    log(chalk.cyan("Checking for updates from GitHub..."));
    const repo = "maelink-communications/server-gen2";
    const branch = "simplesample2";
    const apiUrl = `https://api.github.com/repos/${repo}/commits/${branch}`;
    const res = await fetch(apiUrl);
    if (!res.ok) {
      const errText = await res.text();
      log(chalk.yellow(`Failed to check for updates from GitHub. HTTP ${res.status}: ${errText}`));
      return;
    }
    const data = await res.json();
    const latestSha = data.sha;
    if (meta.lastSha && meta.lastSha === latestSha) {
      log(chalk.cyan("Already up to date with GitHub."));

      if (meta._restartMsgShown) {
        delete meta._restartMsgShown;
        saveMetaToFile(meta);
      }
      return;
    }
    log(chalk.yellow("Update found. Pulling latest from GitHub..."));
    const p = Deno.run({ cmd: ["git", "pull"], stdout: "piped", stderr: "piped" });
    const { code } = await p.status();
    const raw = await p.output();
    const out = new TextDecoder().decode(raw);
    if (code === 0) {
      log(chalk.green("Update pulled successfully:\n" + out));
      meta.lastSha = latestSha;
      saveMetaToFile(meta);
      if (!meta._restartMsgShown) {
        log(chalk.yellow("Restart the server to apply updates."));
        meta._restartMsgShown = true;
        saveMetaToFile(meta);
      }
    } else {
      const err = new TextDecoder().decode(await p.stderrOutput());
      log(chalk.red("Failed to pull update:\n" + err));
    }
  } catch (e) {
    log(chalk.red(`Auto-update error: ${e && e.stack ? e.stack : e}`));
  }
}
setInterval(() => {
  checkAndAutoUpdate();
}, 1000 * 60 * 60);

const coreFunctions = {
  registerUser,
  searchUsers,
  executeSql,
  initializeDatabase,
  dbClose,
  getMeta: () => meta,
  setMeta: isAdmin ? setMeta : undefined,
  isAdmin: () => isAdmin,
  setAutoUpdate: (v) => setMeta("autoupdate", v),
  checkAndAutoUpdate,
};

if (useConsoleInterface) {
  log(chalk.yellow("Starting console interface..."));
  startConsoleInterface(coreFunctions);
} else {
}

log(chalk.green.bold("Core server components initialized."));


async function createPost(token, content) {
  if (!db) {
    return {
      success: false,
      status: 503,
      message: "Main database unavailable",
      error: "DB connection lost",
    };
  }
  if (!token || !content) {
    return {
      success: false,
      status: 422,
      message: "Missing parameters (token, content)",
    };
  }
  if (content.length > 256) {
    return {
      success: false,
      status: 413,
      message: "Message content too long (max 256 chars)",
    };
  }
  try {
    const user = db.prepare("SELECT id FROM users WHERE token = ?").get(token);
    if (!user) {
      return {
        success: false,
        status: 403,
        message: "Invalid or expired token",
      };
    }
    const postId = crypto.randomUUID();
    const timestamp = Math.floor(Date.now() / 1000);
    db.prepare(
      `INSERT INTO posts (id, author, content, timestamp) VALUES (?, ?, ?, ?)`,
    )
      .run(postId, user.id, content, timestamp);
    return {
      success: true,
      status: 201,
      message: "Posted successfully",
      payload: { postId },
    };
  } catch (e) {
    log(chalk.red(`Error creating post: ${e.message}`));
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      error: e.message,
    };
  }
}

function fetchPosts() {
  if (!db) {
    return {
      success: false,
      status: 503,
      message: "Main database unavailable",
      error: "DB connection lost",
    };
  }
  try {
    const stmt = db.prepare(
      `SELECT posts.id, posts.content, posts.timestamp, users.name as author_name, users.display_name FROM posts JOIN users ON posts.author = users.id ORDER BY posts.timestamp DESC`,
    );
    const posts = stmt.all();
    return {
      success: true,
      status: 200,
      message: "Fetched posts",
      payload: { posts },
    };
  } catch (e) {
    log(chalk.red(`Error fetching posts: ${e.message}`));
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      error: e.message,
    };
  }
}

function fetchUserCommunities(token) {
  if (!db) {
    return {
      success: false,
      status: 503,
      message: "Main database unavailable",
      error: "DB connection lost",
    };
  }
  try {
    const user = db.prepare("SELECT id FROM users WHERE token = ?").get(token);
    if (!user) {
      return {
        success: false,
        status: 403,
        message: "Invalid or expired token",
      };
    }
    const owned = db.prepare("SELECT * FROM communities WHERE owner_id = ?")
      .all(user.id);
    const allCommunities = db.prepare("SELECT * FROM communities").all();
    let member = [];
    for (const com of allCommunities) {
      const sanitizedName = sanitizeFilename(com.name);
      if (!sanitizedName) continue;
      const dbFilename = `bubbles/${sanitizedName}.db`;
      try {
        const communityDb = new Database(dbFilename);
        const found = communityDb.prepare("SELECT id FROM users WHERE id = ?")
          .get(user.id);
        if (found) member.push(com);
        communityDb.close();
      } catch (e) { /* skip if db can't be opened */ }
    }
    const all = [
      ...owned,
      ...member.filter((m) => !owned.some((o) => o.id === m.id)),
    ];
    return {
      success: true,
      status: 200,
      message: "Fetched user communities",
      payload: { communities: all },
    };
  } catch (e) {
    log(chalk.red(`Error fetching user communities: ${e.message}`));
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      error: e.message,
    };
  }
}

function isAllowedImageLink(url) {
  if (typeof url !== "string") return false;
  return (
    url.startsWith("https://i.ibb.co/") ||
    url.startsWith("https://www.i.ibb.co/") ||
    url.startsWith("https://cubeupload.com/") ||
    url.startsWith("https://www.cubeupload.com/") ||
    url.startsWith("https://files.catbox.moe/")
  );
}

function fetchUserInfo({ token, name }) {
  if (!db) return { success: false, status: 503, message: "DB unavailable" };
  let user;
  if (token) {
    user = db.prepare(
      "SELECT name, display_name, bio, avatar, banner, joined_at, tagline FROM users WHERE token = ?",
    ).get(token);
  } else if (name) {
    user = db.prepare(
      "SELECT name, display_name, bio, avatar, banner, joined_at, tagline FROM users WHERE name = ?",
    ).get(name);
  }
  if (!user) return { success: false, status: 404, message: "User not found" };
  return { success: true, status: 200, payload: user };
}

function updateUserInfo(token, { display_name, bio, avatar, banner, tagline }) {
  if (!db) return { success: false, status: 503, message: "DB unavailable" };
  const user = db.prepare("SELECT id FROM users WHERE token = ?").get(token);
  if (!user) {
    return { success: false, status: 403, message: "Invalid or expired token" };
  }

  if (avatar && !isAllowedImageLink(avatar)) {
    return {
      success: false,
      status: 400,
      message:
        "Avatar must be a link from ibb.co, cubeupload.com, or catbox.moe",
    };
  }
  if (banner && !isAllowedImageLink(banner)) {
    return {
      success: false,
      status: 400,
      message:
        "Banner must be a link from ibb.co, cubeupload.com, or catbox.moe",
    };
  }

  if (tagline && tagline.length > 128) {
    return {
      success: false,
      status: 400,
      message: "Tagline too long (max 128 characters)",
    };
  }

  const safeDisplayName = display_name || null;
  const safeBio = bio || null;
  const safeAvatar = avatar || null;
  const safeBanner = banner || null;
  const safeTagline = tagline || null;

  db.prepare(`UPDATE users SET 
        display_name = COALESCE(?, display_name), 
        bio = COALESCE(?, bio), 
        avatar = COALESCE(?, avatar), 
        banner = COALESCE(?, banner),
        tagline = COALESCE(?, tagline)
        WHERE token = ?`)
    .run(safeDisplayName, safeBio, safeAvatar, safeBanner, safeTagline, token);

  return { success: true, status: 200, message: "User info updated" };
}

function fetchPostsByUser(name) {
  if (!db) {
    return {
      success: false,
      status: 503,
      message: "Main database unavailable",
      error: "DB connection lost",
    };
  }
  try {
    const user = db.prepare(
      "SELECT id, name, display_name FROM users WHERE name = ?",
    ).get(name);
    if (!user) {
      return { success: false, status: 404, message: "User not found" };
    }
    const stmt = db.prepare(
      `SELECT posts.id, posts.content, posts.timestamp, users.name as author_name, users.display_name FROM posts JOIN users ON posts.author = users.id WHERE users.name = ? ORDER BY posts.timestamp DESC`,
    );
    const posts = stmt.all(name);
    return {
      success: true,
      status: 200,
      message: "Fetched user posts",
      payload: { posts },
    };
  } catch (e) {
    log(chalk.red(`Error fetching user posts: ${e.message}`));
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      error: e.message,
    };
  }
}

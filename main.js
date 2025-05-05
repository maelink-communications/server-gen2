// deno-lint-ignore-file
import chalk from "npm:chalk";
import { Database } from "@db/sqlite";
import { hash, verify } from "@ts-rex/bcrypt";
import { startConsoleInterface } from "./console.js"; // Import the console UI


let db = null;
const startTime = performance.now();


let useConsoleInterface = false;


function askAboutConsole() {
    const answer = prompt("Start full console interface? (y/N)", "n");
    if (answer && answer.trim().toLowerCase() === 'y') {
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
                 log(chalk.yellow(`Warning: Could not close existing DB connection: ${closeError.message}`));
             }
             db = null;
        }

        log(chalk.grey("Connecting to DB (data.db)..."));
        db = new Database("data.db");
        log(chalk.grey("DB connection established."));

        const usersTableExists = db.prepare("SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='users'").get().count > 0;
        const postsTableExists = db.prepare("SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='posts'").get().count > 0;

        if (!usersTableExists) {
            log("Setting up 'users' table...");
            db.exec(`
                CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    joined_at INTEGER DEFAULT (unixepoch()),
                    display_name TEXT,
                    password_hash TEXT NOT NULL,
                    token TEXT
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

        const communitiesTableExists = db.prepare("SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='communities'").get().count > 0;
        if (!communitiesTableExists) {
            log("Setting up 'communities' table...");
            db.exec(`
                CREATE TABLE communities (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL,
                    visibility TEXT NOT NULL DEFAULT
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
        if(db) {
            try { db.close(); } catch(e2){}
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
            return { success: true, payload: { changes: info.changes, lastInsertRowid: info.lastInsertRowid } };
        }
    } catch (e) {
        log(chalk.red(`SQL execution error: ${e.message}`)); 
        return { success: false, error: e.message };
    }
}

async function registerUser(username, password, displayName = null) {
    if (!db) {
        log(chalk.red("Database not available. Cannot register user."));
        return { success: false, message: "Database not connected", error: "Database not connected" };
    }
    try {
        const userId = crypto.randomUUID();
        const hashedPassword = await hash(password);
        const token = await hash(username + Date.now().toString()); 

        db.prepare(`
            INSERT INTO users (id, name, display_name, password_hash, token)
            VALUES (?, ?, ?, ?, ?)
        `).run(userId, username, displayName, hashedPassword, token);
        
        log(chalk.green(`User ${username} registered successfully`));
        return { 
            success: true, 
            message: "Registered successfully",
            payload: { token } 
        };
    } catch (e) {
        if (e.message.includes('UNIQUE constraint failed')) {
            error(`Username ${username} is already taken`);
            return { success: false, message: 'Username taken', error: 'Username taken' };
        }
        error(`Registration failed: ${e.message}`);
        return { success: false, message: `Registration failed: ${e.message}`, error: e.message };
    }
}

async function authenticateUser(username, password) {
    if (!db) {
        log(chalk.red("Database not available. Cannot authenticate user."));
        return { success: false, message: "Database not connected", error: "Database not connected" };
    }
    try {
        const user = db.prepare(`
            SELECT id, name, display_name, password_hash, token 
            FROM users 
            WHERE name = ?
        `).get(username);

        if (!user) {
            error(`User ${username} not found`);
            return { success: false, message: 'User not found', error: 'User not found' };
        }

        const isValid = await verify(password, user.password_hash);
        if (!isValid) {
            error(`Invalid password for user ${username}`);
            return { success: false, message: 'Incorrect credentials', error: 'Invalid password' };
        }

        let token = user.token;
        if (!token) {
            log(`Generating missing token for user ${username}`);
            token = await hash(username + Date.now().toString());
            db.prepare("UPDATE users SET token = ? WHERE id =?").run(token, user.id);
        }

        log(chalk.green(`User ${username} authenticated successfully`));
        return { 
            success: true, 
            message: "Authenticated successfully",
            payload: { token }
        };
    } catch (e) {
        error(`Authentication failed: ${e.message}`);
        return { success: false, message: `Authentication failed: ${e.message}`, error: e.message };
    }
}


Deno.serve({ 
    port: 3000,
    onListen({ port }) {
        log(chalk.cyan(`[WebSocket server listening on port ${port}]`));
    }
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
          socket.send(JSON.stringify({ success: false, message: "Invalid message format: Must be JSON." }));
          return;
      }

      log(`WebSocket parsed command: ${data.cmd}`);

      try {
        if (typeof data === 'object' && data !== null && data.cmd) {
          switch (data.cmd) {
            case "gpost": {
              const { token, communityId, content } = data;
              if (!token || !communityId || typeof content === 'undefined') {
                  socket.send(JSON.stringify({ success: false, message: "Missing parameters for gpost (token, communityId, content)" }));
                  break;
              }
              log(chalk.blue(`Processing 'gpost' for community ${communityId}...`));
              const result = await postToCommunity(token, communityId, content);
              const response = { success: result.success, message: result.message };
              if (result.payload) response.payload = result.payload;
              socket.send(JSON.stringify(response));
              break;
            }
            default: {
              log(chalk.yellow(`WebSocket received unknown command: ${data.cmd}`));
              socket.send(JSON.stringify({ success: false, message: `Unknown command: ${data.cmd}` }));
              break;
            }
          }
        } else {
          log(chalk.yellow(`WebSocket received data without a 'cmd' property: ${event.data}`));
          socket.send(JSON.stringify({ success: false, message: "Invalid message structure: Missing 'cmd' property." }));
        }
      } catch (error) {
          log(chalk.red(`WebSocket message processing error: ${error.message}`));
          socket.send(JSON.stringify({ success: false, message: "Internal Server Error during command processing." }));
      }
    };

    socket.onerror = (errorEvent) => {
        // Log the actual error object
        log(chalk.red(`WebSocket error: ${errorEvent.message || errorEvent}`));
        console.error(errorEvent); // Also log the full error object for details
    };

    socket.onclose = (event) => {
      log(`WebSocket connection closed. Code: ${event.code}, Reason: ${event.reason}`);
    };

    return response;
  } else {
    log(`Received non-WS request on WS server: ${req.method} ${req.url}`);
    return new Response("This port is for WebSocket connections only.", { status: 400 });
  }
});


Deno.serve({ 
    port: 3001,
    onListen({ port }) {
        log(chalk.cyan(`[HTTP server listening on port ${port}]`));
    }
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
        headers: { "Access-Control-Allow-Origin": "*" } 
    });
  }

  try {
    const body = await req.json();

    if (!body || typeof body.type !== 'string') {
      return new Response(JSON.stringify({ success: false, error: "Missing or invalid 'type' in request body" }), {
        status: 400,
        headers: { 
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        },
      });
    }

    switch (body.type) {
      case "reg": {
        const { user, password, displayName } = body;
        if (!user || !password) {
            return new Response(JSON.stringify({ success: false, error: "Username and password required for registration" }), {
                status: 400,
                headers: { 
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
            });
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
              "Access-Control-Allow-Origin": "*"
          },
        });
      }
      case "auth": {
        const { user, password } = body;
        if (!user || !password) {
            return new Response(JSON.stringify({ success: false, error: "Username and password required for auth" }), {
                status: 400,
                headers: { 
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                },
            });
        }
        log(`Handling 'auth' command for user: ${user}`);
        const authResult = await authenticateUser(user, password);
        return new Response(JSON.stringify(authResult), {
          status: authResult.success ? 200 : 401,
          headers: { 
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*"
          },
        });
      }
      case "communityCreate": {
        const { name, token, visibility, code } = body;
        if (!name || !token) {
            return new Response(JSON.stringify({ success: false, message: "Missing required parameters (name, token)" }), {
                status: 422, // Unprocessable Entity (missing fields)
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
            });
        }
        log(`Handling 'communityCreate' command for: ${name}`);
        const result = await createCommunity(name, token, visibility, code);
        const responsePayload = { success: result.success, message: result.message };
        if (!result.success && result.error) {
            responsePayload.error = result.error;
        }
        const responseBody = JSON.stringify(responsePayload);

        return new Response(responseBody, {
            status: result.status, // Use status from createCommunity result
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }
      case "communityFetchPublic": {
        const { token } = body;
        if (!token) {
            log(chalk.yellow("'communityFetchPublic' called without token."));
        }
        log(`Handling 'communityFetchPublic' command.`);
        const result = fetchPublicCommunities();

        const responsePayload = { success: result.success, message: result.message };
        if (result.payload) {
            responsePayload.communities = result.payload.communities;
        }
        if (!result.success && result.error) {
            responsePayload.error = result.error;
        }
        const responseBody = JSON.stringify(responsePayload);

        return new Response(responseBody, {
            status: result.status,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
        });
      }
      default: {
        error(`Unknown command received: ${body.type}`); // Corrected to body.type
        const responsePayload = { success: false, error: `Unknown command type: ${body.type}` }; // Corrected to body.type
        return new Response(JSON.stringify(responsePayload), {
          status: 404, 
          headers: { 
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*"
          },
        });
      }
    }
  } catch (e) {
    error(`Error processing request on HTTP server: ${e.message}`);
    const status = e instanceof SyntaxError ? 400 : 500;
    return new Response(JSON.stringify({ success: false, error: `Failed to process request: ${e.message}` }), {
      status: status,
      headers: { 
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
      },
    });
  }

});

function sanitizeFilename(name) {
    let sanitized = name.replace(/[^a-zA-Z0-9_-]/g, '_').replace(/_+/g, '_');
    sanitized = sanitized.replace(/^_+|_+$/g, '');
    if (!sanitized || sanitized.toLowerCase() === 'sqlite_') {
        return null;
    }
    return sanitized;
}

async function createCommunity(communityName, authToken, visibility = 'public', inviteCode = null) {
    if (!db) {
        return { success: false, status: 503, message: "Main database unavailable", error: "DB connection lost" };
    }
    if (!communityName || typeof communityName !== 'string' || communityName.length < 3 || communityName.length > 32) {
         return { success: false, status: 400, message: "Invalid community name (must be 3-32 characters)", error: "Invalid name length" };
    }

    // Validate visibility
    const validVisibilities = ['public', 'inviteonly'];
    if (!validVisibilities.includes(visibility)) {
        return { success: false, status: 400, message: "Invalid visibility type (must be 'public' or 'inviteonly')", error: "Invalid visibility" };
    }

    // Validate invite code if visibility is inviteonly
    if (visibility === 'inviteonly' && (!inviteCode || typeof inviteCode !== 'string' || inviteCode.length < 6)) {
        return { success: false, status: 400, message: "Invite code required (at least 6 characters) for invite-only communities", error: "Missing or invalid invite code" };
    }
    // Clear invite code if not inviteonly
    if (visibility !== 'inviteonly') {
        inviteCode = null;
    }

    const sanitizedName = sanitizeFilename(communityName);
    if (!sanitizedName) {
        return { success: false, status: 400, message: "Invalid characters in community name", error: "Invalid name format" };
    }

    try {
        const userStmt = db.prepare("SELECT id, name FROM users WHERE token = ?");
        const owner = userStmt.get(authToken);
        if (!owner) {
            return { success: false, status: 403, message: "Invalid or expired token", error: "Authentication failed" };
        }

        const existingCommunityStmt = db.prepare("SELECT id FROM communities WHERE name = ?");
        const existingCommunity = existingCommunityStmt.get(communityName);
        if (existingCommunity) {
            return { success: false, status: 409, message: "Community name already taken", error: "Name conflict" };
        }

        const communityId = crypto.randomUUID();
        const dbFilename = `b//${sanitizedName}.db`;

        try {
            await Deno.mkdir("b", { recursive: true });
            log(chalk.grey(`Ensured directory 'b' exists.`));
        } catch (dirError) {
             log(chalk.red(`Failed to create directory 'b': ${dirError.message}`));
             return { success: false, status: 500, message: "Failed to create community storage directory", error: dirError.message };
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
            log(chalk.grey(`Added owner ${owner.name} (${owner.id}) to ${dbFilename}'s users table.`));

        } catch (communityDbError) {
            log(chalk.red(`Failed to setup community DB ${dbFilename}: ${communityDbError.message}`));
            if (communityDb) { try { communityDb.close(); } catch(e){} }
            try { await Deno.remove(dbFilename); } catch(e){}
            return { success: false, status: 500, message: "Failed to initialize community database", error: communityDbError.message };
        } finally {
            if (communityDb) {
                try { communityDb.close(); } catch(e){ log(chalk.yellow(`Could not close community DB ${dbFilename}: ${e.message}`)); }
            }
        }

         try {
            const insertCommunityStmt = db.prepare("INSERT INTO communities (id, name, owner_id, visibility, invite_code) VALUES (?, ?, ?, ?, ?)");
            insertCommunityStmt.run(communityId, communityName, owner.id, visibility, inviteCode);
            log(chalk.green(`Community '${communityName}' (ID: ${communityId}, Visibility: ${visibility}) created successfully by ${owner.name}.`));
         } catch(mainDbError) {
             log(chalk.red(`Failed to record community '${communityName}' in main DB: ${mainDbError.message}`));
             return { success: false, status: 500, message: "Community created but failed to register globally", error: mainDbError.message };
         }

        return { success: true, status: 201, message: "Created successfully" };

    } catch (e) {
        log(chalk.red(`Unexpected error during community creation: ${e.message}`));
        return { success: false, status: 500, message: "Internal Server Error", error: e.message };
    }
}


function fetchPublicCommunities() {
     if (!db) {
        return { success: false, status: 503, message: "Main database unavailable", error: "DB connection lost" };
    }
    try {
        // Select relevant info for public communities
        const stmt = db.prepare(`
            SELECT id, name, owner_id, created_at 
            FROM communities 
            WHERE visibility = 'public' 
            ORDER BY created_at DESC
        `);
        const communities = stmt.all();

        // Client might expect `payload: { communities: [...] }` structure based on server.js
        // Or just `{ communities: [...] }`? Let's return the array directly in payload for now.
        return { success: true, status: 200, message: "Fetched public communities", payload: { communities: communities } };

    } catch (e) {
        log(chalk.red(`Error fetching public communities: ${e.message}`));
        return { success: false, status: 500, message: "Internal Server Error", error: e.message };
    }
}


async function postToCommunity(token, communityId, content) {
    if (!db) { // Check main DB connection
        return { success: false, status: 503, message: "Main database unavailable" };
    }
    if (!token || !communityId || !content) {
        return { success: false, status: 422, message: "Missing parameters (token, communityId, content)" };
    }
    if (content.length > 256) { // Content length validation
        return { success: false, status: 413, message: "Message content too long (max 256 chars)" };
    }

    let communityDb = null; // Variable to hold the community DB connection
    try {
        // 1. Authenticate user and get ID from main DB
        const userStmt = db.prepare("SELECT id FROM users WHERE token = ?");
        const user = userStmt.get(token);
        if (!user) {
            return { success: false, status: 403, message: "Invalid or expired token" };
        }
        const userId = user.id;

        // 2. Validate community and get its name from main DB
        const communityStmt = db.prepare("SELECT name FROM communities WHERE id = ?");
        const community = communityStmt.get(communityId);
        if (!community) {
            return { success: false, status: 404, message: "Community not found" };
        }
        const communityName = community.name;
        const sanitizedName = sanitizeFilename(communityName);
        if (!sanitizedName) {
            // Should not happen if creation sanitization worked, but check anyway
            log(chalk.red(`Error: Could not sanitize name '${communityName}' for community ID ${communityId}`));
            return { success: false, status: 500, message: "Internal error processing community name" };
        }
        const dbFilename = `b//${sanitizedName}.db`;

        // 3. Connect to the community database
        try {
            communityDb = new Database(dbFilename); // Opens existing
            log(chalk.grey(`Connected to community DB: ${dbFilename}`));
        } catch (dbOpenError) {
            log(chalk.red(`Failed to open community DB ${dbFilename}: ${dbOpenError.message}`));
            return { success: false, status: 500, message: "Failed to access community storage" };
        }

        // 4. Verify user membership in community DB
        const memberStmt = communityDb.prepare("SELECT id FROM users WHERE id = ?");
        const member = memberStmt.get(userId);
        if (!member) {
            // User token is valid, community exists, but user is not in this community's user list
            return { success: false, status: 403, message: "User not a member of this community" };
        }

        // 5. Insert the post into the '&default' channel table
        const postId = crypto.randomUUID();
        const insertStmt = communityDb.prepare(`
            INSERT INTO "&default" (id, author_id, content)
            VALUES (?, ?, ?)
        `);
        insertStmt.run(postId, userId, content);
        log(chalk.green(`User ${userId} posted message ${postId} to community ${communityId} (&default)`));

        // 6. Success
        return { success: true, status: 201, message: "Posted successfully", payload: { postId: postId } };

    } catch (error) {
        log(chalk.red(`Error during gpost processing: ${error.message}`));
        return { success: false, status: 500, message: "Internal Server Error" };
    } finally {

        if (communityDb) {
            try {
                communityDb.close();
                log(chalk.grey(`Closed community DB connection: ${dbFilename}`));
            } catch (dbCloseError) {
                log(chalk.yellow(`Warning: Failed to close community DB ${dbFilename}: ${dbCloseError.message}`));
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


const coreFunctions = {
    registerUser,      // Provided by main.js
    searchUsers,       // Provided by main.js
    executeSql,        // Provided by main.js
    initializeDatabase,// Provided by main.js
    dbClose,           // Provided by main.js
    // We can add more functions here if the console needs them (e.g., list communities?)
};


if (useConsoleInterface) {
    log(chalk.yellow("Starting console interface..."));
    startConsoleInterface(coreFunctions);
} else {
    // No console UI, just keep running the servers.
    // Basic logs will appear from log() calls.
}

log(chalk.green.bold("Core server components initialized."));




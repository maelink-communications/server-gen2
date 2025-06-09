// deno-lint-ignore-file
import chalk from "npm:chalk";
let demoMode = false;

export function enableDemoMode() {
  demoMode = true;
  console.log('[DEMO MODE ENABLED] All dangerous actions are simulated!');
}

function isDemoMode() {
  return demoMode;
}

let consoleCoreFunctions = null;

let startTime = performance.now();
let logs = [];
let consoleUpdateInterval = null;
const CONSOLE_UPDATE_INTERVAL = 100;
let isHandlingInput = false;
let inputBuffer = "";
let commandHistory = [];
let historyIndex = -1;
let currentInputBuffer = "";
let logScrollOffset = 0;
let terminalColumns = 80;
let terminalRows = 24;

const ansiRegex = /\x1b\[[0-9;]*[mK]/g;
function stripAnsi(text) {
  return text.replace(ansiRegex, "");
}

function applyPastelRainbow(text) {
  const MAX_RAINBOW_LENGTH = 100;
  if (text.length > MAX_RAINBOW_LENGTH) {
    return text;
  }

  const frequency = 0.3;
  const amplitude = 60;
  const center = 195;
  let rainbowText = "";
  const timeOffset = performance.now() / 1000;

  for (let i = 0; i < text.length; i++) {
    const r = Math.sin(frequency * (i + timeOffset) + 0) * amplitude + center;
    const g =
      Math.sin(frequency * (i + timeOffset) + 2 * Math.PI / 3) * amplitude +
      center;
    const b =
      Math.sin(frequency * (i + timeOffset) + 4 * Math.PI / 3) * amplitude +
      center;
    rainbowText += chalk.rgb(Math.round(r), Math.round(g), Math.round(b))(
      text[i],
    );
  }
  return rainbowText;
}

function formatDuration(totalSeconds) {
  if (totalSeconds < 0) totalSeconds = 0;

  const seconds = Math.floor(totalSeconds) % 60;
  const totalMinutes = Math.floor(totalSeconds / 60);
  const minutes = totalMinutes % 60;
  const totalHours = Math.floor(totalMinutes / 60);
  const hours = totalHours % 24;
  const days = Math.floor(totalHours / 24);

  let parts = [];
  if (days > 0) {
    parts.push(`${days}d`);
  }
  if (hours > 0) {
    parts.push(`${hours}h`);
  }
  if (minutes > 0) {
    parts.push(`${minutes}m`);
  }
  if (seconds > 0 || parts.length === 0) {
    parts.push(`${seconds}s`);
  }

  return parts.join(" ") || "0s";
}

function calculateColor(elapsed) {
  const red = { r: 255, g: 0, b: 0 };
  const pink = { r: 255, g: 105, b: 180 };
  const frequency = Math.PI;
  const factor = (Math.sin(elapsed * frequency) + 1) / 2;

  const r = Math.round(red.r + (pink.r - red.r) * factor);
  const g = Math.round(red.g + (pink.g - red.g) * factor);
  const b = Math.round(red.b + (pink.b - red.b) * factor);
  return { r, g, b };
}

function printStatusLines(elapsed) {
  const { columns } = Deno.consoleSize();
  let baseTimeStr = `Server has been up for ${formatDuration(elapsed)}`;
  let scrollIndicator = "";
  if (logScrollOffset > 0) {
    scrollIndicator = chalk.yellow(" [SCROLLED]");
  }
  const timePart = chalk.grey.dim(baseTimeStr) + scrollIndicator;

  let name = chalk.grey.dim("maelink [gen2] | server");
  let versionText;
  if (consoleCoreFunctions && typeof consoleCoreFunctions.getMeta === "function") {
    const meta = consoleCoreFunctions.getMeta();
    if (meta) {
      versionText = `${meta.version} | ${meta.codename}`;
    }
  }

  const { r, g, b } = calculateColor(elapsed);
  const coloredVersion = chalk.rgb(r, g, b)(versionText);

  const paddingLine1 = Math.max(
    0,
    columns - stripAnsi(name).length - 1 - stripAnsi(coloredVersion).length,
  );
  const finalStringLine1 = `${name}${
    " ".repeat(paddingLine1 + 1)
  }${coloredVersion}`;

  const helpTextPart = chalk.grey.dim(`Type 'help' for commands`);
  const visibleTimeLength = stripAnsi(timePart).length;
  const visibleHelpLength = stripAnsi(helpTextPart).length;
  const paddingLine2 = Math.max(
    1,
    columns - visibleTimeLength - visibleHelpLength,
  );
  const finalStringLine2 = `${timePart}${
    " ".repeat(paddingLine2)
  }${helpTextPart}`;

  const separator = chalk.grey.dim("─".repeat(columns));

  return [
    finalStringLine1,
    finalStringLine2,
    separator,
  ];
}

let cursorVisible = true;
let cursorBlinkInterval = null;

function getRainbowCursorChar(input, cursorPos) {
  const MAX_RAINBOW_LENGTH = 100;
  const frequency = 0.3;
  const amplitude = 60;
  const center = 195;
  const timeOffset = performance.now() / 1000;

  let i = (input.length > 0 && cursorPos > 0)
    ? Math.min(cursorPos - 1, input.length - 1, MAX_RAINBOW_LENGTH - 1)
    : 0;

  let r = Math.sin(frequency * (i + timeOffset) + 0) * amplitude + center;
  let g = Math.sin(frequency * (i + timeOffset) + 2 * Math.PI / 3) * amplitude + center;
  let b = Math.sin(frequency * (i + timeOffset) + 4 * Math.PI / 3) * amplitude + center;

  const hex = "#" +
    [r, g, b].map((x) => Math.max(0, Math.min(255, Math.round(x))).toString(16).padStart(2, "0")).join("");
  return chalk.hex(hex)("▉");
}

function updateConsole() {
  if (isHandlingInput) return;

  const { columns, rows } = Deno.consoleSize();
  terminalColumns = columns;
  terminalRows = rows;

  console.clear();

  const elapsed = (performance.now() - startTime) / 1000;
  const [statusLine, helpTextLine, separatorLine] = printStatusLines(elapsed);
  console.log(statusLine);
  console.log(helpTextLine);
  console.log(separatorLine);

  const availableLogLines = rows - 4;
  const maxScrollOffset = Math.max(0, logs.length - availableLogLines);
  logScrollOffset = Math.min(logScrollOffset, maxScrollOffset);

  const logEndIndex = logs.length - logScrollOffset;
  const logStartIndex = Math.max(0, logEndIndex - availableLogLines);
  const visibleLogs = logs.slice(logStartIndex, logEndIndex);

  let linesPrinted = 0;
  for (const line of visibleLogs) {
    console.log(line.substring(0, columns));
    linesPrinted++;
  }

  const blankLines = Math.max(0, availableLogLines - linesPrinted);
  for (let i = 0; i < blankLines; i++) {
    console.log();
  }

  const promptSymbol = "> ";
  const promptWidth = stripAnsi(chalk.yellow(promptSymbol)).length;
  const availableInputWidth = Math.max(0, columns - promptWidth);

  const rawLength = inputBuffer.length;
  const safetyBuffer = 5;

  let inputDisplay;
  let cursorPos = inputBuffer.length;
  let inputRaw = inputBuffer;
  if (rawLength > availableInputWidth - safetyBuffer) {
    const startIndex = Math.max(0, rawLength - availableInputWidth);
    inputDisplay = inputBuffer.substring(startIndex);
    inputRaw = inputBuffer.substring(startIndex);
    cursorPos = inputDisplay.length;
  } else {
    inputDisplay = applyPastelRainbow(inputBuffer);
    inputRaw = inputBuffer;
    cursorPos = inputBuffer.length;
  }

  let promptLine;
  if (inputDisplay.length === 0) {
    promptLine = chalk.yellow(promptSymbol) + (cursorVisible ? getRainbowCursorChar("", 0) : " ");
  } else {
    promptLine = chalk.yellow(promptSymbol) + inputDisplay + (cursorVisible ? getRainbowCursorChar(inputRaw, cursorPos) : " ");
  }

  Deno.stdout.writeSync(new TextEncoder().encode(promptLine));
}
function startCursorBlink() {
  if (cursorBlinkInterval) clearInterval(cursorBlinkInterval);
  cursorBlinkInterval = setInterval(() => {
    cursorVisible = !cursorVisible;
    updateConsole();
  }, 500);
}
function stopCursorBlink() {
  if (cursorBlinkInterval) clearInterval(cursorBlinkInterval);
  cursorBlinkInterval = null;
  cursorVisible = true;
}

function prompt(question) {
  let wasRaw = false;
  try {
    Deno.stdin.setRaw(false);
    wasRaw = true;
  } catch (e) { /* Ignore if already not raw */ }

  Deno.stdout.writeSync(new TextEncoder().encode(question));
  const buf = new Uint8Array(1024);
  const n = Deno.stdin.readSync(buf);

  let response = "";
  if (n !== null) {
    response = new TextDecoder().decode(buf.subarray(0, n)).trim();
  }

  if (wasRaw) {
    try {
      Deno.stdin.setRaw(true);
    } catch (e) { /* Ignore */ }
  }

  if (n === null) {
    handleExit();
  }
  return response;
}

let showLogTimestamps = true;

export function logToConsoleBuffer(content) {
  logScrollOffset = 0;
  let logLine;
  if (showLogTimestamps) {
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
    logLine = ` ${chalk.grey(`[${elapsed}s]`)} ${content}`;
  } else {
    logLine = ` ${content}`;
  }
  logs.push(logLine);

  if (!isHandlingInput) {
    updateConsole();
  }
}
function consoleErrorDisplay(content) {
  const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
  const errorLogLine = ` ${chalk.grey(`[${elapsed}s]`)} ${
    chalk.red.bold(content)
  }`;
  logs.push(errorLogLine);

  if (consoleUpdateInterval) clearInterval(consoleUpdateInterval);
  isHandlingInput = true;

  let wasRaw = false;
  try {
    Deno.stdin.setRaw(false);
    wasRaw = true;
  } catch (e) {}

  console.clear();
  console.log(chalk.red.bold("\n*** CONSOLE COMMAND ERROR ***"));
  console.log(errorLogLine);
  console.log();
  prompt(chalk.yellow("Press Enter to continue..."));

  if (wasRaw) {
    try {
      Deno.stdin.setRaw(true);
    } catch (e) {}
  }
  isHandlingInput = false;
  consoleUpdateInterval = setInterval(updateConsole, CONSOLE_UPDATE_INTERVAL);
  updateConsole();
}

async function startInputListener(executeCommandCallback) {
  Deno.stdin.setRaw(true);
  const decoder = new TextDecoder();
  let partialEscapeSequence = "";

  for await (const chunk of Deno.stdin.readable) {
    let text = decoder.decode(chunk);

    text = partialEscapeSequence + text;
    partialEscapeSequence = "";

    let i = 0;
    while (i < text.length) {
      const char = text[i];

      if (char === "\r" || char === "\n") {
        const commandToExecute = inputBuffer.trim();
        const loggedInput = inputBuffer;
        inputBuffer = "";
        historyIndex = -1;
        currentInputBuffer = "";

        if (commandToExecute) {
          logToConsoleBuffer(chalk.yellow("> ") + loggedInput);
          if (
            commandToExecute &&
            (commandHistory.length === 0 ||
              commandHistory[commandHistory.length - 1] !== commandToExecute)
          ) {
            commandHistory.push(commandToExecute);
          }
          await executeCommandCallback(commandToExecute);
        } else {
          updateConsole();
        }
        i++;
      } else if (char === "\x7f" || char === "\x08") {
        inputBuffer = inputBuffer.slice(0, -1);
        if (historyIndex !== -1) {
          currentInputBuffer = inputBuffer;
          historyIndex = -1;
        }
        updateConsole();
        i++;
      } else if (char === "\x03") {
        handleExit();
        i++;
      } else if (char === "\x1b") {
        if (i + 1 < text.length) {
          const nextChar = text[i + 1];
          if (nextChar === "[") {
            if (i + 2 < text.length) {
              const commandChar = text[i + 2];
              if (commandChar === "A") {
                if (historyIndex === -1) currentInputBuffer = inputBuffer;
                if (commandHistory.length > 0) {
                  historyIndex = Math.max(
                    0,
                    historyIndex === -1
                      ? commandHistory.length - 1
                      : historyIndex - 1,
                  );
                  inputBuffer = commandHistory[historyIndex];
                }
                i += 3;
              } else if (commandChar === "B") {
                if (historyIndex !== -1) {
                  historyIndex++;
                  if (historyIndex >= commandHistory.length) {
                    historyIndex = -1;
                    inputBuffer = currentInputBuffer;
                  } else {
                    inputBuffer = commandHistory[historyIndex];
                  }
                }
                i += 3;
              } else {
                i++;
              }
            } else {
              partialEscapeSequence = text.substring(i);
              break;
            }
          } else if (nextChar === "w") {
            const availableLogLines = terminalRows - 4;
            const maxScrollOffset = Math.max(
              0,
              logs.length - availableLogLines,
            );
            logScrollOffset = Math.min(maxScrollOffset, logScrollOffset + 1);
            updateConsole();
            i += 2;
          } else if (nextChar === "s") {
            logScrollOffset = Math.max(0, logScrollOffset - 1);
            updateConsole();
            i += 2;
          } else {
            i++;
          }
        } else {
          partialEscapeSequence = char;
          break;
        }
      } else {
        const code = char.charCodeAt(0);
        const isPrintable = code >= 32 && code <= 126;

        if (isPrintable) {
          inputBuffer += char;
          if (historyIndex !== -1) {
            currentInputBuffer = inputBuffer;
            historyIndex = -1;
          }
          updateConsole();
        }
        i++;
      }
    }
  }
}

function handleExit() {
  if (consoleUpdateInterval) clearInterval(consoleUpdateInterval);

  if (typeof consoleCoreFunctions?.requestServerShutdown === "function") {
    consoleCoreFunctions.requestServerShutdown();
  } else {
    logToConsoleBuffer(chalk.yellow("Exiting console interface only..."));
    try {
      Deno.stdin.setRaw(false);
      console.log("\x1b[?25h");
      console.log(chalk.yellow("Exiting console interface..."));
    } catch (e) {
      console.warn(
        "Warning: Failed to restore terminal state cleanly.",
        e.message,
      );
    }
  }
  // Actually exit the process
  Deno.exit(0);
}

async function executeCommand(commandString, coreFunctions) {
  isHandlingInput = true;
  if (consoleUpdateInterval) {
    clearInterval(consoleUpdateInterval);
    consoleUpdateInterval = null;
  }

  const [command, ...args] = commandString.trim().split(/\s+/);
  const commandArgs = args.join(" ");

  const needsCleanOutput = [
    "search",
    "sql",
    "help",
    "register",
    "cowsay",
    "erase",
  ].includes(command);
  if (needsCleanOutput) {
    console.clear();
  } else {
  }

  switch (command) {
    case "register": {
      const { columns } = Deno.consoleSize();
      console.log(chalk.cyan("Registering new user"));
      console.log(chalk.cyan("─".repeat(columns)));

      const username = prompt(chalk.blue("Username: "));
      if (!username) {
        logToConsoleBuffer(
          chalk.red("Registration cancelled: Username required."),
        );
        break;
      }
      const password = prompt(chalk.blue("Password: "));
      if (!password) {
        logToConsoleBuffer(
          chalk.red("Registration cancelled: Password required."),
        );
        break;
      }
      const displayName = prompt(chalk.blue("Display name (optional): "));

      console.log(chalk.grey("Registering..."));

      const result = await coreFunctions.registerUser(
        username,
        password,
        displayName || null,
      );
      if (result.success) {
        logToConsoleBuffer(
          chalk.green(
            `Registered ${username}. Token: ${result.payload?.token}`,
          ),
        );
      } else {
        logToConsoleBuffer(
          chalk.red(`Registration failed: ${result.message || result.error}`),
        );
      }

      prompt(chalk.yellow("Press Enter to continue..."));
      break;
    }
    case "help": {
      const { columns } = Deno.consoleSize();
      console.log(chalk.cyan("Your friendly neighborhood help screen!"));
      console.log(chalk.cyan("─".repeat(columns)));
      console.log(chalk.grey(" Use Alt+W / Alt+S to scroll through logs."));
      console.log();
      console.log(chalk.blue(" register") + " - Register a new user.");
      console.log(
        chalk.blue(" search <term>") +
          " - Search for users by name or display name.",
      );
      console.log(
        chalk.blue(" sql <query>") +
          "   - Execute a raw SQL query against the database.",
      );
      console.log(
        chalk.blue(" restart") +
          "  - Re-initialize the database connection and tables.",
      );
      console.log(
        chalk.blue(" cowsay <text>") +
          "  - Make a rainbow cow speak rainbow text.",
      );
      console.log(
        chalk.red.bold(" erase") + chalk.red("      - ") +
          chalk.yellow.bold(
            "PERMANENTLY delete the database file! Requires confirmation.",
          ),
      );
      console.log(chalk.blue(" help") + "     - Show this help message.");
      console.log(
        chalk.blue(" exit") +
          "     - Exit the application (console interface).",
      );
      console.log(
        chalk.blue(" setmeta") +
          "     - Change the metadata of the server. Usage: setmeta <version|codename> <value>",
      );
      console.log(
        chalk.blue(" setautoupdate") +
          " - Enable/disable auto-update from GitHub. Usage: setautoupdate <true|false>",
      );
      console.log(
        chalk.blue(" forceupdate") +
          "    - Force an immediate update check/pull from GitHub.",
      );
      console.log(chalk.cyan("─".repeat(columns)));
      prompt(chalk.yellow("Press Enter to continue..."));
      break;
    }
    case "search": {
      if (!commandArgs) {
        logToConsoleBuffer(chalk.red("Usage: search <term>"));
      } else {
        const { columns } = Deno.consoleSize();
        console.log(chalk.cyan(`Searching users for: "${commandArgs}"`));
        console.log(chalk.cyan("─".repeat(columns)));

        const result = coreFunctions.searchUsers(commandArgs);
        if (result.success) {
          if (result.payload.length > 0) {
            console.log(
              chalk.underline("Username      Display name          Joined at"),
            );
            result.payload.forEach((user) => {
              const joinDate = new Date(user.joined_at * 1000).toLocaleString();
              const displayName = user.display_name || chalk.grey("(none)");
              console.log(
                `${user.name.padEnd(14)}${displayName.padEnd(22)}${joinDate}`,
              );
            });
          } else {
            console.log(chalk.yellow("No users found matching that term."));
          }
        } else {
          console.log(chalk.red(`Search error: ${result.error}`));
        }
        console.log(chalk.cyan("─".repeat(columns)));
        prompt(chalk.yellow("Press Enter to continue..."));
      }
      break;
    }
    case "sql": {
      if (!commandArgs) {
        logToConsoleBuffer(chalk.red("Usage: sql <query>"));
      } else {
        const { columns } = Deno.consoleSize();
        console.log(chalk.cyan(`Executing SQL: ${commandArgs}`));
        console.log(chalk.cyan("─".repeat(columns)));

        const result = coreFunctions.executeSql(commandArgs);
        if (result.success) {
          if (Array.isArray(result.payload)) {
            if (result.payload.length > 0) {
              const headers = Object.keys(result.payload[0]);
              console.log(chalk.underline(headers.join(" | ")));
              result.payload.forEach((row) => {
                const values = headers.map((h) =>
                  row[h] === null ? chalk.grey("NULL") : row[h]
                );
                console.log(values.join(" | "));
              });
            } else {
              console.log(
                chalk.yellow(
                  "Query executed successfully, but returned no rows.",
                ),
              );
            }
          } else {
            console.log(chalk.green(`Query executed successfully!`));
            console.log(chalk.grey(`  Changes: ${result.payload.changes}`));
            if (
              result.payload.lastInsertRowid !== undefined &&
              result.payload.lastInsertRowid !== 0
            ) {
              console.log(
                chalk.grey(
                  `  Last insert row ID: ${result.payload.lastInsertRowid}`,
                ),
              );
            }
          }
        } else {
          console.log(chalk.red(`SQL error: ${result.error}`));
        }
        console.log(chalk.cyan("─".repeat(columns)));
        prompt(chalk.yellow("Press Enter to continue..."));
      }
      break;
    }
    case "restart": {
      logToConsoleBuffer(
        chalk.yellow("Attempting to restart database initialization..."),
      );

      const success = coreFunctions.initializeDatabase();
      if (success) {
        logToConsoleBuffer(
          chalk.green("Database re-initialization completed."),
        );
      } else {
        logToConsoleBuffer(
          chalk.red("Database re-initialization failed. Check logs above."),
        );
      }
      break;
    }
    case "cowsay": {
      const sayText = commandArgs || "moo";
      const rainbowText = applyPastelRainbow(sayText);
      const textLength = sayText.length;
      const topBubble = " " + "_".repeat(textLength + 2);
      const bottomBubble = " " + "-".repeat(textLength + 2);
      const middleBubble = `< ${rainbowText} >`;

      const cowArt = `
         \\   ^__^
          \\  (oo)\\_______
             (__)\\       )\\/\\
                 ||----w |
                 ||     ||
            `;
      const rainbowCow = applyPastelRainbow(cowArt);

      console.log(topBubble);
      console.log(middleBubble);
      console.log(bottomBubble);
      console.log(rainbowCow);
      console.log();

      prompt(chalk.yellow("Press Enter to continue..."));
      break;
    }
    case "erase": {
      const confirmationPhrase = "Yes, erase all user data";
      const { columns } = Deno.consoleSize();

      console.log(chalk.red.bold("\n*** WARNING: DESTRUCTIVE ACTION ***"));
      console.log(chalk.red("─".repeat(columns)));
      console.log(
        chalk.yellow(
          "You are about to permanently delete the database file! Requires confirmation.",
        ),
      );
      console.log(chalk.yellow("This action cannot be undone."));
      console.log(chalk.red("─".repeat(columns)));
      console.log(`To confirm, please type the following phrase exactly:`);
      console.log(chalk.cyan(`"${confirmationPhrase}"`));
      console.log();

      const userInput = prompt(chalk.red.bold("Confirmation: "));

      if (userInput === confirmationPhrase) {
        if (isDemoMode()) {
          logToConsoleBuffer(
            chalk.yellow(
              "[DEMO] Would delete database file 'data.db' (simulated)",
            ),
          );
          break;
        }

        logToConsoleBuffer(
          chalk.yellow(
            "Confirmation received. Attempting to delete database file...",
          ),
        );
        try {
          if (
            coreFunctions.dbClose && typeof coreFunctions.dbClose === "function"
          ) {
            logToConsoleBuffer(
              chalk.grey("Closing database connection via core function..."),
            );
            coreFunctions.dbClose();
            logToConsoleBuffer(
              chalk.grey("Database connection closed via core."),
            );
          } else {
            logToConsoleBuffer(
              chalk.yellow(
                "Warning: dbClose function not provided or DB might be already closed.",
              ),
            );
          }

          await Deno.remove("data.db");
          logToConsoleBuffer(
            chalk.green(
              "Database file 'data.db' deleted successfully. Exiting console.",
            ),
          );
          handleExit();
        } catch (deleteError) {
          logToConsoleBuffer(
            chalk.red(
              `Failed to delete database file 'data.db': ${deleteError.message}`,
            ),
          );
          logToConsoleBuffer(chalk.red("Exiting console anyway."));
          handleExit();
        }
      } else {
        logToConsoleBuffer(
          chalk.green(
            "Confirmation failed or incorrect. Data erasure cancelled.",
          ),
        );
      }
      break;
    }
    case "setmeta": {
      if (!coreFunctions.isAdmin || !coreFunctions.isAdmin()) {
        logToConsoleBuffer(chalk.red("You do not have an admin key set. Access denied."));
        break;
      }
      const [metaKey, ...metaValueArr] = args;
      const metaValue = metaValueArr.join(" ");
      if (!metaKey || !metaValue) {
        logToConsoleBuffer(chalk.red("Usage: setmeta <version|codename|autoupdate> <value>"));
        break;
      }
      if (typeof coreFunctions.setMeta === "function" && coreFunctions.setMeta(metaKey, metaValue)) {
         // do nothing
      } else {
        logToConsoleBuffer(chalk.red("Failed to update metadata. Valid keys: version, codename, autoupdate"));
      }
      break;
    }
    case "setautoupdate": {
      const [value] = args;
      if (typeof coreFunctions.setAutoUpdate !== "function") {
        logToConsoleBuffer(chalk.red("Auto-update not supported."));
        break;
      }
      if (value !== "true" && value !== "false" && value !== "1" && value !== "0") {
        logToConsoleBuffer(chalk.red("Usage: setautoupdate <true|false>"));
        break;
      }
      coreFunctions.setAutoUpdate(value === "true" || value === "1");
      logToConsoleBuffer(chalk.green(`Auto-update set to: ${value}`));
      break;
    }
    case "forceupdate": {
      if (typeof coreFunctions.checkAndAutoUpdate !== "function") {
        logToConsoleBuffer(chalk.red("Auto-update not supported."));
        break;
      }
      logToConsoleBuffer(chalk.yellow("Forcing update check..."));
      await coreFunctions.checkAndAutoUpdate();
      break;
    }
    case "exit": {
      handleExit();

      break;
    }
    default: {
      logToConsoleBuffer(
        chalk.yellow(`Unknown command: '${command}'. Type 'help'.`),
      );
      break;
    }
  }

  isHandlingInput = false;
  if (!consoleUpdateInterval) {
    consoleUpdateInterval = setInterval(updateConsole, CONSOLE_UPDATE_INTERVAL);
  }
  updateConsole();
}

export function startConsoleInterface(coreFunctions) {
  consoleCoreFunctions = coreFunctions;
  logToConsoleBuffer(chalk.green.bold("Initializing console interface..."));

  const requiredFns = [
    "registerUser",
    "searchUsers",
    "executeSql",
    "initializeDatabase",
    "dbClose",
  ];
  for (const fnName of requiredFns) {
    if (typeof coreFunctions?.[fnName] !== "function") {
      console.error(
        chalk.red.bold(
          `Critical Error: Core function '${fnName}' not provided to startConsoleInterface. Console disabled.`,
        ),
      );
      return;
    }
  }

  try {
    console.log("\x1b[?25l");
  } catch (_e) { /* ignore */ }

  if (!consoleUpdateInterval) {
    consoleUpdateInterval = setInterval(updateConsole, CONSOLE_UPDATE_INTERVAL);
  }

  startCursorBlink(); // Start blinking cursor

  startInputListener((cmd) => executeCommand(cmd, coreFunctions));

  logToConsoleBuffer(chalk.green("Console interface ready."));
  // Hide timestamps after core server components initialized
  logToConsoleBuffer(chalk.green.bold("Core server components initialized."));
  showLogTimestamps = false;
}

export { demoMode };

const levels = { error: 0, warn: 1, info: 2, debug: 3 };

let config = {
  level: "info",
  enabled: true,
  output: console,
};

export function init({ level = "info", enabled = true, output = console } = {}) {
  config.level = level;
  config.enabled = enabled;
  config.output = output || console;
}

function shouldLog(level) {
  return config.enabled && levels[level] <= levels[config.level];
}

function sendToBackground(level, args) {
  try {
    if (!globalThis.chrome?.runtime?.id) {
      if (typeof config.output[level] === "function") {
        config.output[level](...args);
      } else {
        config.output.log(...args);
      }
      return;
    }

    const message = args
      .map((arg) => {
        if (arg instanceof Error) {
          return arg.stack || arg.message;
        }
        if (typeof arg === "object") {
          try {
            return JSON.stringify(arg);
          } catch {
            return String(arg);
          }
        }
        return String(arg);
      })
      .join(" ");

    chrome.runtime
      .sendMessage({ type: "log", level, message })
      .catch((error) => {
        if (error.message.includes("Receiving end does not exist")) {
          if (typeof config.output[level] === "function") {
            config.output[level](...args);
          } else {
            config.output.log(...args);
          }
        } else {
          console.error("Failed to send log to background:", error.message);
        }
      });
  } catch (e) {
    console.error("Failed to send log:", e);
  }
}

export function error(...args) {
  if (shouldLog("error")) {
    config.output.error(...args);
    sendToBackground("error", args);
  }
}

export function warn(...args) {
  if (shouldLog("warn")) {
    config.output.warn(...args);
    sendToBackground("warn", args);
  }
}

export function log(...args) {
  if (shouldLog("info")) {
    config.output.log(...args);
    sendToBackground("info", args);
  }
}

export function debug(...args) {
  if (shouldLog("debug")) {
    if (typeof config.output.debug === "function") {
      config.output.debug(...args);
    } else {
      config.output.log(...args);
    }
    sendToBackground("debug", args);
  }
}

export default {
  init,
  log,
  warn,
  error,
  debug,
};

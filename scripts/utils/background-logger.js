export async function store(level, message) {
  try {
    const result = await chrome.storage.local.get(["debugLogs"]);
    const logs = result.debugLogs || [];
    logs.push({ level, message, timestamp: new Date().toISOString() });
    if (logs.length > 1000) {
      logs.splice(0, logs.length - 1000);
    }
    await chrome.storage.local.set({ debugLogs: logs });
  } catch (e) {
    console.error("Failed to store log:", e);
  }
}


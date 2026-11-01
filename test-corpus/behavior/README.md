This benign fixture exercises ordinary extension behavior without executing it.
`source.txt` is copied to `main.js` in temporary directory and installed-extension tests.
The independently authored expectations live in `src/behavior.smoke.test.ts`.

`fixture.vsix` contains the same source and manifest. Python's standard-library
`zipfile` wrote its ZIP_DEFLATED records with fixed timestamps. The archive is
independent of the TypeScript test ZIP builder.

SHA-256: `eb000cca1b3780b94d1847d7618be3eb82049053895ac6b9857e197e70be92a4`.

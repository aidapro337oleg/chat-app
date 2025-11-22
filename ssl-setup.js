// ssl-generator.js
const fs = require('fs');
const { generateKeyPairSync } = require('crypto');

console.log('🔐 Generating SSL certificates using Node.js crypto...');

// Create SSL directory if it doesn't exist
if (!fs.existsSync('./ssl')) {
  fs.mkdirSync('./ssl', { recursive: true });
}

try {
  // Generate RSA key pair
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  // Create a self-signed certificate
  const selfsigned = require('selfsigned');
  const attrs = [{ name: 'commonName', value: '26.191.144.233' }];
  const options = {
    days: 365,
    keySize: 2048,
    extensions: [
      {
        name: 'subjectAltName',
        altNames: [
          { type: 2, value: 'localhost' },
          { type: 2, value: '26.191.144.233' },
          { type: 7, ip: '26.191.144.233' }
        ]
      }
    ]
  };

  const pems = selfsigned.generate(attrs, options);

  // Write certificate and key
  fs.writeFileSync('./ssl/cert.pem', pems.cert);
  fs.writeFileSync('./ssl/key.pem', pems.private);

  console.log('✅ SSL certificates generated successfully!');
  console.log('📍 Certificate includes: localhost and 26.191.144.233');
  
} catch (error) {
  console.error('❌ Error generating SSL certificates:', error.message);
  console.log('⚠️  Falling back to HTTP only');
  
  // Create placeholder files to avoid errors
  if (!fs.existsSync('./ssl/cert.pem')) {
    fs.writeFileSync('./ssl/cert.pem', '');
  }
  if (!fs.existsSync('./ssl/key.pem')) {
    fs.writeFileSync('./ssl/key.pem', '');
  }
}
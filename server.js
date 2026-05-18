require('dotenv').config();
const express = require('express');
const soap    = require('soap');
const fs      = require('fs');
const path    = require('path');
const { registerUser, loginUser, validateToken } = require('./authService');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── CORS — хамгийн эхэнд, бүх зүйлийн өмнө ─────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, SOAPAction, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

app.use(express.text({ type: '*/*' }));

// ── SOAP Service definition ──────────────────────────────────────
const service = {
  AuthService: {
    AuthServicePort: {
      RegisterUser:  (args, callback) => registerUser(args, callback),
      LoginUser:     (args, callback) => loginUser(args, callback),
      ValidateToken: (args, callback) => validateToken(args, callback)
    }
  }
};

// ── Health check ─────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'SOAP Auth Service', port: PORT });
});

// ── SOAP-ийг Express route болгон handle хийнэ ──────────────────
const wsdlText = fs.readFileSync(path.join(__dirname, 'auth.wsdl'), 'utf8');

// WSDL endpoint
app.get('/soap', (req, res) => {
  if (req.query.wsdl !== undefined) {
    res.setHeader('Content-Type', 'text/xml');
    return res.send(wsdlText);
  }
  res.status(400).send('Use ?wsdl for WSDL');
});

// SOAP POST endpoint — XML-ийг parse хийж service рүү дамжуулна
app.post('/soap', (req, res) => {
  const body       = req.body || '';
  const soapAction = (req.headers['soapaction'] || '').replace(/"/g, '');

  // SOAPAction-аас operation нэрийг авна
  let operation = soapAction;
  if (!operation) {
    const match = body.match(/<(?:auth:)?(\w+)>/);
    operation = match ? match[1] : '';
  }

  const args = parseSOAPBody(body);

  const respond = (err, result) => {
    if (err) {
      res.setHeader('Content-Type', 'text/xml');
      return res.status(500).send(soapFault(err.message));
    }
    res.setHeader('Content-Type', 'text/xml');
    res.send(soapResponse(operation, result));
  };

  if (operation === 'RegisterUser') {
    registerUser(args, respond);
  } else if (operation === 'LoginUser') {
    loginUser(args, respond);
  } else if (operation === 'ValidateToken') {
    validateToken(args, respond);
  } else {
    res.setHeader('Content-Type', 'text/xml');
    res.status(400).send(soapFault('Unknown operation: ' + operation));
  }
});

// ── XML parse helper ─────────────────────────────────────────────
function parseSOAPBody(xml) {
  const args = {};
  const tags = ['username', 'password', 'email', 'token'];
  tags.forEach(tag => {
    const m = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
    if (m) args[tag] = m[1];
  });
  return args;
}

// ── SOAP Response builder ────────────────────────────────────────
function soapResponse(operation, result) {
  const fields = Object.entries(result)
    .map(([k, v]) => `<${k}>${v}</${k}>`)
    .join('');
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://auth.service/">
  <soap:Body>
    <tns:${operation}Response>${fields}</tns:${operation}Response>
  </soap:Body>
</soap:Envelope>`;
}

function soapFault(msg) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault><faultstring>${msg}</faultstring></soap:Fault>
  </soap:Body>
</soap:Envelope>`;
}

// ── Start ────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ SOAP Auth Service: http://localhost:${PORT}`);
  console.log(`📄 WSDL: http://localhost:${PORT}/soap?wsdl`);
  console.log(`🧼 SOAP endpoint: http://localhost:${PORT}/soap`);
});

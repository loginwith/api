import express from 'express';
import bodyParser from 'body-parser'
import cors from 'cors'
import morgan from 'morgan'
import nacl from 'tweetnacl'
import Web3 from 'web3'
import bitcoinMessage from 'bitcoinjs-message'

import { parseLWT, parseTemplate } from './js/src/lwt.js'

// TODO: https://github.com/bitcoinjs/bitcoinjs-message
// TODO: https://github.com/trezor/connect/blob/develop/docs/methods/server/server.js

const app = express()
const web3 = new Web3()

app.disable('x-powered-by')

app.use(morgan('combined'))
app.use(bodyParser.urlencoded({
  extended: false
}))
app.use(bodyParser.json())
app.use(cors())

app.get('/', (req, res) => res.send('0K'))

app.get('/robots.txt', (req, res) => {
  res.header('Content-Type', 'text/plain')
  res.send(`User-agent: *
Disallow: /`)
})

app.post('/v1/verify', (req, res) => {
  // TODO: fetch from db
  const { domain } = req.body

  let ticket

  try {
    ticket = parseLWT(req.body.ticket)
    console.log(`ticket: `, ticket)
    console.log(`body: `, req.body)

    const tpl = parseTemplate(ticket.ct, ticket.msg)
    if(tpl.domain != domain) {
      console.log(`domain mismatch: ${tpl.domain} != ${domain}`)
      console.log(`template:`, tpl)
      throw new Error('DOMAIN_MISMATCH')
    }
  } catch (err) {
    console.log(`error: `, err)
    return res.status(401).json({
      valid: false,
      error: err.code || err.message
    })
  }

  switch(ticket.ct) {
    case 0: { // Bitcoin
      if(!bitcoinMessage.verify(ticket.msg, ticket.a, ticket.sig)) {
        return res.status(401).json({
          valid: false,
          error: 'SIGNATURE_VERIFICATION_FAILED'
        })
      }

      break;
    }
    case 60: { // Ethereum
      const data = '0x' + bytesToHex(new TextEncoder().encode(ticket.msg))
      const a = web3.eth.accounts.recover(data, ticket.sig)

      // TODO: verify

      if(a.toLowerCase() != ticket.pub.toLowerCase()) {
        return res.status(401).json({
          valid: false,
          error: 'SIGNATURE_VERIFICATION_FAILED'
        })
      }

      break;
    }
    case 501: { // Solana
      console.log(`VVVV: msg: `, new TextEncoder().encode(ticket.msg))
      console.log(`VVVV: sig hex: `, ticket.sig)
      console.log(`VVVV: sig: `, hexToBytes(ticket.sig))
      console.log(`VVVV: pub hex: `, ticket.pub)
      console.log(`VVVV: pub: `, hexToBytes(ticket.pub))

      // this sometimes FAILS WTF??
      const valid = nacl.sign.detached.verify(
        new TextEncoder().encode(ticket.msg),
        hexToBytes(ticket.sig),
        hexToBytes(ticket.pub)
      )

      if(!valid) {
        return res.status(401).json({
          valid: false,
          error: 'SIGNATURE_VERIFICATION_FAILED'
        })
      }

      break;
    }
    default:
      throw new Error(`unsupported coin type: ${ticket.ct}`)
  }

  return res.json({
    valid: true,
    network: ctToNetwork(ticket.ct),
    account: ticket.a,
    display_name: abbreviate(ticket.a),
    expires_at: ticket.exp,
    __parsed_lwt: ticket
  })
})

const port = process.env.PORT || 1235
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})

console.log(new TextDecoder().decode(hexToBytes("68656c6c6f20e6bca2e5ad9720f09f918d")))

function ctToNetwork(ct) {
  switch(ct) {
    case 60:
      return "ethereum";
    case 501:
      return "solana";
    default:
      return "<unknown>";
  }
}

function bytesToHex(bytes) {
  return Array.from(
    bytes,
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for(let i = 0; i !== bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function abbreviate(addr, max = 20) {
  if(addr.length > max) {
    if(addr.startsWith("0x")) {
      addr = addr.substr(2);
      addr = addr.substr(0, 4) + "..." + addr.substr(-4);
      addr = "0x" + addr;
    } else {
      addr = addr.substr(0, 4) + "..." + addr.substr(-4);
    }
  }

  return addr;
}

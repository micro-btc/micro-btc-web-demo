import './App.css'
import * as btc from 'micro-btc-signer'
import * as secp from '@noble/secp256k1'
const toHex = secp.utils.bytesToHex
import { hex } from '@scure/base';

export const makeScriptTRNS = (pubkeys: Uint8Array[]) => {
  return {
    type: 'tr_ns',
    script: btc.OutScript.encode({
      type: 'tr_ns',
      pubkeys: pubkeys
    })
  }
}

const keySetsTesting = [
  {
    priv: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
    ecdsaPub: hex.decode('030000000000000000000000000000000000000000000000000000000000000001'),
    schnorrPub: hex.decode('0101010101010101010101010101010101010101010101010101010101010101')
  },
  {
    priv: hex.decode('0000000000000000000000000000000000000000000000000000000000000002'),
    ecdsaPub: hex.decode('030000000000000000000000000000000000000000000000000000000000000002'),
    schnorrPub: hex.decode('0202020202020202020202020202020202020202020202020202020202020202')
  },
  {
    priv: hex.decode('0000000000000000000000000000000000000000000000000000000000000003'),
    ecdsaPub: hex.decode('030000000000000000000000000000000000000000000000000000000000000003'),
    schnorrPub: hex.decode('1212121212121212121212121212121212121212121212121212121212121212')
  },
]

type KeySet = {
  priv: Uint8Array,
  ecdsaPub: Uint8Array,
  schnorrPub: Uint8Array
}

let keySetsProduction: KeySet[] = []

for (var i = 0; i < 3; i++) {
  const priv = secp.utils.randomPrivateKey()
  keySetsProduction.push({
    priv: priv,
    ecdsaPub: secp.getPublicKey(priv, true),
    schnorrPub: secp.schnorr.getPublicKey(priv)
  })
}

// Set the key set as testing or production
const keySets = keySetsTesting // keySetsProduction

// Create alternate lists of keys
//const privKeys = keySets.map(keySet => keySet.priv)
//const ecdsaPubs = keySets.map(keySet => keySet.ecdsaPub)
const schnorrPubs = keySets.map(keySet => keySet.schnorrPub)

type ScriptSection = {
  title: string,
  privateKeys?: string[],
  publicKeys?: string[],
  script?: string,
  scriptHash?: string,
  address?: string,
  leafScripts?: string[],
  pubKeyType?: string
}

let scriptSections: ScriptSection[] = []

const classicPKHInfo = btc.p2pkh(keySets[0].ecdsaPub)
scriptSections.push({
  "title": "Classic Public Key Hash",
  "privateKeys": [toHex(keySets[0].priv)],
  "publicKeys": [toHex(keySets[0].ecdsaPub)],
  "script": toHex(classicPKHInfo.script),
  "scriptHash": "",
  "address": classicPKHInfo.address,
  "pubKeyType": "ECDSA"
})

const classicMultisigScriptInfo = btc.p2ms(2, keySets.map(keySet => keySet.ecdsaPub))
const classicMultisigScriptHashinfo = btc.p2sh(classicMultisigScriptInfo)
scriptSections.push({
  "title": "Classic Script Hash: 2 of {A, B, C}",
  "privateKeys": keySets.map(k => toHex(k.priv)),
  "publicKeys": keySets.map(k => toHex(k.ecdsaPub)),
  "script": toHex(classicMultisigScriptInfo.script),
  "scriptHash": toHex(classicMultisigScriptHashinfo.script),
  "address": classicMultisigScriptHashinfo.address,
  "pubKeyType": "ECDSA"
})

// Witness public key hash
const witnessPKHInfo = btc.p2wpkh(keySets[0].ecdsaPub)
scriptSections.push({
  "title": "Witness Public Key Hash",
  "privateKeys": [toHex(keySets[0].priv)],
  "publicKeys": [toHex(keySets[0].ecdsaPub)],
  "script": toHex(witnessPKHInfo.script),
  "scriptHash": "",
  "address": witnessPKHInfo.address,
  "pubKeyType": "ECDSA"
})

const multisigScriptInfo = btc.p2ms(2, keySets.map(k => k.ecdsaPub))
const wshMultisigInfo = btc.p2wsh(multisigScriptInfo)
scriptSections.push({
  "title": "Witness Script Hash: 2 of {A, B, C}",
  "privateKeys": keySets.map(k => toHex(k.priv)),
  "publicKeys": keySets.map(k => toHex(k.ecdsaPub)),
  "script": toHex(multisigScriptInfo.script),
  "scriptHash": toHex(wshMultisigInfo.script),
  "address": wshMultisigInfo.address,
  "pubKeyType": "ECDSA"
})

const taprootScriptInfo = btc.p2tr(keySets[0].schnorrPub)
scriptSections.push({
  "title": "Taproot: Single Public Key",
  "privateKeys": [toHex(keySets[0].priv)],
  "publicKeys": [toHex(keySets[0].schnorrPub)],
  "script": toHex(taprootScriptInfo.script),
  "address": taprootScriptInfo.address,
  "pubKeyType": "Schnorr"
})

const taprootLeafScriptsNS = btc.p2tr_ns(2, keySets.map(k => k.schnorrPub))
const taprootScriptInfoNS = btc.p2tr(undefined, taprootLeafScriptsNS)
scriptSections.push({
  "title": "Taproot Multi-Leaf: (A&B) or (A&C) or (B&C)",
  "privateKeys": keySets.map(k => toHex(k.priv)),
  "publicKeys": keySets.map(k => toHex(k.schnorrPub)),
  "leafScripts": taprootLeafScriptsNS.map(s => toHex(s.script)),
  "script": toHex(taprootScriptInfoNS.script),
  "address": taprootScriptInfoNS.address,
  "pubKeyType": "Schnorr"
})

const taprootSingleLeafScriptMS = btc.p2tr_ms(2, keySets.map(k => k.schnorrPub))
const taprootScriptInfoMS = btc.p2tr(undefined, taprootSingleLeafScriptMS)
scriptSections.push({
  "title": "Taproot Single-Leaf: 2 of {A, B, C}",
  "privateKeys": keySets.map(k => toHex(k.priv)),
  "publicKeys": keySets.map(k => toHex(k.schnorrPub)),
  "leafScripts": [toHex(taprootSingleLeafScriptMS.script)],
  "script": toHex(taprootScriptInfoMS.script),
  "address": taprootScriptInfoMS.address,
  "pubKeyType": "Schnorr"
})

const taprootLeafScriptsNS_AorBC2 = [
  makeScriptTRNS([schnorrPubs[0]]),
  makeScriptTRNS([schnorrPubs[1], schnorrPubs[2]]),
]
const taprootScriptInfoNS_AorBC2 = btc.p2tr(undefined, taprootLeafScriptsNS_AorBC2)
scriptSections.push({
  "title": "Taproot Multi-Leaf: A or (B&C)",
  "privateKeys": keySets.map(k => toHex(k.priv)),
  "publicKeys": keySets.map(k => toHex(k.schnorrPub)),
  "leafScripts": taprootLeafScriptsNS_AorBC2.map(s => toHex(s.script)),
  "script": toHex(taprootScriptInfoNS_AorBC2.script),
  "address": taprootScriptInfoNS_AorBC2.address,
  "pubKeyType": "Schnorr"
})

function App() {
  return (
    <div className="App">
      <h1>MICRO-BTC Web Demo</h1>
 
      <div className='App-main'>
        {scriptSections.map((section, index) => (
          <div key={index}>
            <h2>{section.title}</h2>
            {section.privateKeys ? <p>
              <b>Private Key{section.privateKeys.length > 1 ? 's' : ''}:</b><br/>
              {section.privateKeys.map((privateKey, index) => 
                <span key={index}>{privateKey}<br/></span>
              )}
            </p> : null }
            {section.publicKeys ? <p>
              <b>{section.pubKeyType} Public Key{section.publicKeys.length > 1 ? 's' : ''}:</b><br/>
              {section.publicKeys.map((publicKey, index) => 
                <span key={index}>{publicKey}<br/></span>
              )}
            </p> : null }
            {section.leafScripts ? <p>
              <b>Leaf Scripts:</b><br/>
              {section.leafScripts.map((leafScript, index) => 
                <span key={index}>{leafScript}<br/></span>
              )}
            </p> : null }
            {section.script ? <p><b>Script:</b><br/>{section.script}</p> : null }
            {section.scriptHash ?
              <p><b>Script Hash:</b><br/>{section.scriptHash}</p>
            : null }
            {section.address ? <p><b>Address:</b><br/>{section.address}</p> : null }
          </div>
        ))}
      </div>
    </div>
  )
}

export default App

/*[
  {
    type: 'tr_ns',
    script: btc.OutScript.encode({
      type: 'tr_ns', pubkeys: [keySets[0].schnorrPub]
    })
  },
  {
    type: 'tr_ns',
    script: btc.OutScript.encode({
      type: 'tr_ns', pubkeys: [keySets[1].schnorrPub, keySets[2].schnorrPub]
    })
  }
]*/

/*const keySetAABC = [keySets[0]].concat(keySets)
const taprootLeafScriptsNS_AorBC = btc.p2tr_ns(2, keySetAABC.map(k => k.schnorrPub), true)
const taprootScriptInfoNS_AorBC = btc.p2tr(undefined, taprootLeafScriptsNS_AorBC)
scriptSections.push({
  "title": "Taproot: Multi-Leaf: A|(B&C)",
  "privateKeys": keySetAABC.map(k => toHex(k.priv)),
  "pubKeys": keySetAABC.map(k => toHex(k.schnorrPub)),
  "leafScripts": taprootLeafScriptsNS_AorBC.map(s => toHex(s.script)),
  "script": toHex(taprootScriptInfoNS_AorBC.script),
  "address": taprootScriptInfoNS_AorBC.address,
  "pubKeyType": "Schnorr"
})*/
  /*keySets.push({
    priv: priv,
    ecdsaPub: secp.getPublicKey(priv, true),
    schnorrPub: testKeys[i].schnorr
  })*/
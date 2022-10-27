import './App.css'
import * as btc from 'micro-btc-signer'
import * as secp from '@noble/secp256k1'
import { hex } from '@scure/base';
const toHex = secp.utils.bytesToHex

const testKeys = [
  { schnorr: hex.decode('0101010101010101010101010101010101010101010101010101010101010101') },
  { schnorr: hex.decode('0202020202020202020202020202020202020202020202020202020202020202') },
  { schnorr: hex.decode('1212121212121212121212121212121212121212121212121212121212121212') },
]

type KeySet = {
  privKey: Uint8Array,
  ecdsaPubKey: Uint8Array,
  schnorrPubKey: Uint8Array
}

let keySets: KeySet[] = []

for (var i = 0; i < 3; i++) {
  const privKey = secp.utils.randomPrivateKey()
  keySets.push({
    privKey: privKey,
    ecdsaPubKey: secp.getPublicKey(privKey, true),
    schnorrPubKey: secp.schnorr.getPublicKey(privKey)
  })
  /*keySets.push({
    privKey: privKey,
    ecdsaPubKey: secp.getPublicKey(privKey, true),
    schnorrPubKey: testKeys[i].schnorr
  })*/
}

type ScriptSection = {
  title: string,
  privateKeys?: string[],
  pubKeys?: string[],
  script?: string,
  scriptHash?: string,
  address?: string,
  leafScripts?: string[],
  pubKeyType?: string
}

let scriptSections: ScriptSection[] = []

const classicPKHInfo = btc.p2pkh(keySets[0].ecdsaPubKey)
scriptSections.push({
  "title": "Classic Public Key Hash",
  "privateKeys": [toHex(keySets[0].privKey)],
  "pubKeys": [toHex(keySets[0].ecdsaPubKey)],
  "script": toHex(classicPKHInfo.script),
  "scriptHash": "",
  "address": classicPKHInfo.address,
  "pubKeyType": "ECDSA"
})

const classicMultisigScriptInfo = btc.p2ms(2, keySets.map(keySet => keySet.ecdsaPubKey))
const classicMultisigScriptHashinfo = btc.p2sh(classicMultisigScriptInfo)
scriptSections.push({
  "title": "Classic Script Hash: 2/3 Multisig",
  "privateKeys": keySets.map(k => toHex(k.privKey)),
  "pubKeys": keySets.map(k => toHex(k.ecdsaPubKey)),
  "script": toHex(classicMultisigScriptInfo.script),
  "scriptHash": toHex(classicMultisigScriptHashinfo.script),
  "address": classicMultisigScriptHashinfo.address,
  "pubKeyType": "ECDSA"
})

// Witness public key hash
const witnessPKHInfo = btc.p2wpkh(keySets[0].ecdsaPubKey)
scriptSections.push({
  "title": "Witness Public Key Hash",
  "privateKeys": [toHex(keySets[0].privKey)],
  "pubKeys": [toHex(keySets[0].ecdsaPubKey)],
  "script": toHex(witnessPKHInfo.script),
  "scriptHash": "",
  "address": witnessPKHInfo.address,
  "pubKeyType": "ECDSA"
})

const multisigScriptInfo = btc.p2ms(2, keySets.map(k => k.ecdsaPubKey))
const wshMultisigInfo = btc.p2wsh(multisigScriptInfo)
scriptSections.push({
  "title": "Witness Script Hash: 2/3 Multisig",
  "privateKeys": keySets.map(k => toHex(k.privKey)),
  "pubKeys": keySets.map(k => toHex(k.ecdsaPubKey)),
  "script": toHex(multisigScriptInfo.script),
  "scriptHash": toHex(wshMultisigInfo.script),
  "address": wshMultisigInfo.address,
  "pubKeyType": "ECDSA"
})

const taprootScriptInfo = btc.p2tr(keySets[0].schnorrPubKey)
scriptSections.push({
  "title": "Taproot: Single Public Key",
  "privateKeys": [toHex(keySets[0].privKey)],
  "pubKeys": [toHex(keySets[0].schnorrPubKey)],
  "script": toHex(taprootScriptInfo.script),
  "address": taprootScriptInfo.address,
  "pubKeyType": "Schnorr"
})

const taprootLeafScriptsNS = btc.p2tr_ns(2, keySets.map(k => k.schnorrPubKey))
const taprootScriptInfoNS = btc.p2tr(undefined, taprootLeafScriptsNS)
scriptSections.push({
  "title": "Taproot: Multi-Leaf 2/3 Multisig",
  "privateKeys": keySets.map(k => toHex(k.privKey)),
  "pubKeys": keySets.map(k => toHex(k.schnorrPubKey)),
  "leafScripts": taprootLeafScriptsNS.map(s => toHex(s.script)),
  "script": toHex(taprootScriptInfoNS.script),
  "address": taprootScriptInfoNS.address,
  "pubKeyType": "Schnorr"
})

const taprootSingleLeafScriptMS = btc.p2tr_ms(2, keySets.map(k => k.schnorrPubKey))
const taprootScriptInfoMS = btc.p2tr(undefined, taprootSingleLeafScriptMS)
scriptSections.push({
  "title": "Taproot: Single-Leaf 2/3 Multisig",
  "privateKeys": keySets.map(k => toHex(k.privKey)),
  "pubKeys": keySets.map(k => toHex(k.schnorrPubKey)),
  "leafScripts": [toHex(taprootSingleLeafScriptMS.script)],
  "script": toHex(taprootScriptInfoMS.script),
  "address": taprootScriptInfoMS.address,
  "pubKeyType": "Schnorr"
})

function App() {
  return (
    <div className="App">
      <h1>Micro-BTC Web Demo</h1>
 
      <div className='App-main'>
        {scriptSections.map((section, index) => (
          <div key={index}>
            <h2>{section.title}</h2>
            {section.privateKeys ? <p>
              <b>Private Key{section.privateKeys.length > 1 ? 's' : ''}:</b><br/>
              {section.privateKeys.map((privKey, index) => 
                <span key={index}>{privKey}<br/></span>
              )}
            </p> : null }
            {section.pubKeys ? <p>
              <b>{section.pubKeyType} Public Key{section.pubKeys.length > 1 ? 's' : ''}:</b><br/>
              {section.pubKeys.map((pubKey, index) => 
                <span key={index}>{pubKey}<br/></span>
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
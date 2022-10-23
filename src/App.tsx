import { useState } from 'react'
import './App.css'
import * as btc from 'micro-btc-signer'
import * as secp from '@noble/secp256k1'
const toHex = secp.utils.bytesToHex;

// Public Keys
let privKeys: Uint8Array[] = [];
let pubKeys: Uint8Array[] = [];
let schnorrPubKeys: Uint8Array[] = [];
for (var i = 0; i < 3; i++) {
  const privKey = secp.utils.randomPrivateKey();
  privKeys.push(privKey);
  const pubKey = secp.getPublicKey(privKey, true);
  pubKeys.push(pubKey);
  const schnorrPubKey = secp.schnorr.getPublicKey(privKey);
  schnorrPubKeys.push(schnorrPubKey);
}

// Witness public key hash
const pubKeyInfo = btc.p2wpkh(pubKeys[0]);
const pubKeyScript = pubKeyInfo.script;
const pkhAddress = pubKeyInfo.address;

// Witness script hash of a public key hash
const pubKeyHashScriptInfo = btc.p2pkh(pubKeys[0]);
const pubKeyHashScript = pubKeyHashScriptInfo.script;
const wshPubKeyHashScriptInfo = btc.p2wsh(pubKeyHashScriptInfo);
const wshPubKeyHashScript = wshPubKeyHashScriptInfo.script;
const wshPkhAddress = wshPubKeyHashScriptInfo.address;

// Witness script hash of a 2/3 multisig
const multisigScriptInfo = btc.p2ms(2, pubKeys);
const multisigScript = multisigScriptInfo.script;
const multisigScriptHashInfo = btc.p2wsh(multisigScriptInfo);
const multisigScriptHash = multisigScriptHashInfo.script;
const multisigAddress = multisigScriptHashInfo.address;

// Taproot of Simple public key
const taprootScriptInfo = btc.p2tr(schnorrPubKeys[0]);
const taprootScript = taprootScriptInfo.script;
const taprootAddress = taprootScriptInfo.address;

// Taproot: Multi-Leaf 2/3 Multisig
const taprootLeafScriptsNS = btc.p2tr_ns(2, schnorrPubKeys);
console.log(taprootLeafScriptsNS);
const taprootScriptInfoNS = btc.p2tr(undefined, taprootLeafScriptsNS);
console.log(taprootScriptInfoNS);
const taprootScriptNS = taprootScriptInfoNS.script;
const taprootAddressNS = taprootScriptInfoNS.address;

function App() {
  const [count, setCount] = useState(0)

  const sections = [
    {
      "title": "Witness Public Key Hash",
      "privateKeys": [toHex(privKeys[0])],
      "publicKeys": [toHex(pubKeys[0])],
      "script": toHex(pubKeyScript),
      "scriptHash": "",
      "address": pkhAddress
    },
    {
      "title": "Witness Script Hash: 2/3 Multisig",
      "privateKeys": privKeys.map(p => toHex(p)),
      "publicKeys": pubKeys.map(p => toHex(p)),
      "script": toHex(multisigScript),
      "scriptHash": toHex(multisigScriptHash),
      "address": multisigAddress
    },
    {
      "title": "Taproot: Single Public Key",
      "privateKeys": [toHex(privKeys[0])],
      "schnorrPublicKeys": [toHex(schnorrPubKeys[0])],
      "script": toHex(taprootScript),
      "address": taprootAddress
    },
    {
      "title": "Taproot: Multi-Leaf 2/3 Multisig",
      "privateKeys": privKeys.map(p => toHex(p)),
      "schnorrPublicKeys": schnorrPubKeys.map(p => toHex(p)),
      "script": toHex(taprootScriptNS),
      "leafScripts": taprootLeafScriptsNS.map(s => toHex(s.script)),
      "address": taprootAddressNS
    },
  ]

  return (
    <div className="App">
      <h1>Micro-BTC Web Demo</h1>
 
      <div className='App-main'>
        {sections.map((section, index) => (
          <div key={index}>
            <h2>{section.title}</h2>
            {section.privateKeys ? <p>
              <b>Private Keys:</b><br/>
              {section.privateKeys.map((privKey, index) => 
                <span key={index}>{privKey}<br/></span>
              )}
            </p> : null }
            {section.publicKeys ? <p>
              <b>Public Keys:</b><br/>
              {section.publicKeys.map((pubKey, index) => 
                <span key={index}>{pubKey}<br/></span>
              )}
            </p> : null }
            {section.schnorrPublicKeys ? <p>
              <b>Schnorr Public Keys:</b><br/>
              {section.schnorrPublicKeys.map((pubKey, index) => 
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

import { useState } from 'react'
import './App.css'
import * as btc from 'micro-btc-signer'
import * as secp from '@noble/secp256k1'
const toHex = secp.utils.bytesToHex;

// Public Keys
const privKey1 = secp.utils.randomPrivateKey();
const privKey2 = secp.utils.randomPrivateKey(); 
const privKey3 = secp.utils.randomPrivateKey();
const pubKey1 = secp.getPublicKey(privKey1, true);
const pubKey2 = secp.getPublicKey(privKey2, true);
const pubKey3 = secp.getPublicKey(privKey3, true);
const realPubKeys = [pubKey1, pubKey2, pubKey3];
/*const dummyPubKeys = [
  hex.decode('030000000000000000000000000000000000000000000000000000000000000001'),
  hex.decode('030000000000000000000000000000000000000000000000000000000000000002'),
  hex.decode('030000000000000000000000000000000000000000000000000000000000000003'),
];
const dummySchnorrPubKeys = [
  hex.decode('0101010101010101010101010101010101010101010101010101010101010101'),
]
*/

// Witness public key hash
const pubKeyInfo = btc.p2wpkh(pubKey1);
const pubKeyScript = pubKeyInfo.script;
const pkhAddress = pubKeyInfo.address;

// Witness script hash of a public key hash
const pubKeyHashScriptInfo = btc.p2pkh(pubKey1);
const pubKeyHashScript = pubKeyHashScriptInfo.script;
const wshPubKeyHashScriptInfo = btc.p2wsh(pubKeyHashScriptInfo);
const wshPubKeyHashScript = wshPubKeyHashScriptInfo.script;
const wshPkhAddress = wshPubKeyHashScriptInfo.address;

// Witness script hash of a 2/3 multisig
const multisigScriptInfo = btc.p2ms(2, realPubKeys);
const multisigScript = multisigScriptInfo.script;
const multisigScriptHashInfo = btc.p2wsh(multisigScriptInfo);
const multisigScriptHash = multisigScriptHashInfo.script;
const multisigAddress = multisigScriptHashInfo.address;

// Schnorr
const schnorrPubKey1 = secp.schnorr.getPublicKey(privKey1);
const schnorrPubKey2 = secp.schnorr.getPublicKey(privKey2);
const schnorrPubKey3 = secp.schnorr.getPublicKey(privKey3);
const schnorrPubKeys = [schnorrPubKey1, schnorrPubKey2, schnorrPubKey3];

// Taproot of Simple public key
const taprootScriptInfo = btc.p2tr(schnorrPubKey1);
const taprootScript = taprootScriptInfo.script;
const taprootAddress = taprootScriptInfo.address;

// Taproot: Single Leaf 2/3 Multisig

// Taproot: Multi Leaf 2/3 Multisig (EXPERIMENTAL)

function App() {
  const [count, setCount] = useState(0)

  const sections = [
    {
      "title": "Witness Public Key Hash",
      "publicKeys": [toHex(pubKey1)],
      "script": toHex(pubKeyScript),
      "scriptHash": "",
      "address": pkhAddress
    },
    {
      "title": "Witness Script Hash: 2/3 Multisig",
      "publicKeys": realPubKeys.map(p => toHex(p)),
      "script": toHex(multisigScript),
      "scriptHash": toHex(multisigScriptHash),
      "address": multisigAddress
    },
    {
      "title": "Taproot: Simple Public Key",
      "publicKeys": [toHex(schnorrPubKey1)],
      "script": toHex(taprootScript),
      "address": taprootAddress
    },
    /*{
      "title": "Taproot: 2/3 Multisig, Single-Leaf"
    },
    {
      "title": "Taproot: 2/3 Multisig, Multi-Leaf"
    }*/
  ]

  return (
    <div className="App">
      <h1>Micro-BTC Web Demo</h1>
 
      <div className='App-main'>
        {sections.map((section, index) => (
          <div key={index}>
            <h2>{section.title}</h2>
            {section.publicKeys ? <p>
              <b>Public Keys:</b><br/>
              {section.publicKeys.map((pubKey, index) => 
                <span key={index}>{pubKey}<br/></span>
              )}
            </p> : null }
            {section.script ? <p><b>Script:</b><br/>{section.script}</p> : null }
            {section.scriptHash ?
              <p><b>Script Hash:</b><br/>{section.scriptHash}</p>
            : null }
            {section.address ? <p><b>Address:</b><br/>{section.address}</p> : null }
          </div>
        ))}

        {/*<h3>Witness Public Key Hash</h3>
        <p><b>Public key:</b><br/>{toHex(pubKey1)}</p>
        <p><b>Script:</b><br/>{toHex(pubKeyScript)}</p>
        <p><b>Address:</b><br/>{pkhAddress}</p>

        <h3>Witness Script Hash of a 2/3 Multisig</h3>
        <p>
          <b>Public Keys:</b><br/>
          {realPubKeys.map(pubKey => 
            <span>{toHex(pubKey)}<br/></span>
          )}
        </p>
        <p><b>Script:</b><br/>{toHex(multisigScript)}</p>
        <p><b>Script hash:</b><br/>{toHex(multisigScriptHash)}</p>
          <p><b>Address:</b><br/>{multisigAddress}</p>*/}
      </div>

           {/*<div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
      </div>*/}

              {/*<h3>Witness Script Hash of a Public Key Hash</h3>
        <p><b>Public key:</b> {toHex(pubKey1)}</p>
        <p><b>Script:</b> {toHex(pubKeyHashScript)}</p>
        <p><b>Script hash:</b> {toHex(wshPubKeyHashScript)}</p>
        <p><b>Address:</b> {wshPkhAddress}</p>*/}
    </div>
  )
}

export default App

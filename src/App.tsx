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
];*/

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

function App() {
  const [count, setCount] = useState(0)

  return (
    <div className="App">
      <h1>Micro-BTC Web Demo</h1>
      {/*<div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
      </div>*/}
      <div className='App-main'>
        <h3>Witness Public Key Hash</h3>
        <p><b>Public key:</b> {toHex(pubKey1)}</p>
        <p><b>Script:</b> {toHex(pubKeyScript)}</p>
        <p><b>Address:</b> {pkhAddress}</p>

        <h3>Witness Script Hash of a Public Key Hash</h3>
        <p><b>Public key:</b> {toHex(pubKey1)}</p>
        <p><b>Script:</b> {toHex(pubKeyHashScript)}</p>
        <p><b>Script hash:</b> {toHex(wshPubKeyHashScript)}</p>
        <p><b>Address:</b> {wshPkhAddress}</p>

        <h3>Witness Script Hash of a 2/3 Multisig</h3>
        <p><b>Public Keys:</b> {toHex(pubKey1)}, {toHex(pubKey2)}, {toHex(pubKey3)} </p>
        <p><b>Script:</b> {toHex(multisigScript)}</p>
        <p><b>Script hash:</b> {toHex(multisigScriptHash)}</p>
        <p><b>Address:</b> {multisigAddress}</p>
      </div>
    </div>
  )
}

export default App

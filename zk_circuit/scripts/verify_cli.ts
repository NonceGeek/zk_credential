const snarkjs = require('snarkjs');
const readline = require('readline');
const util = require('util');
const { BigNumber, Wallet } = require('ethers');
const fs = require('fs');
const wc = require('../build/verify/verify_js/witness_calculator.js');
import { getPublicKey, sign, Point } from '@noble/secp256k1';

const wasm = '../build/verify/verify_js/verify.wasm';
const zkey = '../build/verify/verify.zkey';
const vkey = '../build/verify/vkey.json';
const wtnsFile = '../build/verify/witness.wtns';


function bigint_to_array(n: number, k: number, x: bigint) {
  let mod: bigint = 1n;
  for (let idx = 0; idx < n; idx++) {
      mod = mod * 2n;
  }

  let ret: bigint[] = [];
  let x_temp: bigint = x;
  for (let idx = 0; idx < k; idx++) {
      ret.push(x_temp % mod);
      x_temp = x_temp / mod;
  }
  return ret;
}

// bigendian
function Uint8Array_to_bigint(x: Uint8Array) {
  var ret: bigint = 0n;
  for (var idx = 0; idx < x.length; idx++) {
      ret = ret * 256n;
      ret = ret + BigInt(x[idx]);
  }
  return ret;
}

function isHex(str: string): boolean {
  if (str.length % 2 !== 0) return false;
  if (str.slice(0, 2) !== '0x') return false;
  const allowedChars = '0123456789abcdefABCDEF';
  for (let i = 2; i < str.length; i++)
      if (!allowedChars.includes(str[i]))
          return false;
  return true;
}

function bigint_to_Uint8Array(x: bigint) {
  let ret: Uint8Array = new Uint8Array(32);
  for (let idx = 31; idx >= 0; idx--) {
      ret[idx] = Number(x % 256n);
      x = x / 256n;
  }
  return ret;
}

function isValidPrivateKey(privkey: string): boolean {
  if (privkey.length !== 66) return false;
  if (!isHex(privkey)) return false;
  return true;
}

function isValidAddr(addr: string): boolean {
  if (addr.length !== 42) return false;
  if (!isHex(addr)) return false;
  return true;
}

function toWordArray(x: bigint, nWords: number, bitsPerWord: number): string[] {
  const res: string[] = [];
  let remaining = x;
  const base = 2n ** BigInt(bitsPerWord);
  for (let i = 0; i < nWords; i++) {
      res.push((remaining % base).toString());
      remaining /= base;
  }
  if (remaining !== 0n) {
      throw new Error(`can't represent ${x} as ${nWords} ${bitsPerWord}-bit words`);
  }
  return res;
}

async function generateWitness(inputs: any) {
  const buffer = fs.readFileSync(wasm);
  const witnessCalculator = await wc(buffer);
  const buff = await witnessCalculator.calculateWTNSBin(inputs, 0);
  fs.writeFileSync(wtnsFile, buff);
}

async function run() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const privKeyStr = await new Promise<string>((res) => {
    rl.question("Enter an ETH private key:\n", (ans: string) => {
      res(ans);
    })
  })

  // take the 1st input.
  const wallet = new Wallet(privKeyStr);
  console.log(`Your address is: ${wallet.address}`);

  let msghash_bigint = 111n;
  let msghash: Uint8Array = bigint_to_Uint8Array(msghash_bigint);

  let privkey = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
  let pubkey: Point = Point.fromPrivateKey(privkey);
  let pub0  = pubkey.x;
  let pub1 =  pubkey.y;

  let sig: Uint8Array = await sign(msghash, bigint_to_Uint8Array(privkey), {canonical: true, der: false})

  let r: Uint8Array = sig.slice(0, 32);
  let r_bigint: bigint = Uint8Array_to_bigint(r);
  let s: Uint8Array = sig.slice(32, 64);
  let s_bigint:bigint = Uint8Array_to_bigint(s);

  let priv_array: bigint[] = bigint_to_array(64, 4, privkey);
  let r_array: bigint[] = bigint_to_array(64, 4, r_bigint);
  let s_array: bigint[] = bigint_to_array(64, 4, s_bigint);
  let msghash_array: bigint[] = bigint_to_array(64, 4, msghash_bigint);
  let pub0_array: bigint[] = bigint_to_array(64, 4, pub0);
  let pub1_array: bigint[] = bigint_to_array(64, 4, pub1);


  console.log('r', r_bigint);
  console.log('s', s_bigint);

//   let witness = await circuit.calculateWitness({"r": r_array,
//                                                 "s": s_array,
//                                                 "msghash": msghash_array,
//                                                 "pubkey": [pub0_array, pub1_array]});
//   expect(witness[1]).to.equal(res);
//   await circuit.checkConstraints(witness);
// });


  const input = {
      r: r_array,
      s: s_array,
      msghash: msghash_array,
      pubkey: [pub0_array, pub1_array],
  };
  console.log(input);

  // for some reason fullprove is broken currently: https://github.com/iden3/snarkjs/issues/107
  console.log('generating witness...');
  const wtnsStart = Date.now();
  await generateWitness(input);
  console.log(`generated witness. took ${Date.now() - wtnsStart}ms`);

  const pfStart = Date.now();
  console.log('generating proof...');
  const { proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtnsFile);
  console.log(proof);
  console.log(publicSignals);
  console.log(`generated proof. took ${Date.now() - pfStart}ms`);

  const verifyStart = Date.now();
  console.log('verifying proof...');

  const vkeyJson = JSON.parse(fs.readFileSync(vkey));
  const res = await snarkjs.groth16.verify(vkeyJson, publicSignals, proof);
  console.log('res of verifying proof...', res);
  if (res === true) {
      console.log("Verification OK");
      console.log(`verified that one of these addresses signed ${publicSignals[4]}:`);
      console.log(BigNumber.from(publicSignals[1]).toHexString());
      console.log(BigNumber.from(publicSignals[2]).toHexString());
      console.log(BigNumber.from(publicSignals[3]).toHexString());
  } else {
      console.log("Invalid proof");
  }
  console.log(`verification took ${Date.now() - verifyStart}ms`);
  
  process.exit(0);
}

run();


    
pragma circom 2.0.2;

// include "../../circuits/ecdsa.circom";
include "../../circuits/user_balance.circom";

// component main {public [r, s, msghash, pubkey]} = ECDSAVerifyNoPubkeyCheck(64, 4);
//component main  = ECDSAVerifyNoPubkeyCheck(64, 4);
// component main  { public [ r, s, msghash ] }= ECDSAVerifyNoPubkeyCheck(64, 4);

component main { public [ r, s, msghash ]} = UserBalance(64, 4, 64);
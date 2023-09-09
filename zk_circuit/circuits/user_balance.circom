pragma circom 2.0.2;

include "./ecdsa.circom";
include "./LessEqalThan.circom";

// keys are encoded as (x, y) pairs with each coordinate being
// encoded with k registers of n bits each
template UserBalance(n, k, m) {
    signal input r[k];
    signal input s[k];
    signal input msghash[k];
    signal input pubkey[2][k];

    signal input user_banlance;
    signal output statis;


    component ecdsaverify = ECDSAVerifyNoPubkeyCheck(n, k);
    ecdsaverify.r <== r;
    ecdsaverify.s <== s;
    ecdsaverify.msghash <== msghash;
    ecdsaverify.pubkey <== pubkey;


    component leEqThan = LessEqalThan(m);
    leEqThan.user_banlance <== user_banlance;

    statis <== leEqThan.c;
}

// component main { public [ r, s, msghash ]} = UserBalance(64, 4, 64);
pragma circom 2.1.4;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";


// user proves that he owns 10**17 <= user_balance.
template LessEqalThan (n) {
    signal input user_banlance;
    var threshold = 100000000000000000;
    signal output c;
    
    component LeEqthan = LessEqThan(n);

    LeEqthan.in[0] <== threshold;
    LeEqthan.in[1] <== user_banlance;

    c <== LeEqthan.out;

    log("10**17 <= user_banlance ? 1 : 0", c);
}
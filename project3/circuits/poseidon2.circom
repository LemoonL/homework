pragma circom 2.0.0;

include "poseidon.circom";


template Poseidon2Hash() {
    signal input a;
    signal input b;
    signal output out;

    signal inputs[2];
    inputs[0] <== a;
    inputs[1] <== b;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== inputs[0];
    poseidon.inputs[1] <== inputs[1];
    out <== poseidon.out;
}

component main = Poseidon2Hash();

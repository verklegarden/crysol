/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

// Scalars
error CRYSOL_ScalarNotAFelt();
error CRYSOL_ScalarInvalid();
error CRYSOL_ScalarMalleable();

// Math
error CRYSOL_DivByZero();
error CRYSOL_InvOfZero();

// (De)Encoding
error CRYSOL_LengthInvalid();
error CRYSOL_PrefixInvalid();

// Point
error CRYSOL_PointInvalid();
error CRYSOL_PointNotOnCurve();

// SecretKey
error CRYSOL_SecretKeyInvalid();

// PublicKey
error CRYSOL_PublicKeyInvalid();

// ECDSA
error CRYSOL_SignerZeroAddress();
error CRYSOL_SignatureMalleable();

// Schnorr
error CRYSOL_SignatureInsane();

/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

// -- arithmetic/Fp --
error CRYSOL_ScalarNotAFelt();
error CRYSOL_DivByZero();
error CRYSOL_InvOfZero();

// -- arithmetic/Points --
error CRYSOL_PointInvalid();
error CRYSOL_ScalarMalleable();
error CRYSOL_LengthInvalid();
error CRYSOL_PrefixInvalid();
error CRYSOL_PointNotOnCurve();

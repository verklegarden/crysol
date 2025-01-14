/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

/// @dev Prime field error thrown when scalar is invalid for attempted
///      operation.
error CRYSOL_ScalarInvalid();

/// @dev Prime field error thrown if division by zero is attempted.
error CRYSOL_DivByZero();

/// @dev Prime field error thrown if computing the inversion of zero is attempted.
error CRYSOL_InvOfZero();

/// @dev De/Serialization error thrown if input's length invalid.
error CRYSOL_LengthInvalid();

/// @dev De/Serialization error thrown if input's prefix invalid.
error CRYSOL_PrefixInvalid();

/// @dev Point error thrown if point invalid.
error CRYSOL_PointInvalid();

/// @dev Cryptographic error thrown if secret key invalid.
error CRYSOL_SecretKeyInvalid();

/// @dev Cryptographic error thrown if public key invalid.
error CRYSOL_PublicKeyInvalid();

/// @dev ECDSA signature error thrown if signer is zero address.
error CRYSOL_SignerZeroAddress();

/// @dev ECDSA signature error thrown if signature is malleable.
error CRYSOL_SignatureMalleable();

/// @dev Schnorr signature error thrown if Schnorr signature insane.
error CRYSOL_SignatureInsane();

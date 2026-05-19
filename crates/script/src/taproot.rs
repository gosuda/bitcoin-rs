use secp256k1::{Message, XOnlyPublicKey, schnorr::Signature};

/// Verifies a taproot key-path Schnorr signature.
#[must_use]
pub fn verify_taproot_keypath(
    signature: &Signature,
    message: &Message,
    public_key: &XOnlyPublicKey,
) -> bool {
    secp256k1::SECP256K1
        .verify_schnorr(signature, message.as_ref(), public_key)
        .is_ok()
}

/// Verifies a tapscript Schnorr signature.
///
/// BIP342 changes the message construction and script rules, but the final
/// Schnorr verification primitive is identical to key-path verification.
#[must_use]
pub fn verify_taproot_scriptpath(
    signature: &Signature,
    message: &Message,
    public_key: &XOnlyPublicKey,
) -> bool {
    verify_taproot_keypath(signature, message, public_key)
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::{verify_taproot_keypath, verify_taproot_scriptpath};

    #[test]
    fn taproot_helpers_accept_valid_schnorr_signature() {
        let secp = Secp256k1::new();
        let secret = match SecretKey::from_byte_array([1; 32]) {
            Ok(secret) => secret,
            Err(error) => panic!("fixed secret key should be valid: {error}"),
        };
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let message = Message::from_digest([2; 32]);
        let signature = secp.sign_schnorr(message.as_ref(), &keypair);

        assert!(verify_taproot_keypath(&signature, &message, &public_key));
        assert!(verify_taproot_scriptpath(&signature, &message, &public_key));
    }
}

use zipher::components::mlkem::{MlKem, MlKemErr, Pk, Sk};
use zipher::pqcrypto_mlkem::mlkem1024_keypair;

fn main() -> Result<(), MlKemErr> {
    // Bob generates a fresh post-quantum keypair (public and secret keys)
    let (pk, sk) = mlkem1024_keypair();

    // Bob creates a MlKem instance with his keypair
    let mut bob = MlKem::new();
    bob.public_key(Pk(pk)).secret_key(Sk(sk));

    // Alice creates a MlKem instance with a default keypair
    let mut alice = MlKem::new();

    // Alice sets her public key to Bob's public key to encapsulate a secret for Bob
    alice.public_key(bob.public_key.clone());

    // Alice encapsulates a shared secret producing ciphertext and shared secret
    let ciphertext = alice.encapsulate()?;

    // Alice's shared secret (hex encoded)
    let alice_shared_secret = alice.shared_secret.clone().expect("missing");

    // Bob decapsulates ciphertext to recover the shared secret using his secret key
    let bob_shared_secret = bob.decapsulate(&ciphertext)?;

    // Both secrets must be identical for successful key exchange
    assert_eq!(alice_shared_secret, bob_shared_secret);

    Ok(())
}

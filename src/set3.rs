extern crate aes;
extern crate oracle;

use crate::set3::oracle::Oracle;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub fn challenge17() -> Result<()> {
    let oracle = oracle::OracleChallenge17::new()?;

    let payload = vec![0];

    let mut cipher = oracle.encrypt(&payload)?;

    cipher = cipher[cipher.len() - 32..].to_vec();

    println!("Valid padding: {}", oracle.check_cipher_padding(&cipher)?);

    Ok(())
}

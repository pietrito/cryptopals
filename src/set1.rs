use std::fs;

extern crate base64;
use std::str;
use std::fs::File;
use std::io::{prelude::*, BufReader};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge1() -> Result<()> {
        assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string().to_owned(), challenge1(&"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string())?);

        Ok(())
    }

    #[test]
    fn test_challenge2() -> Result<()> {
        assert_eq!(
            "746865206b696420646f6e277420706c6179"
                .to_string()
                .to_owned(),
            challenge2(
                &"1c0111001f010100061a024b53535009181c".to_string(),
                &"686974207468652062756c6c277320657965".to_string()
            )?
        );

        Ok(())
    }

    #[test]
    fn test_challenge3() -> Result<()> {
        let decrypted = challenge3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;

        println!("Decrypted: {}", decrypted);
        Ok(())
    }

    #[test]
    fn test_challenge5() -> Result<()> {
        assert_eq!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", challenge5(&"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".as_bytes().to_vec(), &"ICE".as_bytes().to_vec())?);
        Ok(())
    }

    #[test]
    fn test_hamming_distance() -> Result<()> {
        assert_eq!(hamming_distance(
             "this is a test", "wokka wokka!!!")?, 37);

        Ok(())
    }

}

pub fn challenge1(input: &String) -> Result<String> {
    return base64::vec_u8_to_string(hex::string_to_vec_u8(input)?);
}

pub fn challenge2(left: &String, right: &String) -> Result<String> {
    let left_bytes = hex::string_to_vec_u8(left)?;
    let right_bytes = hex::string_to_vec_u8(right)?;

    if right_bytes.len() != right_bytes.len() {
        panic!("Not same length {} - {}", left_bytes.len(), right_bytes.len());
    }

    let out_bytes = do_xor(left_bytes, right_bytes)?;

    hex::vec_u8_to_string(out_bytes)
}

fn do_xor(left: Vec<u8>, right: Vec<u8>) -> Result<Vec<u8>> {
    if right.len() != right.len() {
        panic!("Not same length {} - {}", left.len(), right.len());
    }

    let mut out_bytes: Vec<u8> = Vec::with_capacity(left.len());

    for i in 0..left.len() {
        out_bytes.push(left[i] ^ right[i]);
    }

    Ok(out_bytes)
}

pub fn do_single_xor(input: &Vec<u8>, k: u8) -> Result<Vec<u8>> {
    Ok(input.iter().map(|b| *b ^ k).collect())
}

pub fn challenge3(input: &str) -> Result<String> {
    // let dict = build_dict("data/pride_and_prejudice.txt")?;
    let dict = build_dict("data/alice_wonderlands.txt")?;
    let (key, _) = crack_single_xor(&hex::string_to_vec_u8(input)?, &dict)?;

    /*
        let bonus = "ETAOIN SHRDLU".as_bytes().to_vec();
        let bonus_clear = do_single_xor(&bonus, key)?;
        println!("Bonus of Set1 challenge3: {}", str::from_utf8(&bonus_clear)?);
    */

    Ok(String::from_utf8(do_single_xor(&hex::string_to_vec_u8(input)?, key)?)?)
}

fn crack_single_xor(input: &Vec<u8>, dict: &[f32; 256]) -> Result<(u8, f32)> {
    let mut max_score: f32 = 0.0f32;
    let mut key = 0u8;

    for k in 0..=255 {
        let xored = do_single_xor(input, k)?;
        let score = xored.iter().map(|b| dict[*b as usize]).sum();

        if score > max_score {
            max_score = score;
            key = k;
        }
    }

    Ok((key, max_score))
}

fn build_dict(path: &str) -> Result<[f32; 256]> {
    let file = fs::read_to_string(path)?;
    let mut out_dict = [0.0f32; 256];

    for c in file.bytes() {
        out_dict[c as usize] += 1.0f32;
    }

    for e in &mut out_dict {
        *e /= file.len() as f32;
    }

    Ok(out_dict)
}

pub fn challenge4(path: &str) -> Result<(usize, String, u8)> {
    let mut max_score = 0.0f32;
    let mut max_key = 0u8;
    let mut xored_line_number = 0;
    let mut xored_line = String::new();

    let file = File::open(path)?;
    let dict = build_dict("./data/alice_wonderlands.txt")?;
    let reader = BufReader::new(file);

    for (line_number, line) in reader.lines().enumerate() {
        let as_bytes = hex::string_to_vec_u8(&line.as_ref().unwrap())?;
        let (key, score) = crack_single_xor(&as_bytes, &dict)?;
        if  score > max_score {
            max_score = score;
            xored_line = line.unwrap();
            max_key = key;
            xored_line_number = line_number;
        }
    }
    
    Ok((xored_line_number, xored_line, max_key))
}

pub fn challenge5(input: &Vec<u8>, key: &Vec<u8>) -> Result<String> {
    Ok(hex::vec_u8_to_string(do_vigenere(input, key)?)?)
}

fn do_vigenere(input: &Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());

    for (i, b) in input.bytes().enumerate() {
        out.push(input[i] ^ key[i%key.len()]);
    }

    Ok(out)
}

fn crack_vigenere(path: &str) -> Result<String> {


    Ok(String::new())
}

fn guess_key_size(input: Vec<u8>) -> Result<u32> {
    for key_size in 2..40u32 {
        let left = input[0..key_size];
    }
}

fn hamming_distance(left: &str, right: &str) -> Result<u32> {
    if left.len() != right.len() {
        panic!("Not same length: {} - {}", left.len(), right.len())
    }

    Ok((0..left.len()).map(|i| (left.as_bytes()[i] ^ right.as_bytes()[i]).count_ones()).sum())
}
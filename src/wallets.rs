use core::{str, str::FromStr};

use anyhow::{anyhow, Result};
use heapless::String;

use crate::alg::crypto::{Hash, K256Signature, HMAC, K256};
use crate::path::{ChildNumber, DerivationPath};
use crate::utils::ByteVec;

#[derive(Clone, PartialEq, Hash, Eq, Debug)]
pub struct ExtendedPrivKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: ChildNumber,
    pub secret_key: [u8; 32],
    pub chain_code: [u8; 32],
}

impl ExtendedPrivKey {
    pub fn derive(seed: &[u8], n: DerivationPath) -> Result<ExtendedPrivKey> {
        let result = HMAC::hmac_sha512(b"Bitcoin seed", seed)?;

        let (secret_key, chain_code) = result.split_at(32);

        let mut sk = ExtendedPrivKey {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: ChildNumber::non_hardened_from_u32(0)?,
            secret_key: secret_key.try_into()?,
            chain_code: chain_code.try_into()?,
        };

        for child in n.iter() {
            sk = sk.child(*child)?;
        }

        Ok(sk)
    }

    pub fn child(&self, child: ChildNumber) -> Result<ExtendedPrivKey> {
        let mut bytes = ByteVec::<128>::new();

        if child.is_normal() {
            let encoded_point = K256::export_pk_compressed(&self.secret_key)?;
            bytes.extend(&encoded_point)?;
        } else {
            bytes.push(0)?;
            bytes.extend(&self.secret_key)?;
        };

        bytes.extend(&child.to_bytes())?;

        let result = HMAC::hmac_sha512(&self.chain_code, &bytes.into_vec())?;

        let (tweak, chain_code) = result.split_at(32);

        let child_key = K256::add(&self.secret_key, tweak)?;

        Ok(ExtendedPrivKey {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint()?,
            child_number: child,
            secret_key: child_key.try_into()?,
            chain_code: chain_code.try_into()?,
        })
    }

    pub fn export_pk(&self) -> Result<[u8; 65]> {
        Ok(K256::export_pk(&self.secret_key)?)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<K256Signature> {
        Ok(K256::sign(&self.secret_key, msg)?)
    }

    pub fn fingerprint(&self) -> Result<[u8; 4]> {
        let pub_key = K256::export_pk_compressed(&self.secret_key)?;

        let hash = Hash::hash160(&pub_key)?;

        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash[..4]);

        Ok(fingerprint)
    }

    pub fn encode(&self, is_public: bool) -> Result<String<256>> {
        let mut data = ByteVec::<128>::new();

        if is_public {
            data.extend(&[0x04, 0x88, 0xB2, 0x1E])?;
        } else {
            data.extend(&[0x04, 0x88, 0xAD, 0xE4])?;
        }

        data.push(self.depth)?;
        data.extend(&self.parent_fingerprint)?;
        data.extend(&self.child_number.to_bytes())?;
        data.extend(&self.chain_code)?;

        if is_public {
            let pub_key = K256::export_pk_compressed(&self.secret_key)?;
            data.extend(&pub_key)?;
        } else {
            data.push(0)?;
            data.extend(&self.secret_key)?;
        }

        let mut checksum = [0u8; 4];
        {
            let hash1 = Hash::sha256(&data.clone().into_vec())?;
            let hash2 = Hash::sha256(&hash1)?;
            checksum.copy_from_slice(&hash2[0..4]);
        }

        data.extend(&checksum)?;

        let mut base58 = [0u8; 256];

        let len = bs58::encode(&data.clone().into_vec())
            .onto(&mut base58[..])
            .map_err(|e| anyhow!(e))?;

        Ok(String::from_str(str::from_utf8(&base58[..len])?).map_err(|_| anyhow!(""))?)
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::{vec, vec::Vec};

    pub fn get_test_vector_1() -> Vec<[&'static str; 4]> {
        let test_vectors = vec![
            [
                "000102030405060708090a0b0c0d0e0f",
                "m",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            ],
            [
                "000102030405060708090a0b0c0d0e0f",
                "m/0'",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
            ],
            [
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
            ],
            [
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1/2'",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
            ],
            [
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1/2'/2",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
            ],
            [
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1/2'/2/1000000000",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            ],
        ];
        test_vectors
    }

    pub fn get_test_vector_2() -> Vec<[&'static str; 4]> {
        let test_vectors = vec![
            [
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
            ],
            [
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
            ],
            [
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0/2147483647'",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
            ],
            [
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0/2147483647'/1",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
            ],
            [
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0/2147483647'/1/2147483646'",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
            ],
            [
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0/2147483647'/1/2147483646'/2",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
            ]
        ];
        test_vectors
    }

    pub fn get_test_vector_3() -> Vec<[&'static str; 4]> {
        let test_vectors = vec![
            [
                "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
                "m",
                "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
            ],
            [
                "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
                "m/0'",
                "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
            ]
        ];
        test_vectors
    }

    pub fn get_test_vector_4() -> Vec<[&'static str; 4]> {
        let test_vectors = vec![
            [
                "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
                "m",
                "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
                "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa"
            ],
            [
                "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
                "m/0'",
                "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"
            ],
            [
                "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
                "m/0'/1'",
                "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
            ]
        ];
        test_vectors
    }
    fn run_bip32_test_vector(test_vectors: Vec<[&'static str; 4]>) -> Result<()> {
        for case in &test_vectors {
            let seed = hex::decode(&case[0]).unwrap();
            let path = case[1].parse()?;
            let child = ExtendedPrivKey::derive(&seed, path)?;
            assert_eq!(child.encode(false)?, case[2]);
            assert_eq!(child.encode(true)?, case[3]);
        }
        Ok(())
    }

    #[test]
    fn test_bip32_vector1() -> Result<()> {
        run_bip32_test_vector(get_test_vector_1())
    }

    #[test]
    fn test_bip32_vector2() -> Result<()> {
        run_bip32_test_vector(get_test_vector_2())
    }

    #[test]
    fn test_bip32_vector3() -> Result<()> {
        run_bip32_test_vector(get_test_vector_3())
    }

    #[test]
    fn test_bip32_vector4() -> Result<()> {
        run_bip32_test_vector(get_test_vector_4())
    }
}

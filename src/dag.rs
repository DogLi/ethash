use crate::make_cache;
use crate::{CLASSIC_EPOCH_LENGTH, EPOCH_LENGTH};
use alloc::vec::Vec;
use ethereum_types::{H256, H64, U256};

pub struct LightDAG {
    pub epoch: usize,
    pub cache: Vec<u8>,
    #[allow(dead_code)]
    pub cache_size: usize,
    pub full_size: usize,
    pub is_classic: bool,
}

fn get_epoch_len(block_number: U256, is_classic: bool) -> usize {
    if is_classic {
        CLASSIC_EPOCH_LENGTH
    } else {
        EPOCH_LENGTH
    }
}

fn get_epoch(block_number: U256, is_classic: bool) -> usize {
    let epoch_len = get_epoch_len(block_number, is_classic);
    (block_number / epoch_len).as_usize()
}

impl LightDAG {
    pub fn new(number: U256, is_classic: bool) -> Self {
        let epoch_len = get_epoch_len(number, is_classic);
        let epoch = get_epoch(number, is_classic);
        println!("block: {:?}, epoch: {:?}", number, epoch);
        let cache_size = crate::get_cache_size(epoch);
        let full_size = crate::get_full_size(epoch);
        let seed = crate::get_seedhash(epoch * epoch_len + 1);

        println!(
            "cache_size: {:?}, full size: {:?}, seed: {:?}",
            cache_size,
            full_size,
            seed.as_ref()
        );

        let mut cache: Vec<u8> = alloc::vec![0; cache_size];
        make_cache(&mut cache, seed);

        Self {
            cache,
            cache_size,
            full_size,
            epoch,
            is_classic,
        }
    }

    pub fn compute_light(&self, hash: H256, nonce: H64) -> (H256, H256) {
        crate::hashimoto_light(hash, nonce, self.full_size, &self.cache)
    }

    pub fn is_valid_for(&self, number: U256) -> bool {
        get_epoch(number, self.is_classic) == self.epoch
    }

    pub fn from_cache(cache: Vec<u8>, number: U256, is_classic: bool) -> Self {
        let epoch = get_epoch(number, is_classic);
        let cache_size = crate::get_cache_size(epoch);
        let full_size = crate::get_full_size(epoch);

        Self {
            cache,
            cache_size,
            full_size,
            epoch,
            is_classic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth_verify() {
        // bare_hash of block#8996777 on ethereum mainnet
        let light_dag = LightDAG::new(0x8947a9.into(), false);
        let partial_header_hash =
            "3c2e6623b1de8862a927eeeef2b6b25dea6e1d9dad88dca3c239be3959dc384a"
                .parse()
                .unwrap();
        let nonce: H64 = "a5d3d0ccc8bb8a29".parse().unwrap();
        let mix_hash_expect: H256 =
            "543bc0769f7d5df30e7633f4a01552c2cee7baace8a6da37fddaa19e49e81209"
                .parse()
                .unwrap();
        let mix_hash = light_dag.compute_light(partial_header_hash, nonce).0;
        assert_eq!(mix_hash, mix_hash_expect);
    }

    #[test]
    fn test_etc_verify() {
        let now = std::time::Instant::now();
        let light_dag = LightDAG::new(15212191.into(), true);
        println!("generate dag: {:?}", now.elapsed());
        let partial_header_hash: H256 =
            "516a3f12a1295f5dc38204824bac290e494fbb7a9c6ec6885804ecbe6637fcd2"
                .parse()
                .unwrap();
        let nonce: H64 = "438b7842b6c56f63".parse().unwrap();
        let mix_hash_expect: H256 =
            "50d8aac797b9437cdeedc4776634e57a889e1ed28a3b05f9f3e69ac194350e16"
                .parse()
                .unwrap();
        let mix_hash = light_dag.compute_light(partial_header_hash, nonce).0;
        println!("=================================   {:?}", now.elapsed());
        assert_eq!(mix_hash, mix_hash_expect);
    }
}

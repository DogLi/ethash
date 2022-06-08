use anyhow::{bail, Result};
use ethereum_types::{BigEndianHash, H256, H64, U512};
use memmap::{Mmap, MmapMut};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use walkdir::{DirEntry, WalkDir};

use ethereum_types::U256;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::{fs, io};

use crate::constant::{ALGO_VERSION, CLASSIC_EPOCH_LENGTH, EPOCH_LENGTH, ETCHASH_FORK_BLOCK};
use crate::make_cache;

fn get_epoch_len(block_number: u64, is_classic: bool) -> usize {
    if is_classic {
        if block_number < ETCHASH_FORK_BLOCK {
            EPOCH_LENGTH
        } else {
            CLASSIC_EPOCH_LENGTH
        }
    } else {
        EPOCH_LENGTH
    }
}

fn get_epoch(block_number: u64, is_classic: bool) -> usize {
    let epoch_len = get_epoch_len(block_number, is_classic);
    block_number as usize / epoch_len
}

static GENERATOR_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[derive(Clone)]
pub struct NodeCache {
    epoch: usize,
    cache: Arc<Mmap>,
    full_size: usize,
}

impl NodeCache {
    fn get_mmap_file(cache_dir: &Path, epoch: usize, seed: H256) -> PathBuf {
        let file_name = format!("cache-R{}-{}-{:?}", ALGO_VERSION, epoch, seed);
        cache_dir.join(file_name)
    }

    pub fn generate(epoch: usize, epoch_len: usize, cache_dir: &Path) -> Result<Self> {
        let _lock = GENERATOR_LOCK.lock();
        if let Ok(cache) = Self::new_from_file(epoch, epoch_len, cache_dir) {
            return Ok(cache);
        }
        Self::new(epoch, epoch_len, cache_dir)
    }

    fn new_from_file(epoch: usize, epoch_len: usize, cache_dir: &Path) -> Result<Self> {
        let cache_size = crate::get_cache_size(epoch);
        let seed = crate::get_seedhash(epoch * epoch_len + 1);
        let file = Self::get_mmap_file(cache_dir, epoch, seed);
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(&file)?;
        let mmap = unsafe { Mmap::map(&file)? };
        if mmap.len() != cache_size + 1 {
            bail!("invalid cache file");
        }
        let finished_flag = mmap[cache_size];
        if finished_flag != 1 {
            bail!("invalid cache file, not finished");
        }
        let full_size = crate::get_full_size(epoch);
        Ok(Self {
            epoch,
            cache: Arc::new(mmap),
            full_size,
        })
    }

    fn new(epoch: usize, epoch_len: usize, cache_dir: &Path) -> Result<Self> {
        let cache_size = crate::get_cache_size(epoch);
        let full_size = crate::get_full_size(epoch);
        let seed = crate::get_seedhash(epoch * epoch_len + 1);
        let file = Self::get_mmap_file(cache_dir, epoch, seed);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&file)?;
        file.set_len(cache_size as u64 + 1)?;
        let mut mmap = unsafe { MmapMut::map_mut(&file)? };
        make_cache(&mut mmap, seed);
        if let Err(e) = Self::flush(cache_dir, epoch, &mut mmap) {
            error!("flush DAG error: {:?}", e);
        }
        Ok(Self {
            epoch,
            cache: Arc::new(mmap.make_read_only()?),
            full_size,
        })
    }

    fn flush(cache_dir: &Path, epoch: usize, mmap: &mut MmapMut) -> Result<()> {
        fn is_old_cache_file(entry: &DirEntry, small_epoch: usize) -> bool {
            let file_name = entry.file_name().to_str();
            if file_name.is_none() {
                return false;
            }
            let file_name = file_name.unwrap();
            file_name.starts_with("cache-")
                && file_name < format!("cache-R{}-{}", ALGO_VERSION, small_epoch).as_str()
        }
        mmap.flush()?;
        let old_epoch = epoch.checked_sub(3);
        if old_epoch.is_none() {
            return Ok(());
        }
        let old_epoch = old_epoch.unwrap();
        for old_cache_file in WalkDir::new(cache_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|p| is_old_cache_file(p, old_epoch))
            .map(|p| p.path().to_path_buf())
        {
            fs::remove_file(old_cache_file).unwrap_or_else(|error| match error.kind() {
                io::ErrorKind::NotFound => (),
                _ => warn!("Error removing stale DAG cache: {:?}", error),
            })
        }
        Ok(())
    }

    pub fn compute_light(&self, hash: H256, nonce: H64) -> (H256, H256) {
        let cache_len = self.cache.len();
        let dag = &self.cache[0..cache_len - 1];
        crate::hashimoto_light(hash, nonce, self.full_size, dag)
    }
}

/// Computation result
pub struct ProofOfWork {
    /// Difficulty boundary
    pub value: H256,
    /// Mix
    pub mix_hash: H256,
}

impl ProofOfWork {
    pub fn difficulty(&self) -> U256 {
        boundary_to_difficulty(&self.value)
    }
}

/// Convert an Ethash boundary to its original difficulty. Basically just `f(x) = 2^256 / x`.
pub fn boundary_to_difficulty(boundary: &ethereum_types::H256) -> U256 {
    difficulty_to_boundary_aux(&boundary.into_uint())
}

/// Convert an Ethash difficulty to the target boundary. Basically just `f(x) = 2^256 / x`.
pub fn difficulty_to_boundary(difficulty: &U256) -> ethereum_types::H256 {
    BigEndianHash::from_uint(&difficulty_to_boundary_aux(difficulty))
}

fn difficulty_to_boundary_aux<T: Into<U512>>(difficulty: T) -> ethereum_types::U256 {
    let difficulty = difficulty.into();

    assert!(!difficulty.is_zero());

    if difficulty == U512::one() {
        U256::max_value()
    } else {
        const PROOF: &str = "difficulty > 1, so result never overflows 256 bits; qed";
        U256::try_from((U512::one() << 256) / difficulty).expect(PROOF)
    }
}

static CURRENT_CACHE: Lazy<RwLock<Option<NodeCache>>> = Lazy::new(|| RwLock::new(None));
static NEXT_CACHE: Lazy<RwLock<Option<NodeCache>>> = Lazy::new(|| RwLock::new(None));

pub struct HashManager {
    pub cache_dir: PathBuf,
    pub is_classic: bool,
}

impl HashManager {
    pub fn new(cache_dir: PathBuf, is_classic: bool) -> Self {
        Self {
            cache_dir,
            is_classic,
        }
    }

    pub fn compute_light(
        &self,
        block_number: u64,
        header_hash: H256,
        nonce: H64,
    ) -> Result<ProofOfWork> {
        let cache = self.get_cache(block_number)?;
        let (mix_hash, value) = cache.compute_light(header_hash, nonce);
        Ok(ProofOfWork { mix_hash, value })
    }

    fn get_cache(&self, number: u64) -> Result<NodeCache> {
        let epoch_len = get_epoch_len(number, self.is_classic);
        let epoch = get_epoch(number, self.is_classic);

        // get the cache
        {
            let cache = CURRENT_CACHE.read();
            if let Some(cache) = cache.as_ref() {
                if cache.epoch == epoch {
                    return Ok(cache.clone());
                }
            }
        }

        // use the next epoch as current epoch
        let mut cache = CURRENT_CACHE.write();
        {
            // check if current cache is ok
            if let Some(cache) = cache.as_ref() {
                if cache.epoch == epoch {
                    return Ok(cache.clone());
                }
            }
            // use next cache
            let mut next_cache = NEXT_CACHE.write();
            *cache = next_cache.clone();
            *next_cache = None;
        }

        // check if current cache is ok
        let cache = match cache.as_mut() {
            None => {
                let new_cache = NodeCache::generate(epoch, epoch_len, self.cache_dir.as_path())?;
                *cache = Some(new_cache.clone());
                new_cache
            }
            Some(cache) => {
                if cache.epoch != epoch {
                    // generate current cache
                    let new_cache =
                        NodeCache::generate(epoch, epoch_len, self.cache_dir.as_path())?;
                    *cache = new_cache.clone();
                    new_cache
                } else {
                    cache.clone()
                }
            }
        };
        Self::generate_next_cache(epoch + 1, epoch_len, self.cache_dir.clone());
        Ok(cache)
    }

    fn generate_next_cache(next_epoch: usize, epoch_len: usize, cache_dir: PathBuf) {
        thread::spawn(move || {
            let mut next_cache = NEXT_CACHE.write();
            if let Ok(new_cache) = NodeCache::generate(next_epoch, epoch_len, cache_dir.as_path()) {
                *next_cache = Some(new_cache);
            }
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_eth_verify() {
        let now = std::time::Instant::now();
        let hash_manager = HashManager {
            cache_dir: PathBuf::from("/tmp"),
            is_classic: false,
        };
        //  { height: 14925590, diff: 8000000000, pow_hash: "0xe123ef54e16679347bf772bcaa76ad8b8ca67cf1d331644eee41dad227baf018", nonce: "0x019f836d60808af8", mix_digest: "0x8bea7ee173775346e724a9b080c5913ac4a7b8edd5dd04c85f22ed90172c3170", miner_wallet: "jazzdog", miner_id: "21164", miner_ip: 47.57.186.163, server_node: "x-pool-node-0", kind: ShareKind { block: false, inferior: true, invalid: Some(Stale)
        let diff: u64 = 8000000000;
        let block_number = 14925590;
        let partial_header_hash =
            "e123ef54e16679347bf772bcaa76ad8b8ca67cf1d331644eee41dad227baf018"
                .parse()
                .unwrap();
        let nonce: H64 = "019f836d60808af8".parse().unwrap();
        let mix_hash_expect: H256 =
            "8bea7ee173775346e724a9b080c5913ac4a7b8edd5dd04c85f22ed90172c3170"
                .parse()
                .unwrap();
        let proof = hash_manager
            .compute_light(block_number, partial_header_hash, nonce)
            .unwrap();
        assert_eq!(proof.mix_hash, mix_hash_expect);
        assert!(proof.difficulty() > U256::from(diff));
        println!("=================================   {:?}", now.elapsed());
    }

    #[test]
    fn test_etc_verify() {
        let now = std::time::Instant::now();
        let hash_manager = HashManager {
            cache_dir: PathBuf::from("/tmp"),
            is_classic: true,
        };
        let block_number = 15212191;
        let partial_header_hash: H256 =
            "516a3f12a1295f5dc38204824bac290e494fbb7a9c6ec6885804ecbe6637fcd2"
                .parse()
                .unwrap();
        let nonce: H64 = "438b7842b6c56f63".parse().unwrap();
        let mix_hash_expect: H256 =
            "50d8aac797b9437cdeedc4776634e57a889e1ed28a3b05f9f3e69ac194350e16"
                .parse()
                .unwrap();
        let share_diff: U256 = 2000000000.into();
        let proof = hash_manager
            .compute_light(block_number, partial_header_hash, nonce)
            .unwrap();
        println!("=================================   {:?}", now.elapsed());
        assert_eq!(proof.mix_hash, mix_hash_expect);
        assert!(boundary_to_difficulty(&proof.value) > share_diff)
    }

    #[test]
    fn test_difficulty_to_boundary() {
        use ethereum_types::{BigEndianHash, H256};
        use std::str::FromStr;

        assert_eq!(
            difficulty_to_boundary(&U256::from(1)),
            BigEndianHash::from_uint(&U256::max_value())
        );
        assert_eq!(
            difficulty_to_boundary(&U256::from(2)),
            H256::from_str("8000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        assert_eq!(
            difficulty_to_boundary(&U256::from(4)),
            H256::from_str("4000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        assert_eq!(
            difficulty_to_boundary(&U256::from(32)),
            H256::from_str("0800000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
    }

    #[test]
    fn test_difficulty_to_boundary_regression() {
        use ethereum_types::H256;

        // the last bit was originally being truncated when performing the conversion
        // https://github.com/openethereum/openethereum/issues/8397
        for difficulty in 1..9 {
            assert_eq!(
                U256::from(difficulty),
                boundary_to_difficulty(&difficulty_to_boundary(&difficulty.into()))
            );
            assert_eq!(
                H256::from_low_u64_be(difficulty),
                difficulty_to_boundary(&boundary_to_difficulty(&H256::from_low_u64_be(difficulty)))
            );
            assert_eq!(
                U256::from(difficulty),
                boundary_to_difficulty(&BigEndianHash::from_uint(&boundary_to_difficulty(
                    &H256::from_low_u64_be(difficulty)
                ))),
            );
            assert_eq!(
                H256::from_low_u64_be(difficulty),
                difficulty_to_boundary(&difficulty_to_boundary(&difficulty.into()).into_uint())
            );
        }
    }

    #[test]
    #[should_panic]
    fn test_difficulty_to_boundary_panics_on_zero() {
        difficulty_to_boundary(&U256::from(0));
    }

    #[test]
    #[should_panic]
    fn test_boundary_to_difficulty_panics_on_zero() {
        boundary_to_difficulty(&ethereum_types::H256::zero());
    }
}

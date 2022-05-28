use anyhow::{bail, Result};
use ethereum_types::{H256, H64};
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

    pub fn new_from_file(epoch: usize, epoch_len: usize, cache_dir: &Path) -> Result<Self> {
        let cache_size = crate::get_cache_size(epoch);
        let seed = crate::get_seedhash(epoch * epoch_len + 1);
        let file = Self::get_mmap_file(cache_dir, epoch, seed);
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(&file)?;
        let mmap = unsafe { Mmap::map(&file)? };
        if mmap.len() != cache_size {
            bail!("invalid cache file")
        }
        let full_size = crate::get_full_size(epoch);
        Ok(Self {
            epoch,
            cache: Arc::new(mmap),
            full_size,
        })
    }

    pub fn new(epoch: usize, epoch_len: usize, cache_dir: &Path) -> Result<Self> {
        let cache_size = crate::get_cache_size(epoch);
        let full_size = crate::get_full_size(epoch);
        let seed = crate::get_seedhash(epoch * epoch_len + 1);
        let file = Self::get_mmap_file(cache_dir, epoch, seed);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&file)?;
        file.set_len(cache_size as u64)?;
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
        crate::hashimoto_light(hash, nonce, self.full_size, &self.cache)
    }
}

/// Computation result
pub struct ProofOfWork {
    /// Difficulty boundary
    pub value: U256,
    /// Mix
    pub mix_hash: H256,
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
        let value = U256::from(value.0);
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
            let mut next_cache = NEXT_CACHE.write();
            *cache = next_cache.clone();
            *next_cache = None;
        }

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
        // bare_hash of block#8996777 on ethereum mainnet
        let block_number = 0x8947a9_u64;
        let partial_header_hash =
            "3c2e6623b1de8862a927eeeef2b6b25dea6e1d9dad88dca3c239be3959dc384a"
                .parse()
                .unwrap();
        let nonce: H64 = "a5d3d0ccc8bb8a29".parse().unwrap();
        let mix_hash_expect: H256 =
            "543bc0769f7d5df30e7633f4a01552c2cee7baace8a6da37fddaa19e49e81209"
                .parse()
                .unwrap();
        let proof = hash_manager
            .compute_light(block_number, partial_header_hash, nonce)
            .unwrap();
        assert_eq!(proof.mix_hash, mix_hash_expect);
        println!("finish test eth verify, use time: {:?}", now.elapsed());
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
        assert!(proof.value > share_diff)
    }
}

#[derive(Debug, Clone)]
pub struct HashBloomFilter {
    bits: Vec<bool>,
    bit_count: usize,
    hash_functions: usize,
    items: usize,
}

impl HashBloomFilter {
    pub fn from_keys<I>(keys: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let bit_count = 128;
        let hash_functions = 3;
        let mut filter = Self {
            bits: vec![false; bit_count],
            bit_count,
            hash_functions,
            items: 0,
        };

        for key in keys {
            filter.insert(&key);
        }
        filter
    }

    pub fn insert(&mut self, key: &str) {
        for index in self.indices(key) {
            self.bits[index] = true;
        }
        self.items += 1;
    }

    pub fn might_contain(&self, algorithm: &str, digest: &str) -> bool {
        let key = format!("{}:{}", algorithm.to_lowercase(), digest.to_lowercase());
        self.indices(&key).into_iter().all(|index| self.bits[index])
    }

    pub fn bit_count(&self) -> usize {
        self.bit_count
    }

    pub fn hash_functions(&self) -> usize {
        self.hash_functions
    }

    pub fn items(&self) -> usize {
        self.items
    }

    fn indices(&self, key: &str) -> Vec<usize> {
        (0..self.hash_functions)
            .map(|seed| fnv1a64(key.as_bytes(), seed as u64) as usize % self.bit_count)
            .collect()
    }
}

fn fnv1a64(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = 0xcbf29ce484222325u64 ^ seed.wrapping_mul(0x9e3779b97f4a7c15);
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::HashBloomFilter;

    #[test]
    fn inserted_hash_key_might_contain() {
        let filter = HashBloomFilter::from_keys(["sha256:abc123".to_string()]);
        assert!(filter.might_contain("sha256", "abc123"));
    }
}

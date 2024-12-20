use anyhow::anyhow;

#[derive(Clone)]
pub struct ByteVec<const N: usize> {
    inner: heapless::Vec<u8, N>,
}

impl<const N: usize> ByteVec<N> {
    pub fn new() -> Self {
        Self {
            inner: heapless::Vec::new(),
        }
    }

    pub fn push(&mut self, byte: u8) -> Result<(), anyhow::Error> {
        self.inner.push(byte).map_err(|e| anyhow!(e))
    }

    pub fn extend(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.inner
            .extend_from_slice(data)
            .map_err(|_| anyhow!("Buffer full"))
    }

    pub fn into_vec(self) -> heapless::Vec<u8, N> {
        self.inner
    }
}

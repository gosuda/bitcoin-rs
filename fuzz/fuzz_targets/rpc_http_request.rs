#![no_main]

use std::io::{self, BufReader, Read};

use libfuzzer_sys::fuzz_target;

struct ChunkReader<'a> {
    data: &'a [u8],
    chunk_size: usize,
    pos: usize,
}

impl<'a> ChunkReader<'a> {
    fn new(data: &'a [u8], chunk_size: usize) -> Self {
        Self {
            data,
            chunk_size: chunk_size.max(1),
            pos: 0,
        }
    }
}

impl Read for ChunkReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        let remaining = self.data.len() - self.pos;
        let to_read = remaining.min(self.chunk_size).min(buf.len());
        buf[..to_read].copy_from_slice(&self.data[self.pos..self.pos + to_read]);
        self.pos += to_read;
        Ok(to_read)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut r1 = BufReader::new(ChunkReader::new(data, data.len()));
    let res1 = bitcoin_rs_serving::read_http_request(&mut r1);

    let mid = (data.len() / 2).max(1);
    let mut r2 = BufReader::new(ChunkReader::new(data, mid));
    let res2 = bitcoin_rs_serving::read_http_request(&mut r2);

    let third = (data.len() / 3).max(1);
    let mut r3 = BufReader::new(ChunkReader::new(data, third));
    let res3 = bitcoin_rs_serving::read_http_request(&mut r3);

    match (&res1, &res2) {
        (Ok(req1), Ok(req2)) => {
            assert_eq!(
                req1, req2,
                "parse mismatch between 1-chunk and 2-chunk reads"
            );
        }
        (Err(_), Err(_)) => {}
        (Ok(req), Err(err)) => {
            panic!("1-chunk succeeded with {req:?}, but 2-chunk failed with {err:?}");
        }
        (Err(err), Ok(req)) => {
            panic!("1-chunk failed with {err:?}, but 2-chunk succeeded with {req:?}");
        }
    }

    match (&res1, &res3) {
        (Ok(req1), Ok(req3)) => {
            assert_eq!(
                req1, req3,
                "parse mismatch between 1-chunk and 3-chunk reads"
            );
        }
        (Err(_), Err(_)) => {}
        (Ok(req), Err(err)) => {
            panic!("1-chunk succeeded with {req:?}, but 3-chunk failed with {err:?}");
        }
        (Err(err), Ok(req)) => {
            panic!("1-chunk failed with {err:?}, but 3-chunk succeeded with {req:?}");
        }
    }

    if let Ok(Some(req)) = res1 {
        assert!(
            req.body.len() <= 16 * 1024 * 1024,
            "read body {} exceeds maximum allowed body size",
            req.body.len()
        );
        if req.keep_alive {
            let _ = bitcoin_rs_serving::read_http_request(&mut r1);
        }
    }
});

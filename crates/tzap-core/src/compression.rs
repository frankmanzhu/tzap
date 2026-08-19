use crate::format::{FormatError, READER_MAX_METADATA_OBJECT_SIZE};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

pub fn compress_zstd_frame(plaintext: &[u8], level: i32) -> Result<Vec<u8>, FormatError> {
    compress_zstd_frame_with_jobs(plaintext, level, 1)
}

pub fn compress_zstd_frame_with_jobs(plaintext: &[u8], level: i32, jobs: usize) -> Result<Vec<u8>, FormatError> {
    if jobs <= 1 {
        return zstd::bulk::compress(plaintext, level).map_err(|_| FormatError::ZstdCompressionFailure);
    }
    let jobs = u32::try_from(jobs).map_err(|_| FormatError::WriterUnsupported("jobs exceeds zstd worker limit"))?;
    let mut compressor = zstd::bulk::Compressor::new(level).map_err(|_| FormatError::ZstdCompressionFailure)?;
    compressor.set_parameter(zstd::zstd_safe::CParameter::NbWorkers(jobs)).map_err(|_| FormatError::ZstdCompressionFailure)?;
    compressor.compress(plaintext).map_err(|_| FormatError::ZstdCompressionFailure)
}

pub fn compress_zstd_frame_with_dictionary(plaintext: &[u8], level: i32, dictionary: &[u8]) -> Result<Vec<u8>, FormatError> {
    compress_zstd_frame_with_dictionary_and_jobs(plaintext, level, dictionary, 1)
}

pub fn compress_zstd_frame_with_dictionary_and_jobs(plaintext: &[u8], level: i32, dictionary: &[u8], jobs: usize) -> Result<Vec<u8>, FormatError> {
    let mut compressor = zstd::bulk::Compressor::with_dictionary(level, dictionary).map_err(|_| FormatError::ZstdCompressionFailure)?;
    if jobs > 1 {
        let jobs = u32::try_from(jobs).map_err(|_| FormatError::WriterUnsupported("jobs exceeds zstd worker limit"))?;
        compressor.set_parameter(zstd::zstd_safe::CParameter::NbWorkers(jobs)).map_err(|_| FormatError::ZstdCompressionFailure)?;
    }
    compressor.compress(plaintext).map_err(|_| FormatError::ZstdCompressionFailure)
}

pub fn decompress_exact_zstd_frame(compressed: &[u8], expected_decompressed_size: usize) -> Result<Vec<u8>, FormatError> {
    validate_metadata_decompressed_size(expected_decompressed_size)?;
    validate_exact_zstd_frame(compressed)?;
    let decompressed = zstd::bulk::decompress(compressed, expected_decompressed_size).map_err(|_| FormatError::ZstdDecompressionFailure)?;
    if decompressed.len() != expected_decompressed_size {
        return Err(FormatError::ZstdDecompressedSizeMismatch { expected: expected_decompressed_size, actual: decompressed.len() });
    }
    Ok(decompressed)
}

pub fn decompress_exact_zstd_frame_with_dictionary(compressed: &[u8], expected_decompressed_size: usize, dictionary: &[u8]) -> Result<Vec<u8>, FormatError> {
    validate_metadata_decompressed_size(expected_decompressed_size)?;
    validate_exact_zstd_frame(compressed)?;
    let decompressed = zstd::bulk::Decompressor::with_dictionary(dictionary)
        .and_then(|mut decompressor| decompressor.decompress(compressed, expected_decompressed_size))
        .map_err(|_| FormatError::ZstdDecompressionFailure)?;
    if decompressed.len() != expected_decompressed_size {
        return Err(FormatError::ZstdDecompressedSizeMismatch { expected: expected_decompressed_size, actual: decompressed.len() });
    }
    Ok(decompressed)
}

pub fn validate_exact_zstd_frame(compressed: &[u8]) -> Result<(), FormatError> {
    if compressed.is_empty() {
        return Err(FormatError::EmptyZstdFrame);
    }
    if compressed.len() < 4 || compressed[0..4] != ZSTD_MAGIC {
        return Err(FormatError::NotStandardZstdFrame);
    }
    let frame_size = zstd::zstd_safe::find_frame_compressed_size(compressed).map_err(|_| FormatError::InvalidZstdFrame)?;
    if frame_size != compressed.len() {
        return Err(FormatError::TrailingBytesAfterZstdFrame);
    }
    Ok(())
}

fn validate_metadata_decompressed_size(expected_decompressed_size: usize) -> Result<(), FormatError> {
    if expected_decompressed_size > READER_MAX_METADATA_OBJECT_SIZE as usize {
        Err(FormatError::ReaderResourceLimitExceeded {
            field: "decompressed_size",
            cap: READER_MAX_METADATA_OBJECT_SIZE as u64,
            actual: expected_decompressed_size as u64,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compresses_and_decompresses_exact_frame() {
        let plaintext = b"metadata object payload";
        let compressed = compress_zstd_frame(plaintext, 3).unwrap();
        let decompressed = decompress_exact_zstd_frame(&compressed, plaintext.len()).unwrap();
        assert_eq!(decompressed, plaintext);
    }

    #[test]
    fn rejects_trailing_concatenated_and_skippable_frames() {
        let plaintext = b"payload";
        let mut compressed = compress_zstd_frame(plaintext, 1).unwrap();
        compressed.push(0);
        assert_eq!(decompress_exact_zstd_frame(&compressed, plaintext.len()).unwrap_err(), FormatError::TrailingBytesAfterZstdFrame);

        let one = compress_zstd_frame(plaintext, 1).unwrap();
        let mut concatenated = one.clone();
        concatenated.extend_from_slice(&one);
        assert_eq!(decompress_exact_zstd_frame(&concatenated, plaintext.len()).unwrap_err(), FormatError::TrailingBytesAfterZstdFrame);

        let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        assert_eq!(validate_exact_zstd_frame(&skippable).unwrap_err(), FormatError::NotStandardZstdFrame);
    }

    #[test]
    fn rejects_wrong_decompressed_size() {
        let compressed = compress_zstd_frame(b"payload", 1).unwrap();
        assert_eq!(decompress_exact_zstd_frame(&compressed, 100).unwrap_err(), FormatError::ZstdDecompressedSizeMismatch { expected: 100, actual: 7 });
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn rejects_decompressed_size_over_u32_cap() {
        let compressed = compress_zstd_frame(b"metadata-object", 1).unwrap();
        assert_eq!(
            decompress_exact_zstd_frame(&compressed, (u32::MAX as usize) + 1).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded { field: "decompressed_size", cap: READER_MAX_METADATA_OBJECT_SIZE as u64, actual: (u32::MAX as u64) + 1 }
        );
    }

    #[test]
    fn rejects_decompressed_size_over_metadata_object_cap() {
        let compressed = compress_zstd_frame(b"metadata-object", 1).unwrap();
        let over_cap = READER_MAX_METADATA_OBJECT_SIZE as usize + 1;
        assert_eq!(
            decompress_exact_zstd_frame(&compressed, over_cap).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded { field: "decompressed_size", cap: READER_MAX_METADATA_OBJECT_SIZE as u64, actual: over_cap as u64 }
        );
    }

    #[test]
    fn compresses_and_decompresses_exact_dictionary_frame() {
        let dictionary = b"common prefix common prefix common prefix";
        let plaintext = b"common prefix payload";
        let compressed = compress_zstd_frame_with_dictionary(plaintext, 3, dictionary).unwrap();
        let decompressed = decompress_exact_zstd_frame_with_dictionary(&compressed, plaintext.len(), dictionary).unwrap();
        assert_eq!(decompressed, plaintext);
    }
}

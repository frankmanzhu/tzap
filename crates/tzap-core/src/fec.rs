use crate::format::{FormatError, READER_MAX_REPAIR_TOTAL_SHARDS};

use std::sync::OnceLock;

const GF16_REDUCTION_POLY_LOW: u16 = 0x100b;
const GF16_MAX_TOTAL_SHARDS: usize = 65_535;
const GF16_FIELD_SIZE: usize = 1 << 16;
const GF16_ORDER: usize = GF16_FIELD_SIZE - 1;
const GF16_GENERATOR: u16 = 2;
const GF16_LOG_ZERO: u16 = u16::MAX;

struct Gf16Tables {
    log: Box<[u16; GF16_FIELD_SIZE]>,
    exp: Box<[u16; GF16_ORDER * 2]>,
}

static GF16_TABLES: OnceLock<Gf16Tables> = OnceLock::new();

pub fn encode_parity_gf16(data_shards: &[Vec<u8>], parity_shard_count: usize) -> Result<Vec<Vec<u8>>, FormatError> {
    let data_shard_count = data_shards.len();
    validate_fec_shape(data_shard_count, parity_shard_count, data_shards)?;
    if parity_shard_count == 0 {
        return Ok(Vec::new());
    }

    let shard_size = data_shards[0].len();
    let mut parity = vec![vec![0u8; shard_size]; parity_shard_count];
    let tables = gf16_tables();

    for (j, parity_shard) in parity.iter_mut().enumerate().take(parity_shard_count) {
        for (i, data_shard) in data_shards.iter().enumerate().take(data_shard_count) {
            let coefficient = cauchy_coefficient(data_shard_count, j, i);
            if coefficient == 0 {
                continue;
            }
            if coefficient == 1 {
                accumulate_xor_shard(parity_shard, data_shard);
                continue;
            }
            let log_c = tables.log[coefficient as usize] as usize;
            accumulate_gf16_mul_shard(parity_shard, data_shard, log_c, tables);
        }
    }

    Ok(parity)
}

pub fn repair_data_gf16(data_shards: &[Option<Vec<u8>>], parity_shards: &[Option<Vec<u8>>], shard_size: usize) -> Result<Vec<Vec<u8>>, FormatError> {
    let data_shard_count = data_shards.len();
    let parity_shard_count = parity_shards.len();
    validate_fec_counts(data_shard_count, parity_shard_count)?;
    if shard_size % 2 != 0 {
        return Err(FormatError::FecOddShardSize);
    }

    if data_shards.iter().all(Option::is_some) {
        return data_shards
            .iter()
            .map(|shard| validate_available_shard(shard.as_ref().unwrap(), shard_size))
            .collect();
    }

    // Bound the O(n³) Gauss-Jordan inversion before building the matrix: this path runs
    // on erasure recovery (plaintext archives are fully forgeable, so shard counts are
    // attacker-controlled). The parse caps are larger by spec, but repair work gets a
    // tighter local bound with a clean resource-limit diagnostic.
    if data_shard_count > READER_MAX_REPAIR_TOTAL_SHARDS as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "fec repair data shards",
            cap: READER_MAX_REPAIR_TOTAL_SHARDS as u64,
            actual: data_shard_count as u64,
        });
    }

    let mut rows = Vec::with_capacity(data_shard_count);
    let mut available = Vec::with_capacity(data_shard_count);

    for (i, shard) in data_shards.iter().enumerate() {
        if let Some(shard) = shard {
            rows.push(identity_row(data_shard_count, i));
            available.push(validate_available_shard(shard, shard_size)?);
            if rows.len() == data_shard_count {
                break;
            }
        }
    }

    if rows.len() < data_shard_count {
        for (j, shard) in parity_shards.iter().enumerate() {
            if let Some(shard) = shard {
                rows.push(cauchy_row(data_shard_count, j));
                available.push(validate_available_shard(shard, shard_size)?);
                if rows.len() == data_shard_count {
                    break;
                }
            }
        }
    }

    if rows.len() < data_shard_count {
        return Err(FormatError::FecTooFewAvailableShards);
    }

    let inverse = invert_matrix(rows)?;
    let mut repaired = vec![vec![0u8; shard_size]; data_shard_count];
    let tables = gf16_tables();

    for output_row in 0..data_shard_count {
        let dest = &mut repaired[output_row];
        for source_row in 0..data_shard_count {
            let coefficient = inverse[output_row][source_row];
            if coefficient == 0 {
                continue;
            }
            let src = &available[source_row];
            if coefficient == 1 {
                accumulate_xor_shard(dest, src);
            } else {
                let log_c = tables.log[coefficient as usize] as usize;
                accumulate_gf16_mul_shard(dest, src, log_c, tables);
            }
        }
    }

    Ok(repaired)
}

fn concatenate_complete_data_shards(data_shards: &[Option<Vec<u8>>], shard_size: usize) -> Result<Option<Vec<u8>>, FormatError> {
    if data_shards.is_empty() || data_shards.iter().any(Option::is_none) {
        return Ok(None);
    }

    let capacity = data_shards.len().checked_mul(shard_size).ok_or(FormatError::FecInconsistentShardSize)?;
    let mut concatenated = Vec::with_capacity(capacity);
    for shard in data_shards {
        let Some(shard) = shard.as_ref() else {
            return Ok(None);
        };
        if shard.len() != shard_size {
            return Err(FormatError::FecInconsistentShardSize);
        }
        concatenated.extend_from_slice(shard);
    }
    Ok(Some(concatenated))
}

pub(crate) fn recover_data_bytes_gf16(data_shards: &[Option<Vec<u8>>], parity_shards: &[Option<Vec<u8>>], shard_size: usize) -> Result<Vec<u8>, FormatError> {
    if let Some(concatenated) = concatenate_complete_data_shards(data_shards, shard_size)? {
        return Ok(concatenated);
    }

    let repaired = repair_data_gf16(data_shards, parity_shards, shard_size)?;
    let mut recovered = Vec::with_capacity(repaired.len() * shard_size);
    for shard in repaired {
        recovered.extend_from_slice(&shard);
    }
    Ok(recovered)
}

#[inline]
fn accumulate_xor_shard(dest: &mut [u8], src: &[u8]) {
    let mut d_chunks = dest.chunks_exact_mut(8);
    let mut s_chunks = src.chunks_exact(8);
    for (d, s) in (&mut d_chunks).zip(&mut s_chunks) {
        let dv = u64::from_ne_bytes(d.try_into().unwrap());
        let sv = u64::from_ne_bytes(s.try_into().unwrap());
        d.copy_from_slice(&(dv ^ sv).to_ne_bytes());
    }
    let d_rem = d_chunks.into_remainder();
    let s_rem = s_chunks.remainder();
    for (d, s) in d_rem.iter_mut().zip(s_rem.iter()) {
        *d ^= *s;
    }
}

#[inline]
fn accumulate_gf16_mul_shard(dest: &mut [u8], src: &[u8], log_c: usize, tables: &Gf16Tables) {
    let symbol_count = dest.len() / 2;
    for k in 0..symbol_count {
        let offset = 2 * k;
        let symbol = u16::from_le_bytes([src[offset], src[offset + 1]]);
        if symbol != 0 {
            let log_a = tables.log[symbol as usize] as usize;
            let val = tables.exp[log_a + log_c];
            let current = u16::from_le_bytes([dest[offset], dest[offset + 1]]);
            dest[offset..offset + 2].copy_from_slice(&(current ^ val).to_le_bytes());
        }
    }
}

pub fn gf16_add(a: u16, b: u16) -> u16 {
    a ^ b
}

pub fn gf16_mul(a: u16, b: u16) -> u16 {
    if a == 0 || b == 0 {
        return 0;
    }
    let tables = gf16_tables();
    let exponent = tables.log[a as usize] as usize + tables.log[b as usize] as usize;
    tables.exp[exponent]
}

fn gf16_mul_slow(mut a: u16, mut b: u16) -> u16 {
    let mut product = 0u16;
    for _ in 0..16 {
        if b & 1 != 0 {
            product ^= a;
        }
        b >>= 1;
        let carry = a & 0x8000 != 0;
        a <<= 1;
        if carry {
            a ^= GF16_REDUCTION_POLY_LOW;
        }
    }
    product
}

fn gf16_tables() -> &'static Gf16Tables {
    GF16_TABLES.get_or_init(|| {
        let mut log = Box::new([GF16_LOG_ZERO; GF16_FIELD_SIZE]);
        let mut exp = Box::new([0u16; GF16_ORDER * 2]);
        let mut value = 1u16;
        for (power, slot) in exp.iter_mut().take(GF16_ORDER).enumerate() {
            *slot = value;
            log[value as usize] = power as u16;
            value = gf16_mul_slow(value, GF16_GENERATOR);
        }
        debug_assert_eq!(value, 1);
        for power in GF16_ORDER..(GF16_ORDER * 2) {
            exp[power] = exp[power - GF16_ORDER];
        }
        Gf16Tables { log, exp }
    })
}

pub fn gf16_pow(mut base: u16, mut exponent: u32) -> u16 {
    let mut result = 1u16;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf16_mul(result, base);
        }
        exponent >>= 1;
        base = gf16_mul(base, base);
    }
    result
}

pub fn gf16_inverse(value: u16) -> Result<u16, FormatError> {
    if value == 0 {
        return Err(FormatError::FecSingularMatrix);
    }
    Ok(gf16_pow(value, 65_534))
}

fn validate_fec_shape(data_shard_count: usize, parity_shard_count: usize, data_shards: &[Vec<u8>]) -> Result<(), FormatError> {
    validate_fec_counts(data_shard_count, parity_shard_count)?;
    let shard_size = data_shards[0].len();
    if shard_size % 2 != 0 {
        return Err(FormatError::FecOddShardSize);
    }
    if data_shards.iter().any(|shard| shard.len() != shard_size) {
        return Err(FormatError::FecInconsistentShardSize);
    }
    Ok(())
}

fn validate_fec_counts(data_shard_count: usize, parity_shard_count: usize) -> Result<(), FormatError> {
    if data_shard_count == 0 {
        return Err(FormatError::FecZeroDataShards);
    }
    let total = data_shard_count
        .checked_add(parity_shard_count)
        .ok_or(FormatError::FecTooManyShards(usize::MAX))?;
    if total > GF16_MAX_TOTAL_SHARDS {
        return Err(FormatError::FecTooManyShards(total));
    }
    Ok(())
}

fn validate_available_shard(shard: &[u8], shard_size: usize) -> Result<Vec<u8>, FormatError> {
    if shard.len() != shard_size {
        return Err(FormatError::FecInconsistentShardSize);
    }
    Ok(shard.to_owned())
}

fn cauchy_coefficient(data_shard_count: usize, parity_row: usize, data_col: usize) -> u16 {
    let x_i = data_col as u16;
    let y_j = (data_shard_count + parity_row) as u16;
    gf16_inverse(x_i ^ y_j).expect("Cauchy denominator is non-zero under D + P limit")
}

fn cauchy_row(data_shard_count: usize, parity_row: usize) -> Vec<u16> {
    (0..data_shard_count).map(|i| cauchy_coefficient(data_shard_count, parity_row, i)).collect()
}

fn identity_row(width: usize, one_at: usize) -> Vec<u16> {
    let mut row = vec![0u16; width];
    row[one_at] = 1;
    row
}

fn invert_matrix(mut matrix: Vec<Vec<u16>>) -> Result<Vec<Vec<u16>>, FormatError> {
    let n = matrix.len();
    for (i, row) in matrix.iter_mut().enumerate() {
        if row.len() != n {
            return Err(FormatError::FecSingularMatrix);
        }
        row.extend(identity_row(n, i));
    }

    for col in 0..n {
        let pivot = (col..n).find(|row| matrix[*row][col] != 0).ok_or(FormatError::FecSingularMatrix)?;
        if pivot != col {
            matrix.swap(pivot, col);
        }

        let inv_pivot = gf16_inverse(matrix[col][col])?;
        for value in &mut matrix[col] {
            *value = gf16_mul(*value, inv_pivot);
        }

        let pivot_row = matrix[col].clone();
        for (row_idx, row) in matrix.iter_mut().enumerate() {
            if row_idx == col {
                continue;
            }
            let factor = row[col];
            if factor == 0 {
                continue;
            }
            for c in 0..2 * n {
                row[c] ^= gf16_mul(factor, pivot_row[c]);
            }
        }
    }

    Ok(matrix.into_iter().map(|row| row[n..2 * n].to_vec()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf16_arithmetic_matches_polynomial_examples() {
        assert_eq!(gf16_add(0x1234, 0x00ff), 0x12cb);
        assert_eq!(gf16_mul(0x8000, 0x0002), 0x100b);
        assert_eq!(gf16_mul(0x1234, 0x5678), 0x6324);
        let inv = gf16_inverse(0x5678).unwrap();
        assert_eq!(gf16_mul(0x5678, inv), 1);
    }

    #[test]
    fn gf16_table_multiplication_matches_polynomial_multiplication() {
        for a in [0, 1, 2, 3, 0x1234, 0x8000, 0xffff] {
            for b in [0, 1, 2, 5, 0x5678, 0xabcd, 0xffff] {
                assert_eq!(gf16_mul(a, b), gf16_mul_slow(a, b));
            }
        }
    }

    #[test]
    fn encodes_hardcoded_cauchy_parity_vector() {
        let data = vec![vec![0x01, 0x00, 0x02, 0x00], vec![0x03, 0x00, 0x04, 0x00]];
        let parity = encode_parity_gf16(&data, 2).unwrap();
        assert_eq!(parity, vec![vec![0x04, 0x88, 0x04, 0xf0], vec![0x02, 0x78, 0x05, 0xf0]]);
    }

    #[test]
    fn encodes_little_endian_symbols() {
        let data = vec![vec![0x34, 0x12, 0xcd, 0xab], vec![0x78, 0x56, 0x01, 0x00], vec![0xff, 0x00, 0x20, 0x00]];
        let parity = encode_parity_gf16(&data, 1).unwrap();
        assert_eq!(parity, vec![vec![0xd6, 0xd5, 0x9e, 0xee]]);
    }

    #[test]
    fn repairs_missing_data_from_data_and_parity_rows() {
        let data = vec![vec![0x01, 0x00, 0x02, 0x00], vec![0x03, 0x00, 0x04, 0x00], vec![0x05, 0x00, 0x06, 0x00]];
        let parity = encode_parity_gf16(&data, 2).unwrap();
        let repaired = repair_data_gf16(
            &[Some(data[0].clone()), None, Some(data[2].clone())],
            &[Some(parity[0].clone()), Some(parity[1].clone())],
            4,
        )
        .unwrap();
        assert_eq!(repaired, data);
    }

    #[test]
    fn concatenates_complete_data_shards_without_repair() {
        let shards = vec![Some(vec![0x01, 0x00]), Some(vec![0x02, 0x00])];
        assert_eq!(recover_data_bytes_gf16(&shards, &[], 2).unwrap(), vec![0x01, 0x00, 0x02, 0x00]);
        assert_eq!(
            recover_data_bytes_gf16(&[Some(vec![0; 1])], &[], 2).unwrap_err(),
            FormatError::FecInconsistentShardSize
        );
    }

    #[test]
    fn rejects_erasure_repair_above_work_cap_before_inversion() {
        // Regression: the O(n³) inversion is bounded by READER_MAX_REPAIR_TOTAL_SHARDS;
        // a crafted archive with an erased shard among a huge stripe must fail with a
        // clean resource-limit diagnostic instead of burning minutes of CPU.
        let shards = (0..READER_MAX_REPAIR_TOTAL_SHARDS as usize + 1)
            .map(|index| if index == 0 { None } else { Some(vec![0u8; 2]) })
            .collect::<Vec<_>>();
        assert_eq!(
            repair_data_gf16(&shards, &[], 2).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "fec repair data shards",
                cap: READER_MAX_REPAIR_TOTAL_SHARDS as u64,
                actual: (READER_MAX_REPAIR_TOTAL_SHARDS as u64) + 1,
            }
        );

        // At the cap the same shape with no erasures still validates (no inversion).
        let full = (0..READER_MAX_REPAIR_TOTAL_SHARDS as usize).map(|_| Some(vec![0u8; 2])).collect::<Vec<_>>();
        assert!(repair_data_gf16(&full, &[], 2).is_ok());
    }

    #[test]
    fn repairs_when_only_parity_and_one_data_row_remain() {
        let data = vec![vec![0x10, 0x00, 0x20, 0x00], vec![0x30, 0x00, 0x40, 0x00], vec![0x50, 0x00, 0x60, 0x00]];
        let parity = encode_parity_gf16(&data, 3).unwrap();
        let repaired = repair_data_gf16(
            &[None, Some(data[1].clone()), None],
            &[Some(parity[0].clone()), None, Some(parity[2].clone())],
            4,
        )
        .unwrap();
        assert_eq!(repaired, data);
    }

    #[test]
    fn rejects_invalid_shapes_before_repair() {
        assert_eq!(encode_parity_gf16(&[], 1).unwrap_err(), FormatError::FecZeroDataShards);
        assert_eq!(encode_parity_gf16(&[vec![0; 3]], 1).unwrap_err(), FormatError::FecOddShardSize);
        assert_eq!(encode_parity_gf16(&[vec![0; 4]], 65_535).unwrap_err(), FormatError::FecTooManyShards(65_536));
        assert_eq!(
            repair_data_gf16(&[None, None], &[Some(vec![0; 4])], 4).unwrap_err(),
            FormatError::FecTooFewAvailableShards
        );
    }

    #[test]
    fn multi_shard_random_erasure_repair_round_trips() {
        // Test 16 data shards + 4 parity shards, 1024 bytes each
        let data_shard_count = 16;
        let parity_shard_count = 4;
        let shard_size = 1024;
        let mut data = Vec::with_capacity(data_shard_count);
        for i in 0..data_shard_count {
            let shard = (0..shard_size)
                .map(|b| ((i * 37 + b * 13 + 7) & 0xff) as u8)
                .collect::<Vec<u8>>();
            data.push(shard);
        }

        let parity = encode_parity_gf16(&data, parity_shard_count).unwrap();
        assert_eq!(parity.len(), parity_shard_count);

        // Erase 4 data shards: #2, #5, #10, #14
        let mut data_with_erasures: Vec<Option<Vec<u8>>> = data.iter().cloned().map(Some).collect();
        data_with_erasures[2] = None;
        data_with_erasures[5] = None;
        data_with_erasures[10] = None;
        data_with_erasures[14] = None;

        let parity_available: Vec<Option<Vec<u8>>> = parity.iter().cloned().map(Some).collect();

        let repaired = repair_data_gf16(&data_with_erasures, &parity_available, shard_size).unwrap();
        assert_eq!(repaired, data);
    }
}


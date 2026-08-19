use crate::format::FormatError;

pub fn suffix_pad_for_aead(payload: &[u8], tag_len: usize, block_size: usize) -> Result<Vec<u8>, FormatError> {
    let total_before_padding = payload.len().checked_add(tag_len).ok_or(FormatError::PaddingOverflow)?;
    let mut envelope_total = round_up_to_block(total_before_padding, block_size)?;
    let mut pad_len = envelope_total.checked_sub(total_before_padding).ok_or(FormatError::PaddingOverflow)?;
    if pad_len == 0 {
        envelope_total = envelope_total.checked_add(block_size).ok_or(FormatError::PaddingOverflow)?;
        pad_len = block_size;
    }

    let plaintext_len = envelope_total.checked_sub(tag_len).ok_or(FormatError::PaddingOverflow)?;
    let mut plaintext = Vec::with_capacity(plaintext_len);
    plaintext.extend_from_slice(payload);
    append_suffix_padding(&mut plaintext, pad_len)?;
    Ok(plaintext)
}

pub fn append_suffix_padding(plaintext: &mut Vec<u8>, pad_len: usize) -> Result<(), FormatError> {
    if pad_len == 0 {
        return Err(FormatError::InvalidSuffixPadding);
    }
    if pad_len <= 254 {
        plaintext.resize(plaintext.len() + pad_len - 1, 0);
        plaintext.push(pad_len as u8);
        return Ok(());
    }

    if pad_len > u32::MAX as usize {
        return Err(FormatError::PaddingOverflow);
    }
    // Wide form is only reached when `pad_len > 254`, so no minimum check is
    // needed here; the depad side enforces `pad_len >= 255`.
    plaintext.resize(plaintext.len() + pad_len - 5, 0);
    plaintext.extend_from_slice(&(pad_len as u32).to_le_bytes());
    plaintext.push(0xff);
    Ok(())
}

pub fn depad_suffix_padding(plaintext: &[u8]) -> Result<&[u8], FormatError> {
    let n = plaintext.len();
    if n == 0 {
        return Err(FormatError::EmptyPaddedPlaintext);
    }

    let final_byte = plaintext[n - 1];
    let (marker_size, pad_len) = if final_byte < 0xff {
        (1usize, final_byte as usize)
    } else {
        if n < 5 {
            return Err(FormatError::InvalidSuffixPadding);
        }
        let pad_len = u32::from_le_bytes(plaintext[n - 5..n - 1].try_into().expect("slice length checked")) as usize;
        if pad_len < 255 {
            return Err(FormatError::InvalidSuffixPadding);
        }
        (5usize, pad_len)
    };

    if pad_len < marker_size || pad_len > n {
        return Err(FormatError::InvalidSuffixPadding);
    }
    let payload_len = n.checked_sub(pad_len).ok_or(FormatError::InvalidSuffixPadding)?;
    let zero_padding_end = n - marker_size;
    if plaintext[payload_len..zero_padding_end].iter().any(|byte| *byte != 0) {
        return Err(FormatError::NonZeroPaddingBytes);
    }
    Ok(&plaintext[..payload_len])
}

fn round_up_to_block(value: usize, block_size: usize) -> Result<usize, FormatError> {
    if block_size == 0 {
        return Err(FormatError::PaddingOverflow);
    }
    let remainder = value % block_size;
    if remainder == 0 {
        Ok(value.max(block_size))
    } else {
        value.checked_add(block_size - remainder).ok_or(FormatError::PaddingOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_form_padding_round_trips() {
        let padded = suffix_pad_for_aead(b"hello", 16, 32).unwrap();
        assert_eq!(padded.len() + 16, 32);
        assert_eq!(depad_suffix_padding(&padded).unwrap(), b"hello");
    }

    #[test]
    fn exact_fit_adds_full_extra_block_with_wide_form() {
        let padded = suffix_pad_for_aead(&vec![7; 4080], 16, 4096).unwrap();
        assert_eq!(padded.len() + 16, 8192);
        assert_eq!(padded[padded.len() - 1], 0xff);
        assert_eq!(depad_suffix_padding(&padded).unwrap(), vec![7; 4080]);
    }

    #[test]
    fn wide_form_padding_round_trips() {
        let padded = suffix_pad_for_aead(b"hello", 16, 4096).unwrap();
        assert_eq!(padded[padded.len() - 1], 0xff);
        assert_eq!(depad_suffix_padding(&padded).unwrap(), b"hello");
    }

    #[test]
    fn rejects_noncanonical_wide_form_padding_below_255() {
        assert_eq!(depad_suffix_padding(&[0x05, 0x00, 0x00, 0x00, 0xff]).unwrap_err(), FormatError::InvalidSuffixPadding);
    }

    #[test]
    fn payload_ending_with_ff_does_not_confuse_suffix_marker() {
        let payload = [b'f', b'r', b'a', b'm', b'e', 0xff];
        let padded = suffix_pad_for_aead(&payload, 16, 32).unwrap();

        assert_ne!(padded[payload.len() - 1], padded[padded.len() - 1]);
        assert_eq!(padded[payload.len() - 1], 0xff);
        assert_eq!(depad_suffix_padding(&padded).unwrap(), payload);
    }

    #[test]
    fn rejects_zero_padding_and_non_zero_padding_bytes() {
        assert_eq!(depad_suffix_padding(&[1, 2, 0]).unwrap_err(), FormatError::InvalidSuffixPadding);

        let mut padded = suffix_pad_for_aead(b"hello", 16, 32).unwrap();
        let payload_len = 5;
        padded[payload_len] = 1;
        assert_eq!(depad_suffix_padding(&padded).unwrap_err(), FormatError::NonZeroPaddingBytes);
    }
}

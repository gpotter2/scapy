use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub(crate) fn generate_uuid() -> String {
    /*
     * Generate a stupid UUID with.. 0 dependency.
     * uuid has 614 in its full dependency tree as of today, 06/12/2024. What a broken ecosystem.
     */

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let nanos = since_the_epoch.as_nanos();

    // Convert the nanoseconds to a byte array
    let nanos_bytes = nanos.to_be_bytes().to_vec();

    // Add 2 bytes before that to get 18bytes
    let mut extended_bytes = vec![0x50u8, 0x59u8];
    extended_bytes.extend_from_slice(&nanos_bytes);

    // Format the bytes into a UUID-like string
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes(extended_bytes[0..4].try_into().unwrap()),
        u16::from_be_bytes(extended_bytes[4..6].try_into().unwrap()),
        u16::from_be_bytes(extended_bytes[6..8].try_into().unwrap()),
        u16::from_be_bytes(extended_bytes[8..10].try_into().unwrap()),
        u64::from_be_bytes(extended_bytes[10..18].try_into().unwrap())
    )
}

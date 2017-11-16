extern crate base64;
extern crate ring;
extern crate untrusted;

use base64::{decode_config, URL_SAFE};
use ring::signature;
use untrusted::Input;

fn main() {
    // Replace these 2 lines by the ones displayed when loading index.html
    let public_key =
        "LjtRe7c_gR1fRlxDZ4wnnLAb7rj_yElTwU4B8WQdY3wodN1USPZoJ7PCAE6PAs9wurBhWVnHyzlCYrwXgwXZns";
    let signature = [
        242,
        17,
        132,
        214,
        252,
        20,
        85,
        109,
        130,
        5,
        163,
        76,
        43,
        159,
        99,
        91,
        210,
        153,
        22,
        244,
        31,
        184,
        221,
        159,
        115,
        48,
        114,
        192,
        18,
        28,
        181,
        64,
        8,
        17,
        100,
        165,
        109,
        110,
        155,
        169,
        173,
        156,
        34,
        19,
        48,
        113,
        234,
        103,
        24,
        226,
        141,
        81,
        91,
        108,
        14,
        224,
        230,
        21,
        112,
        69,
        138,
        66,
        255,
        244,
    ];


    let pub_key = decode_config(public_key, URL_SAFE).unwrap();
    let msg = b"bob@example.com";
    let res = signature::verify(
        &signature::ECDSA_P256_SHA256_FIXED,
        Input::from(&pub_key),
        Input::from(msg),
        Input::from(&signature),
    );
    assert!(res.is_ok());

    let msg = b"alice@example.com";
    let res = signature::verify(
        &signature::ECDSA_P256_SHA256_FIXED,
        Input::from(&pub_key),
        Input::from(msg),
        Input::from(&signature),
    );
    assert!(res.is_err());
}

extern crate base64;
extern crate jsonwebtoken as jwt;

use jwt::{decode, Algorithm, DecodingKey, Validation};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn decode_jwt(token: *const c_char, public_key: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(token) };
    let token_str = c_str.to_str().unwrap();

    let c_str_key = unsafe { CStr::from_ptr(public_key) };
    let public_key_str = c_str_key.to_str().unwrap();

    let decoding_key = DecodingKey::from_rsa_pem(public_key_str.as_bytes()).unwrap();
    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<serde_json::Value>(token_str, &decoding_key, &validation);

    match token_data {
        Ok(data) if data.claims["issuer"] == "auth" => {
            let payload = data.claims.to_string();
            let c_string = CString::new(payload).unwrap();
            c_string.into_raw()
        }
        _ => std::ptr::null_mut(),
    }
}

use std::fmt;

use base64ct::Encoding;

/// Debug formatting helper that renders bytes as `TypeName("base64...")`.
pub struct Base64<'a>(pub &'static str, pub &'a [u8]);

impl fmt::Debug for Base64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(self.0)
            .field(&base64ct::Base64::encode_string(self.1))
            .finish()
    }
}

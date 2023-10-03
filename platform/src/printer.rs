// Licensed under the Apache-2.0 license

use ufmt::uWrite;

use crate::{Platform, PlatformError};

pub struct Printer<'a> {
    pub platform: &'a mut dyn Platform,
}

impl<'a> uWrite for Printer<'a> {
    type Error = PlatformError;

    fn write_str(&mut self, str: &str) -> Result<(), Self::Error> {
        self.platform.write_str(str)
    }
}

impl<'a> Printer<'a> {
    pub fn new(platform: &'a mut dyn Platform) -> Self {
        Self { platform }
    }
}

#[macro_export]
macro_rules! plat_println {
    ($platform:expr, $($tt:tt)*) => {{
        let _ = ufmt::uwriteln!(&mut $crate::printer::Printer::new($platform), $($tt)*);
    }}
}

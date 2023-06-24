#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DpeErrorCode {
    NoError = 0,
    InternalError = 1,
    InvalidCommand = 2,
    InvalidArgument = 3,
    ArgumentNotSupported = 4,
    InvalidHandle = 0x1000,
    InvalidLocality = 0x1001,
    BadTag = 0x1002,
    MaxTcis = 0x1003,
    PlatformError = 0x1004,
    CryptoError = 0x1005,
    HashError = 0x1006,
    RandError = 0x1007,
}

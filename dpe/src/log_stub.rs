/*++
Licensed under the Apache-2.0 license.

Abstract:
    Stub implementations for logging macros.
--*/
//! Stub implementations for logging macros

macro_rules! debug {
    (logger: $logger:expr, target: $target:expr, $($arg:tt)+) => {};
    (logger: $logger:expr, $($arg:tt)+) => {};
    (target: $target:expr, $($arg:tt)+) => {};
    ($($arg:tt)+) => {};
}
macro_rules! error {
    (logger: $logger:expr, target: $target:expr, $($arg:tt)+) => {};
    (logger: $logger:expr, $($arg:tt)+) => {};
    (target: $target:expr, $($arg:tt)+) => {};
    ($($arg:tt)+) => {};
}
macro_rules! info {
    (logger: $logger:expr, target: $target:expr, $($arg:tt)+) => {};
    (logger: $logger:expr, $($arg:tt)+) => {};
    (target: $target:expr, $($arg:tt)+) => {};
    ($($arg:tt)+) => {};
}
macro_rules! trace {
    (logger: $logger:expr, target: $target:expr, $($arg:tt)+) => {};
    (logger: $logger:expr, $($arg:tt)+) => {};
    (target: $target:expr, $($arg:tt)+) => {};
    ($($arg:tt)+) => {};
}
macro_rules! warn {
    (logger: $logger:expr, target: $target:expr, $($arg:tt)+) => {};
    (logger: $logger:expr, $($arg:tt)+) => {};
    (target: $target:expr, $($arg:tt)+) => {};
    ($($arg:tt)+) => {};
}

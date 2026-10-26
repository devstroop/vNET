//! Error taxonomy.
//!
//! Modules return typed error sets; the CLI and FFI map these to stable
//! messages/codes. Do not leak implementation errors across module boundaries.

pub const ConfigError = error{
    InvalidJson,
    NotAnObject,
    UnknownField,
    MissingField,
    InvalidType,
    InvalidValue,
    InvalidVersion,
    DuplicateName,
    UndefinedReference,
    OutOfMemory,
};

pub const PortError = error{
    Closed,
    Empty,
    QueueFull,
    FrameTooLarge,
    Unsupported,
    LinkDown,
    PermissionDenied,
    NotFound,
    Busy,
    InvalidArgument,
    WouldBlock,
    NoBufferSpace,
    FdLimit,
    Interrupted,
    Timeout,
    Io,
    OutOfMemory,
};

pub const VnetError = ConfigError || PortError;

test "error sets compose" {
    const err: VnetError = error.UnknownField;
    try @import("std").testing.expectEqual(@as(VnetError, error.UnknownField), err);
}

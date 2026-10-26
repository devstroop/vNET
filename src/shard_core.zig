//! vnet-core: shared types, errors, I/O, logging and configuration.

pub const types = @import("types.zig");
pub const errors = @import("errors.zig");
pub const io = @import("io.zig");
pub const log = @import("log.zig");
pub const config_schema = @import("config/schema.zig");
pub const config_parse = @import("config/parse.zig");
pub const config_validate = @import("config/validate.zig");
pub const config_write = @import("config/write.zig");
pub const config_store = @import("config/store.zig");

pub const version = @import("build_options").version;

pub const Config = config_schema.Config;
pub const PortId = types.PortId;
pub const ConfigError = errors.ConfigError;
pub const PortError = errors.PortError;
pub const VnetError = errors.VnetError;

test {
    _ = types;
    _ = errors;
    _ = io;
    _ = log;
    _ = config_schema;
    _ = config_parse;
    _ = config_validate;
    _ = config_write;
    _ = config_store;
}

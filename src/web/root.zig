pub const assets = @import("assets.zig");
pub const auth = @import("auth.zig");
pub const html = @import("html.zig");
pub const pages = @import("pages.zig");
pub const server = @import("server.zig");

test {
    _ = assets;
    _ = auth;
    _ = html;
    _ = pages;
    _ = server;
}

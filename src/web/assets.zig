//! Frontend assets are embedded so the web process has no runtime asset
//! directory, Node build step or network dependency.

const std = @import("std");

pub const htmx = @embedFile("assets/htmx.min.js");
pub const app_css = @embedFile("assets/app.css");
pub const app_js = @embedFile("assets/app.js");
pub const app_css_rev = contentRevision(app_css);
pub const app_js_rev = contentRevision(app_js);

fn contentRevision(comptime data: []const u8) []const u8 {
    @setEvalBranchQuota(data.len * 2 + 100);
    comptime var hash: u32 = 2_166_136_261;
    comptime var index: usize = 0;
    inline while (index < data.len) : (index += 1) {
        hash = (hash ^ data[index]) *% 16_777_619;
    }
    return std.fmt.comptimePrint("{x}", .{hash});
}
pub const theme_init_js = @embedFile("assets/theme-init.js");
pub const favicon_svg = @embedFile("assets/favicon.svg");
pub const htmx_license = @embedFile("assets/htmx.LICENSE");

pub const Asset = struct {
    data: []const u8,
    content_type: []const u8,
    cache: []const u8,
};

pub fn find(path: []const u8) ?Asset {
    if (std.mem.eql(u8, path, "/favicon.svg")) return .{
        .data = favicon_svg,
        .content_type = "image/svg+xml",
        .cache = "public, max-age=86400",
    };
    if (std.mem.eql(u8, path, "/assets/htmx.min.js")) return .{
        .data = htmx,
        .content_type = "text/javascript; charset=utf-8",
        .cache = "public, max-age=31536000, immutable",
    };
    if (std.mem.eql(u8, path, "/assets/app.css")) return .{
        .data = app_css,
        .content_type = "text/css; charset=utf-8",
        .cache = "public, max-age=31536000, immutable",
    };
    if (std.mem.eql(u8, path, "/assets/app.js")) return .{
        .data = app_js,
        .content_type = "text/javascript; charset=utf-8",
        .cache = "public, max-age=31536000, immutable",
    };
    if (std.mem.eql(u8, path, "/assets/theme-init.js")) return .{
        .data = theme_init_js,
        .content_type = "text/javascript; charset=utf-8",
        .cache = "public, max-age=31536000, immutable",
    };
    if (std.mem.eql(u8, path, "/assets/htmx.LICENSE")) return .{
        .data = htmx_license,
        .content_type = "text/plain; charset=utf-8",
        .cache = "public, max-age=31536000, immutable",
    };
    return null;
}

test "embedded assets are present and traversal is rejected" {
    try std.testing.expect(find("/assets/htmx.min.js") != null);
    try std.testing.expect(find("/assets/app.css") != null);
    try std.testing.expect(find("/assets/app.js") != null);
    try std.testing.expect(find("/favicon.svg") != null);
    try std.testing.expect(find("/assets/../secret") == null);
    try std.testing.expect(find("/overview") == null);
}

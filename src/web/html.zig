const std = @import("std");

pub fn writeEscaped(w: *std.Io.Writer, text: []const u8) !void {
    for (text) |byte| {
        switch (byte) {
            '&' => try w.writeAll("&amp;"),
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '"' => try w.writeAll("&quot;"),
            '\'' => try w.writeAll("&#39;"),
            else => try w.writeByte(byte),
        }
    }
}

pub fn begin(w: *std.Io.Writer, title: []const u8, csrf: ?[]const u8) !void {
    try w.writeAll(
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\<meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<title>
    );
    try writeEscaped(w, title);
    try w.writeAll(
        \\ — vRouter
        \\</title>
        \\<style>
        \\:root{color-scheme:light dark;--bg:#f6f7f9;--panel:#fff;--ink:#16181d;--muted:#5d6470;--line:#d9dde5;--accent:#1f6feb;--ok:#18794e;--bad:#b42318}
        \\@media (prefers-color-scheme:dark){:root{--bg:#111318;--panel:#1a1d24;--ink:#eef1f6;--muted:#a3abb8;--line:#303642;--accent:#71a7ff;--ok:#4ac486;--bad:#ff8a80}}
        \\*{box-sizing:border-box}
        \\body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
        \\header{display:flex;gap:24px;align-items:center;padding:14px 24px;border-bottom:1px solid var(--line);background:var(--panel)}
        \\header strong{font-size:17px;letter-spacing:.02em}
        \\nav{display:flex;gap:16px;flex:1}
        \\nav a{color:var(--muted);text-decoration:none}
        \\nav a:hover,nav a.active{color:var(--ink)}
        \\main{max-width:1120px;margin:0 auto;padding:28px 24px 60px}
        \\h1{font-size:24px;margin:0 0 6px}
        \\p.sub{color:var(--muted);margin:0 0 24px}
        \\section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:0 0 16px}
        \\h2{font-size:16px;margin:0 0 12px}
        \\table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
        \\th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
        \\th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
        \\tr:last-child td{border-bottom:0}
        \\code{font:13px ui-monospace,SFMono-Regular,monospace}
        \\label{display:block;margin:0 0 6px;color:var(--muted)}
        \\input[type=password]{width:100%;max-width:360px;padding:9px 11px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--ink)}
        \\button{padding:9px 16px;border:0;border-radius:7px;background:var(--accent);color:#fff;font-weight:600;cursor:pointer}
        \\.error{color:var(--bad);margin:0 0 14px}
        \\.empty{color:var(--muted);margin:0}
        \\.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
        \\.stat{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px}
        \\.stat b{display:block;font-size:22px;margin-top:4px}
        \\.muted{color:var(--muted)}
        \\.pill{display:inline-block;padding:1px 7px;border-radius:999px;border:1px solid var(--line);font-size:12px}
        \\footer{color:var(--muted);font-size:12px;margin-top:28px}
        \\</style>
        \\</head>
        \\<body>
        \\<header>
        \\<strong>vRouter</strong>
    );
    if (csrf) |token| {
        try w.writeAll(
            \\<nav>
            \\<a href="/">Overview</a>
            \\<a href="/nat">NAT</a>
            \\<a href="/conntrack">Conntrack</a>
            \\</nav>
            \\<form method="post" action="/logout"><input type="hidden" name="csrf" value="
        );
        try writeEscaped(w, token);
        try w.writeAll("\"><button type=\"submit\">Sign out</button></form>");
    } else {
        try w.writeAll("<nav></nav>");
    }
    try w.writeAll("</header><main>");
}

pub fn end(w: *std.Io.Writer) !void {
    try w.writeAll(
        \\</main>
        \\<footer>Read-only preview. All state comes from the vRouter control socket.</footer>
        \\</body>
        \\</html>
    );
}

test "escapes HTML metacharacters" {
    var out: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeEscaped(&w, "<script>&\"'");
    try std.testing.expectEqualStrings("&lt;script&gt;&amp;&quot;&#39;", w.buffered());
}

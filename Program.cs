using BCrypt.Net;
using MySqlConnector;
using System.Security.Cryptography;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowAnyOrigin()));

var app = builder.Build();
app.UseCors();
app.UseWebSockets();

var connStr = builder.Configuration["MySql:ConnectionString"]!;
// Render и другие PaaS задают PORT; локально — Server:Port или 3847
var port = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var envPort)
    ? envPort
    : (int.TryParse(builder.Configuration["Server:Port"], out var cfgPort) ? cfgPort : 3847);

await Db.Migrate(connStr);

var sessions = new Dictionary<string, string>(); // token -> userId
var connections = new Dictionary<string, HashSet<WebSocket>>(); // userId -> sockets
var socketUsers = new Dictionary<WebSocket, string>();

string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

IResult Unauthorized() => Results.Json(new { error = "Unauthorized" }, statusCode: 401);

string? Auth(HttpRequest req)
{
    var h = req.Headers.Authorization.ToString();
    if (!h.StartsWith("Bearer ")) return null;
    var token = h["Bearer ".Length..].Trim();
    if (sessions.TryGetValue(token, out var uid)) return uid;
    return null;
}

async Task SendToUser(string userId, object obj)
{
    if (!connections.TryGetValue(userId, out var set)) return;
    var json = JsonSerializer.Serialize(obj, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    var bytes = Encoding.UTF8.GetBytes(json);
    var seg = new ArraySegment<byte>(bytes);
    foreach (var ws in set.ToArray())
    {
        if (ws.State != WebSocketState.Open) continue;
        try { await ws.SendAsync(seg, WebSocketMessageType.Text, true, CancellationToken.None); }
        catch { }
    }
}

app.Map("/ws", async context =>
{
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = 400;
        return;
    }
    var token = context.Request.Query["token"].ToString();
    if (string.IsNullOrWhiteSpace(token) || !sessions.TryGetValue(token, out var userId))
    {
        context.Response.StatusCode = 401;
        return;
    }

    var ws = await context.WebSockets.AcceptWebSocketAsync();
    if (!connections.TryGetValue(userId, out var set))
    {
        set = new HashSet<WebSocket>();
        connections[userId] = set;
    }
    set.Add(ws);
    socketUsers[ws] = userId;

    var buf = new byte[64 * 1024];
    try
    {
        while (ws.State == WebSocketState.Open)
        {
            var sb = new StringBuilder();
            WebSocketReceiveResult r;
            do
            {
                r = await ws.ReceiveAsync(buf, CancellationToken.None);
                if (r.MessageType == WebSocketMessageType.Close) return;
                sb.Append(Encoding.UTF8.GetString(buf, 0, r.Count));
            } while (!r.EndOfMessage);

            var json = sb.ToString();
            JsonDocument doc;
            try { doc = JsonDocument.Parse(json); } catch { continue; }
            using (doc)
            {
                var root = doc.RootElement;
                if (!root.TryGetProperty("type", out var typeEl)) continue;
                var type = typeEl.GetString() ?? "";

                if (type == "chat")
                {
                    var to = root.GetProperty("to").GetString()?.Trim().ToLowerInvariant();
                    var enc = root.TryGetProperty("enc", out var encEl) && encEl.GetBoolean();
                    var iv = root.TryGetProperty("iv", out var ivEl) ? ivEl.GetString() : null;
                    var ct = root.TryGetProperty("ct", out var ctEl) ? ctEl.GetString() : null;
                    var at = root.TryGetProperty("at", out var atEl) ? atEl.GetInt64() : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    if (string.IsNullOrWhiteSpace(to) || !enc || string.IsNullOrWhiteSpace(iv) || string.IsNullOrWhiteSpace(ct)) continue;

                    await using var conn = new MySqlConnection(connStr);
                    await conn.OpenAsync();
                    if (!await Db.AreFriends(conn, userId, to)) continue;
                    await Db.InsertMessage(conn, userId, to, iv!, ct!, at);
                    await SendToUser(to, new { type = "chat", from = userId, enc = true, iv, ct, at });
                    continue;
                }

                if (type is "signal" or "call-invite" or "call-accept" or "call-end")
                {
                    var to = root.GetProperty("to").GetString()?.Trim().ToLowerInvariant();
                    if (string.IsNullOrWhiteSpace(to)) continue;
                    await using var conn = new MySqlConnection(connStr);
                    await conn.OpenAsync();
                    if (!await Db.AreFriends(conn, userId, to)) continue;

                    if (type == "signal")
                    {
                        var payload = root.GetProperty("payload");
                        await SendToUser(to, new { type = "signal", from = userId, payload });
                    }
                    else if (type == "call-invite")
                    {
                        var callId = root.TryGetProperty("callId", out var c) ? c.GetString() : null;
                        await SendToUser(to, new { type = "call-invite", from = userId, callId = callId ?? Guid.NewGuid().ToString() });
                    }
                    else if (type == "call-accept")
                    {
                        var callId = root.TryGetProperty("callId", out var c) ? c.GetString() : null;
                        await SendToUser(to, new { type = "call-accept", from = userId, callId });
                    }
                    else if (type == "call-end")
                    {
                        var callId = root.TryGetProperty("callId", out var c) ? c.GetString() : null;
                        await SendToUser(to, new { type = "call-end", from = userId, callId });
                    }
                    continue;
                }
            }
        }
    }
    finally
    {
        if (connections.TryGetValue(userId, out var s)) s.Remove(ws);
        socketUsers.Remove(ws);
        try { ws.Dispose(); } catch { }
    }
});

app.MapPost("/api/register", async (RegisterRequest req) =>
{
    var u = (req.username ?? "").Trim().ToLowerInvariant();
    var pw = req.password ?? "";
    if (u.Length < 2 || pw.Length < 1) return Results.BadRequest(new { error = "username and password required" });

    var dn = string.IsNullOrWhiteSpace(req.displayName) ? u : req.displayName.Trim();
    var hash = BCrypt.Net.BCrypt.HashPassword(pw);

    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();

    // ensure unique username
    await using (var check = conn.CreateCommand())
    {
        check.CommandText = "SELECT 1 FROM users WHERE id=@id LIMIT 1;";
        check.Parameters.AddWithValue("@id", u);
        var exists = await check.ExecuteScalarAsync();
        if (exists is not null) return Results.BadRequest(new { error = "invalid or taken username" });
    }

    await using (var cmd = conn.CreateCommand())
    {
        cmd.CommandText = @"INSERT INTO users (id,password_hash,display_name,avatar,public_key_json)
VALUES (@id,@ph,@dn,@av,NULL);";
        cmd.Parameters.AddWithValue("@id", u);
        cmd.Parameters.AddWithValue("@ph", hash);
        cmd.Parameters.AddWithValue("@dn", dn);
        cmd.Parameters.AddWithValue("@av", (object?)req.avatar ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync();
    }

    var token = NewToken();
    sessions[token] = u;
    return Results.Json(new
    {
        token,
        user = new { id = u, displayName = dn, avatar = req.avatar, publicKey = (object?)null, contacts = Array.Empty<object>() }
    });
});

app.MapPost("/api/login", async (LoginRequest req) =>
{
    var u = (req.username ?? "").Trim().ToLowerInvariant();
    var pw = req.password ?? "";

    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();

    string? hash = null;
    string? dn = null;
    string? avatar = null;
    string? pkJson = null;

    await using (var cmd = conn.CreateCommand())
    {
        cmd.CommandText = "SELECT password_hash,display_name,avatar,public_key_json FROM users WHERE id=@id LIMIT 1;";
        cmd.Parameters.AddWithValue("@id", u);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return Results.Json(new { error = "wrong credentials" }, statusCode: 401);
        hash = r.GetString(0);
        dn = r.GetString(1);
        avatar = r.IsDBNull(2) ? null : r.GetString(2);
        pkJson = r.IsDBNull(3) ? null : r.GetString(3);
    }

    if (!BCrypt.Net.BCrypt.Verify(pw, hash)) return Results.Json(new { error = "wrong credentials" }, statusCode: 401);

    var token = NewToken();
    sessions[token] = u;

    var contacts = await Db.GetContacts(conn, u);
    var pk = pkJson is null ? null : System.Text.Json.JsonSerializer.Deserialize<object>(pkJson);
    return Results.Json(new
    {
        token,
        user = new
        {
            id = u,
            displayName = dn,
            avatar,
            publicKey = pk,
            contacts
        }
    });
});

app.MapGet("/api/me", async (HttpRequest request) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    var me = await Db.GetUser(conn, uid);
    if (me is null) return Unauthorized();
    me.contacts = await Db.GetContacts(conn, uid);
    return Results.Json(me);
});

app.MapPost("/api/keys", async (HttpRequest request, KeysRequest body) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    await Db.SetPublicKey(conn, uid, body.publicKey);
    return Results.Json(new { ok = true });
});

app.MapPost("/api/profile", async (HttpRequest request, ProfileRequest body) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    await Db.SetAvatar(conn, uid, body.avatar);
    return Results.Json(new { ok = true });
});

app.MapGet("/api/chat/{peerId}/messages", async (HttpRequest request, string peerId) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    peerId = (peerId ?? "").Trim().ToLowerInvariant();
    if (!await Db.AreFriends(conn, uid, peerId))
        return Results.Json(new { error = "not a contact" }, statusCode: 403);
    var rows = await Db.GetConversation(conn, uid, peerId, 400);
    return Results.Json(rows);
});

app.MapGet("/api/search", async (HttpRequest request, string q) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    q = (q ?? "").Trim().ToLowerInvariant();
    var rows = await Db.SearchUsers(conn, uid, q, 20);
    return Results.Json(rows);
});

app.MapPost("/api/friends/request", async (HttpRequest request, FriendRequestBody body) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    var other = (body.username ?? "").Trim().ToLowerInvariant();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    var ok = await Db.CreateFriendRequest(conn, uid, other);
    return Results.Json(new { ok, duplicate = !ok });
});

app.MapGet("/api/friends/incoming", async (HttpRequest request) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    var rows = await Db.ListIncomingRequests(conn, uid);
    return Results.Json(rows);
});

app.MapPost("/api/friends/respond", async (HttpRequest request, FriendRespondBody body) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    var from = (body.from ?? "").Trim().ToLowerInvariant();
    if (body.accept)
        await Db.AcceptFriend(conn, uid, from);
    else
        await Db.DeleteFriendRequestsBetween(conn, uid, from);
    return Results.Json(new { ok = true });
});

app.MapPost("/api/friends/remove", async (HttpRequest request, FriendRequestBody body) =>
{
    var uid = Auth(request);
    if (uid is null) return Unauthorized();
    var other = (body.username ?? "").Trim().ToLowerInvariant();
    await using var conn = new MySqlConnection(connStr);
    await conn.OpenAsync();
    await Db.RemoveFriend(conn, uid, other);
    return Results.Json(new { ok = true });
});

// 0.0.0.0 — нужно для облака (Render, Fly и т.д.); локально тоже ок
app.Run($"http://0.0.0.0:{port}");

record RegisterRequest(string username, string password, string? displayName, string? avatar);
record LoginRequest(string username, string password);
record KeysRequest(object publicKey);
record ProfileRequest(string? avatar);
record FriendRequestBody(string username);
record FriendRespondBody(string from, bool accept);

using MySqlConnector;
using System.Text.Json;

public static class Db
{
    public static async Task Migrate(string connStr)
    {
        await using var conn = new MySqlConnection(connStr);
        await conn.OpenAsync();
        var sql = @"
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) PRIMARY KEY,
  password_hash VARCHAR(255) NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  avatar MEDIUMTEXT NULL,
  public_key_json MEDIUMTEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_contacts (
  user_id VARCHAR(64) NOT NULL,
  contact_id VARCHAR(64) NOT NULL,
  PRIMARY KEY (user_id, contact_id),
  INDEX idx_contact (contact_id),
  CONSTRAINT fk_uc_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_uc_contact FOREIGN KEY (contact_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS messages (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  from_user VARCHAR(64) NOT NULL,
  to_user VARCHAR(64) NOT NULL,
  iv VARCHAR(64) NOT NULL,
  ciphertext MEDIUMTEXT NOT NULL,
  created_at BIGINT NOT NULL,
  INDEX idx_msg_pair (from_user, to_user, created_at),
  UNIQUE KEY uniq_msg (from_user, to_user, iv, created_at),
  CONSTRAINT fk_msg_from FOREIGN KEY (from_user) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_msg_to FOREIGN KEY (to_user) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS friend_requests (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  from_user VARCHAR(64) NOT NULL,
  to_user VARCHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'pending',
  created_at BIGINT NOT NULL,
  UNIQUE KEY uniq_fr (from_user, to_user),
  INDEX idx_fr_to (to_user, status, created_at),
  CONSTRAINT fk_fr_from FOREIGN KEY (from_user) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_fr_to FOREIGN KEY (to_user) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }

    public static async Task<dynamic?> GetUser(MySqlConnection conn, string id)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id,display_name,avatar,public_key_json FROM users WHERE id=@id LIMIT 1;";
        cmd.Parameters.AddWithValue("@id", id);
        await using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return null;
        var avatar = r.IsDBNull(2) ? null : r.GetString(2);
        var pkJson = r.IsDBNull(3) ? null : r.GetString(3);
        object? pk = pkJson is null ? null : JsonSerializer.Deserialize<object>(pkJson);
        return new
        {
            id = r.GetString(0),
            displayName = r.GetString(1),
            avatar,
            publicKey = pk,
            contacts = Array.Empty<object>()
        };
    }

    public static async Task<List<object>> GetContacts(MySqlConnection conn, string userId)
    {
        var outList = new List<object>();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT u.id, u.display_name, u.avatar, u.public_key_json
FROM user_contacts uc
JOIN users u ON u.id = uc.contact_id
WHERE uc.user_id = @me
ORDER BY u.display_name ASC;";
        cmd.Parameters.AddWithValue("@me", userId);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var avatar = r.IsDBNull(2) ? null : r.GetString(2);
            var pkJson = r.IsDBNull(3) ? null : r.GetString(3);
            object? pk = pkJson is null ? null : JsonSerializer.Deserialize<object>(pkJson);
            outList.Add(new
            {
                id = r.GetString(0),
                displayName = r.GetString(1),
                avatar,
                publicKey = pk
            });
        }
        return outList;
    }

    public static async Task SetPublicKey(MySqlConnection conn, string userId, object publicKey)
    {
        var json = JsonSerializer.Serialize(publicKey, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE users SET public_key_json=@j WHERE id=@id;";
        cmd.Parameters.AddWithValue("@j", json);
        cmd.Parameters.AddWithValue("@id", userId);
        await cmd.ExecuteNonQueryAsync();
    }

    public static async Task SetAvatar(MySqlConnection conn, string userId, string? avatar)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "UPDATE users SET avatar=@a WHERE id=@id;";
        cmd.Parameters.AddWithValue("@a", (object?)avatar ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@id", userId);
        await cmd.ExecuteNonQueryAsync();
    }

    public static async Task<bool> AreFriends(MySqlConnection conn, string a, string b)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM user_contacts WHERE user_id=@a AND contact_id=@b LIMIT 1;";
        cmd.Parameters.AddWithValue("@a", a);
        cmd.Parameters.AddWithValue("@b", b);
        var ok = await cmd.ExecuteScalarAsync();
        return ok is not null;
    }

    public static async Task<List<object>> GetConversation(MySqlConnection conn, string a, string b, int limit)
    {
        var outList = new List<object>();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT id, from_user, to_user, iv, ciphertext, created_at
FROM messages
WHERE (from_user=@a AND to_user=@b) OR (from_user=@b AND to_user=@a)
ORDER BY created_at ASC
LIMIT @lim;";
        cmd.Parameters.AddWithValue("@a", a);
        cmd.Parameters.AddWithValue("@b", b);
        cmd.Parameters.AddWithValue("@lim", limit);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            outList.Add(new
            {
                id = r.GetUInt64(0),
                from_user = r.GetString(1),
                to_user = r.GetString(2),
                iv = r.GetString(3),
                ciphertext = r.GetString(4),
                created_at = r.GetInt64(5)
            });
        }
        return outList;
    }

    public static async Task InsertMessage(MySqlConnection conn, string from, string to, string iv, string ciphertext, long createdAt)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"INSERT IGNORE INTO messages (from_user,to_user,iv,ciphertext,created_at)
VALUES (@f,@t,@iv,@ct,@at);";
        cmd.Parameters.AddWithValue("@f", from);
        cmd.Parameters.AddWithValue("@t", to);
        cmd.Parameters.AddWithValue("@iv", iv);
        cmd.Parameters.AddWithValue("@ct", ciphertext);
        cmd.Parameters.AddWithValue("@at", createdAt);
        await cmd.ExecuteNonQueryAsync();
    }

    public static async Task<List<object>> SearchUsers(MySqlConnection conn, string me, string q, int limit)
    {
        var outList = new List<object>();
        if (string.IsNullOrWhiteSpace(q)) return outList;
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT id, display_name, avatar, public_key_json
FROM users
WHERE id <> @me AND (id LIKE @q OR display_name LIKE @q)
ORDER BY display_name ASC
LIMIT @lim;";
        cmd.Parameters.AddWithValue("@me", me);
        cmd.Parameters.AddWithValue("@q", "%" + q + "%");
        cmd.Parameters.AddWithValue("@lim", limit);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            var avatar = r.IsDBNull(2) ? null : r.GetString(2);
            var pkJson = r.IsDBNull(3) ? null : r.GetString(3);
            object? pk = pkJson is null ? null : JsonSerializer.Deserialize<object>(pkJson);
            outList.Add(new
            {
                id = r.GetString(0),
                displayName = r.GetString(1),
                avatar,
                publicKey = pk
            });
        }
        return outList;
    }

    public static async Task<bool> CreateFriendRequest(MySqlConnection conn, string from, string to)
    {
        if (string.IsNullOrWhiteSpace(to) || to == from) return false;
        // must exist
        await using (var check = conn.CreateCommand())
        {
            check.CommandText = "SELECT 1 FROM users WHERE id=@id LIMIT 1;";
            check.Parameters.AddWithValue("@id", to);
            if (await check.ExecuteScalarAsync() is null) return false;
        }
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        try
        {
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"INSERT INTO friend_requests (from_user,to_user,status,created_at)
VALUES (@f,@t,'pending',@at);";
            cmd.Parameters.AddWithValue("@f", from);
            cmd.Parameters.AddWithValue("@t", to);
            cmd.Parameters.AddWithValue("@at", now);
            await cmd.ExecuteNonQueryAsync();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static async Task<List<object>> ListIncomingRequests(MySqlConnection conn, string toUser)
    {
        var outList = new List<object>();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
SELECT fr.id, fr.from_user, fr.created_at, u.display_name, u.avatar
FROM friend_requests fr
LEFT JOIN users u ON u.id = fr.from_user
WHERE fr.to_user=@me AND fr.status='pending'
ORDER BY fr.created_at DESC;";
        cmd.Parameters.AddWithValue("@me", toUser);
        await using var r = await cmd.ExecuteReaderAsync();
        while (await r.ReadAsync())
        {
            outList.Add(new
            {
                id = r.GetUInt64(0),
                from = r.GetString(1),
                created_at = r.GetInt64(2),
                displayName = r.IsDBNull(3) ? r.GetString(1) : r.GetString(3),
                avatar = r.IsDBNull(4) ? null : r.GetString(4)
            });
        }
        return outList;
    }

    public static async Task DeleteFriendRequestsBetween(MySqlConnection conn, string a, string b)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"DELETE FROM friend_requests
WHERE (from_user=@a AND to_user=@b) OR (from_user=@b AND to_user=@a);";
        cmd.Parameters.AddWithValue("@a", a);
        cmd.Parameters.AddWithValue("@b", b);
        await cmd.ExecuteNonQueryAsync();
    }

    public static async Task AcceptFriend(MySqlConnection conn, string me, string from)
    {
        // add both directions
        await using var tx = await conn.BeginTransactionAsync();
        try
        {
            async Task add(string a, string b)
            {
                await using var cmd = conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = "INSERT IGNORE INTO user_contacts (user_id, contact_id) VALUES (@a,@b);";
                cmd.Parameters.AddWithValue("@a", a);
                cmd.Parameters.AddWithValue("@b", b);
                await cmd.ExecuteNonQueryAsync();
            }
            await add(me, from);
            await add(from, me);
            await DeleteFriendRequestsBetween(conn, me, from);
            await tx.CommitAsync();
        }
        catch
        {
            await tx.RollbackAsync();
            throw;
        }
    }

    public static async Task RemoveFriend(MySqlConnection conn, string me, string other)
    {
        await using var tx = await conn.BeginTransactionAsync();
        try
        {
            async Task del(string a, string b)
            {
                await using var cmd = conn.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = "DELETE FROM user_contacts WHERE user_id=@a AND contact_id=@b;";
                cmd.Parameters.AddWithValue("@a", a);
                cmd.Parameters.AddWithValue("@b", b);
                await cmd.ExecuteNonQueryAsync();
            }
            await del(me, other);
            await del(other, me);
            await DeleteFriendRequestsBetween(conn, me, other);
            await tx.CommitAsync();
        }
        catch
        {
            await tx.RollbackAsync();
            throw;
        }
    }
}


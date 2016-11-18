import vibe.appmain;
import vibe.http.server;
import vibe.http.router;
import vibe.http.session;
import vibe.templ.diet;

import mysql; // mysql-lited

import std.conv : to;
import std.datetime;
import std.regex;
import std.stdio;
import std.uuid;


MySQLClient client;

struct User
{
    ulong id;
    string account_name;
    string passhash;
    bool authority;
    bool del_flg;
    Date created_at;
}

struct Post
{
    ulong id;
    ulong user_id;
    string text;
    Date created_at;
    string mime;
}

struct Comment
{
    ulong id;
    ulong post_id;
    ulong user_id;
    string comment;
    Date created_at;
}

/**
 * Utils
*/

void dbInitialize()
{
    auto conn = client.lockConnection();
    auto sqls = [
        "delete from users where id > 1000",
        "delete from posts where id > 10000",
        "delete from comments where id > 10000",
        // "update users set del_flg = 0",
        // "update users set del_flg = 1 where id % 50 = 0"
        ];
    foreach (q; sqls)
    {
        writeln(q);
        conn.execute(q);
    }
}

string digest(string src)
{
    import std.algorithm : findSplitAfter;
    import std.process : executeShell, escapeShellCommand;
    import std.string : strip;
    return executeShell(escapeShellCommand("print", `"`,  src, `"`, "| openssl dgst -sha512"))
        .output.findSplitAfter("= ")[1].strip;
}

string calculateSalt(string accountName)
{
    return digest(accountName);
}

string calculatePasshash(string accountName, string password)
{
    return digest(password ~ ":" ~ calculateSalt(accountName));
}

User tryLogin(string accountName, string password)
{
    auto conn = client.lockConnection();
    User[] users;
    conn.execute("select * from users where account_name = ? and del_flg = 0", accountName, (MySQLRow row) {
            users ~= row.toStruct!User;
        });
    if (users.length == 0)
        return User.init;
    auto user = users[0];

    if (calculatePasshash(user.account_name, password) == user.passhash)
        return user;
    return User.init;
}

User getSessionUser(HTTPServerRequest req, HTTPServerResponse res)
{
    if (!req.session)
        return User.init;
    if (req.session.isKeySet("user"))
    {
        auto conn = client.lockConnection();
        User[] users;
        auto id = req.session.get("user", "id");
        conn.execute("select * from users where id = ?", id, (MySQLRow row) {
                users ~= row.toStruct!User;
            });
        return users[0];
    }
    return User.init;
}

bool validateUser(string accountName, string password)
{
    if (accountName.matchFirst(ctRegex!`[0-9a-zA-z]{3,}`).empty)
        return false;
    if (password.matchFirst(ctRegex!`[0-9a-zA-Z_]{6,}`).empty)
        return false;
    return true;
}

unittest
{
    assert(!validateUser("", ""));
}

/**
 * Handler.
 */


void getIndex(HTTPServerRequest req, HTTPServerResponse res)
{
    if (getSessionUser(req, res) != User.init)
    {
        auto conn = client.lockConnection();
        Post[] posts;
        conn.execute("select id, user_id, text, created_at, mime from posts order by created_at desc limit 5", (MySQLRow row) {
                posts ~= row.toStruct!Post;
            });
        return res.render!("index.dt", posts);
    }
     return res.redirect("/login");
}


void postIndex(HTTPServerRequest req, HTTPServerResponse res)
{
    auto me = getSessionUser(req, res);
    if (me == User.init)
    {
        writeln("postIndex() no login.");
        res.redirect("/login");
    }
    else if (req.form["csrf_token"] != req.session.get("csrf_token", ""))
    {
        writeln(req.form["csrf_token"]);
        writeln(req.session);
        writeln("トークンが違います");
        res.writeBody("", 422);
    }
    else
    {
        writeln(req.form["csrf_token"]);
        writeln(req.session);
        res.redirect("/login");
    }
}


void getLogin(HTTPServerRequest req, HTTPServerResponse res)
{
    if (getSessionUser(req, res) != User.init)
        return res.redirect("/");
    res.render!("login.dt");
}


void postLogin(HTTPServerRequest req, HTTPServerResponse res)
{
    if (getSessionUser(req, res) != User.init)
        return res.redirect("/");

    auto user = tryLogin(req.form["account_name"], req.form["password"]);
    if (user != User.init)
    {
        if (!req.session)
            req.session = res.startSession();
        req.session.set("user", user.id.to!string);
        req.session.set("csrf_token", randomUUID().to!string);
        return res.redirect("/");
    }
    return res.redirect("/login");
}


void getRegister(HTTPServerRequest req, HTTPServerResponse res)
{
    auto user = getSessionUser(req, res);
    if (user != User.init)
        return res.redirect("/");
    return res.render!("register.dt");
}


void postRegister(HTTPServerRequest req, HTTPServerResponse res)
{
    if (getSessionUser(req, res) != User.init)
        res.redirect("/");

    auto accountName = req.form["account_name"];
    auto password = req.form["password"];

    if (!validateUser(accountName, password))
        return res.redirect("/register");

    auto conn = client.lockConnection();
    bool isSet = false;
    conn.execute("select 1 from users where account_name = ?", accountName, (MySQLRow row) {
            isSet = true;
        });
    if (isSet)
    {
        writeln("アカウント名がすでに使われています");
        return res.redirect("/register");
    }

    conn.execute("insert into users (account_name, passhash) values (?, ?)",
                 accountName, calculatePasshash(accountName, password));

    if (!req.session)
        req.session = res.startSession();
    req.session.set("user", conn.insertID.to!string);
    req.session.set("csrf_token", randomUUID().to!string);
    return res.redirect("/");
}


void getLogout(HTTPServerRequest req, HTTPServerResponse res)
{
    res.terminateSession();
    res.redirect("/");
}


// void getInitialize(HTTPServerRequest req, HTTPServerResponse res)
// {
//     dbInitialize();
// }


version(unittest) {}
else
shared static this()
{
    client = new MySQLClient("host=localhost;port=3306;user=root;pwd=password;db=isuconp");

    auto router = new URLRouter;
    router.get("/", &getIndex);
    router.post("/", &postIndex);
    router.get("/login", &getLogin);
    router.post("/login", &postLogin);
    router.get("/register", &getRegister);
    router.post("/register", &postRegister);
    router.get("/logout", &getLogout);
    // router.get("/initialize", &getInitialize);
    dbInitialize();

    auto settings = new HTTPServerSettings;
    settings.port = 8080;
    settings.bindAddresses = ["::1", "127.0.0.1"];
    settings.sessionStore = new MemorySessionStore;

    listenHTTP(settings, router);
}

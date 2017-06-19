import vibe.appmain;
import vibe.http.server;
import vibe.http.router;
import vibe.http.session;
import vibe.templ.diet;
import vibe.http.fileserver;
import vibe.core.file;

import mysql;

import std.algorithm;
import std.conv : to;
import std.datetime;
import std.regex;
import std.stdio;
import std.uuid;
import std.variant;

immutable UPDATE_LIMIT = 10 * 1024 * 1024;  // 10mb
immutable POST_PER_PAGE = 20;

MySQLPool client;

struct User
{
    int id;
    string account_name;
    string passhash;
    bool authority;
    bool del_flg;
    DateTime created_at;
}

struct Post
{
    int id;
    int user_id;
    string body_;
    string mime;
    DateTime created_at;
    long comment_count;
    User user;
    Comment[] comments;
}

struct Comment
{
    int id;
    int post_id;
    int user_id;
    string comment;
    DateTime created_at;
    User user;
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
        "update users set del_flg = 0",
        "update users set del_flg = 1 where id % 50 = 0"
        ];
    foreach (q; sqls) {
        conn.exec(q);
    }
}

string digest(string src)
{
    import std.algorithm : findSplitAfter;
    import std.process : executeShell, escapeShellCommand;
    import std.string : strip;
    return executeShell(`echo "` ~ escapeShellCommand(src) ~ `"| openssl dgst -sha512`)
        .output
        .findSplitAfter("= ")[1]  // opensslのバージョンによっては (stdin)= というのがつくので取る
        .strip;
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
    auto select = conn.prepare("select * from users where account_name = ? and del_flg = 0");
    select.setArgs(accountName);
    ResultRange range = select.query();
    Row row = range.front;
    auto user = User(
                     row[0].get!(int),
                     row[1].get!(string),
                     row[2].get!(string),
                     row[3].get!(byte).to!bool,
                     row[4].get!(byte).to!bool,
                     row[5].get!(DateTime)
                     );
    if (calculatePasshash(user.account_name, password) == user.passhash)
        return user;
    return User.init;
}

User getSessionUser(HTTPServerRequest req, HTTPServerResponse res)
{
    if (!req.session)
        return User.init;
    if (req.session.isKeySet("user")) {
        auto conn = client.lockConnection();
        auto id = req.session.get("user", "id");
        auto select = conn.prepare("select * from users where id = ?");
        select.setArgs(id);
        auto range = select.query();
        auto row = range.front;
        return User(
                    row[0].get!(int),
                    row[1].get!(string),
                    row[2].get!(string),
                    row[3].get!(byte).to!bool,
                    row[4].get!(byte).to!bool,
                    row[5].get!(DateTime)
                    );
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
    assert(validateUser("kubo39", "kubo39"));
}

string imageURL(Post post)
{
    import std.format : format;
    string ext;
    auto mime = post.mime;
    if (mime == "image/jpeg")
        ext = ".jpg";
    else if (mime == "image/png")
        ext = ".png";
    else if (mime == "image/gif")
        ext = ".gif";
    return format("/image/%d%s", post.id, ext);
}

Post[] makePosts(Post[] results, bool allComments=false)
{
    auto conn = client.lockConnection();
    Post[] posts;
    posts.reserve(POST_PER_PAGE);

    foreach (post; results) {
        {
            auto select = conn.prepare("select count(*) as count from comments where post_id = ?");
            select.setArgs(post.id);
            auto range = select.query();
            auto row = range.front;
            post.comment_count = row[0].get!(long);
        }

        auto queryStmt = "select * from comments where post_id = ? order by created_at desc";
        if (!allComments)
            queryStmt ~= " limit 3";

        Comment[] comments;

        {
            auto select = conn.prepare(queryStmt);
            select.setArgs(post.id);
            auto range = select.query();
            foreach (row; range) {
                comments ~= Comment(
                                    row[0].get!(int),
                                    row[1].get!(int),
                                    row[2].get!(int),
                                    row[3].get!(string),
                                    row[4].get!(DateTime),
                                    );
            }
        }

        {
            foreach (c; comments) {
                auto select = conn.prepare("select * from users where id = ?");
                select.setArgs(c.user_id);
                auto range = select.query();
                auto row = range.front;
                c.user = User(
                              row[0].get!(int),
                              row[1].get!(string),
                              row[2].get!(string),
                              row[3].get!(byte).to!bool,
                              row[4].get!(byte).to!bool,
                              row[5].get!(DateTime)
                              );
            }
        }

        reverse(comments);
        post.comments = comments;

        {
            auto select = conn.prepare("select * from users where id = ?");
            select.setArgs(post.user_id);
            auto range = select.query();
            auto row = range.front;
            post.user =User(
                            row[0].get!(int),
                            row[1].get!(string),
                            row[2].get!(string),
                            row[3].get!(byte).to!bool,
                            row[4].get!(byte).to!bool,
                            row[5].get!(DateTime)
                            );
        }

        if (!post.user.del_flg)
            posts ~= post;

        if (posts.length >= POST_PER_PAGE)
            break;
    }
    return posts;
}


/**
 * Handler.
 */

void getIndex(HTTPServerRequest req, HTTPServerResponse res)
{
    if (getSessionUser(req, res) !is User.init) {
        auto conn = client.lockConnection();
        auto csrf_token = req.session.get("csrf_token", "");
        Post[] posts;
        posts.reserve(POST_PER_PAGE);

        auto range = conn.query("select id, user_id, body, mime, created_at from posts order by created_at desc limit 20");
        foreach (row; range) {
            posts ~= Post(
                          row[0].get!(int),
                          row[1].get!(int),
                          row[2].get!(string),
                          row[3].get!(string),
                          row[4].get!(DateTime),
                          );
        }
        posts = makePosts(posts);
        return res.render!("index.dt", posts, csrf_token);
    }
     return res.redirect("/login");
}


void postIndex(HTTPServerRequest req, HTTPServerResponse res)
{
    auto me = getSessionUser(req, res);
    if (me is User.init) {
        return res.redirect("/login");
    }

    if (req.form["csrf_token"] != req.session.get("csrf_token", "")) {
        enforceHTTP(false, HTTPStatus.unprocessableEntity, httpStatusText(HTTPStatus.unprocessableEntity));
    }

    auto pf = "file" in req.files;
    if (pf is null) {
        stderr.writeln("画像が必要です");
        return res.redirect("/");
    }

    Path path = pf.tempPath; //filename;
    auto buffer = new ubyte[UPDATE_LIMIT + 1];

    path.readFile(buffer, UPDATE_LIMIT + 1);

    FileStream tempf = createTempFile("xxx");
    tempf.path.writeFile(buffer);
    size_t  filesz = min(tempf.tell(), UPDATE_LIMIT);
    if (filesz > UPDATE_LIMIT) {
        stderr.writeln("ファイルが大きすぎます");
        return res.redirect("/");
    }
    tempf.seek(0);
    ubyte[] imgdata = new ubyte[filesz];
    tempf.write(imgdata);

    auto mime = "";
    auto conn = client.lockConnection();
    auto insert = conn.prepare("insert into posts (user_id, mime, imgdata, body) values (?, ?, ?, ?)");
    insert.setArgs(me.id, mime, imgdata, req.form["body"]);
    insert.exec();
    auto pid = conn.lastInsertID;
    return res.redirect("/posts/" ~ pid.to!string);
}


void getLogin(HTTPServerRequest req, HTTPServerResponse res)
{
    if (getSessionUser(req, res) !is User.init)
        return res.redirect("/");
    return res.render!("login.dt");
}


void postLogin(HTTPServerRequest req, HTTPServerResponse res)
{
    if (getSessionUser(req, res) !is User.init)
        return res.redirect("/");

    auto user = tryLogin(req.form["account_name"], req.form["password"]);
    if (user !is User.init) {
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
    if (user !is User.init)
        return res.redirect("/");
    return res.render!("register.dt");
}


void postRegister(HTTPServerRequest req, HTTPServerResponse res)
{
    if (getSessionUser(req, res) !is User.init)
        return res.redirect("/");

    auto accountName = req.form["account_name"];
    auto password = req.form["password"];

    if (!validateUser(accountName, password))
        return res.redirect("/register");

    auto conn = client.lockConnection();
    auto select = conn.prepare("select 1 from users where account_name = ?");
    select.setArgs(accountName);
    auto row = select.query();
    if (row.count != 0) {
        stderr.writeln("アカウント名がすでに使われています");
        return res.redirect("/register");
    }

    auto insert = conn.prepare("insert into users (account_name, passhash) values (?, ?)");
    insert.setArgs(accountName, calculatePasshash(accountName, password));
    insert.exec();

    if (!req.session)
        req.session = res.startSession();
    req.session.set("user", conn.lastInsertID.to!string);
    req.session.set("csrf_token", randomUUID().to!string);
    return res.redirect("/");
}


void getLogout(HTTPServerRequest req, HTTPServerResponse res)
{
    res.terminateSession();
    return res.redirect("/");
}


void getPosts(HTTPServerRequest req, HTTPServerResponse res)
{
    auto conn = client.lockConnection();
    // auto maxCreatedAt = req.form["max_created_at"];

    Post[] posts;
    posts.reserve(POST_PER_PAGE);

    auto range = conn.query("select id, user_id, body, mime, created_at from posts order by created_at desc limit 20");
    Post post;
    foreach (row; range) {
        posts ~= Post(
                      row[0].get!(int),
                      row[1].get!(int),
                      row[2].get!(string),
                      row[3].get!(string),
                      row[4].get!(DateTime),
                      );
    }
    posts = makePosts(posts);
    string csrf_token = "";
    return res.render!("posts.dt", posts, csrf_token);
}


void getPostsId(HTTPServerRequest req, HTTPServerResponse res)
{
    auto conn = client.lockConnection();
    Post[] posts;
    posts.reserve(POST_PER_PAGE);

    auto select = conn.prepare("select id, user_id, body, mime, created_at from posts where id = ?");  // Do not use `*` !
    select.setArgs(req.params["id"]);
    auto range = select.query();
    foreach (row; range) {
        posts ~= Post(
                      row[0].get!(int),
                      row[1].get!(int),
                      row[2].get!(string),
                      row[3].get!(string),
                      row[4].get!(DateTime),
                      );
    }
    posts = makePosts(posts, true);  // assign `allComments` = true.
    if (!posts.length)
        enforceHTTP(false, HTTPStatus.notFound, httpStatusText(HTTPStatus.notFound));
    auto me = getSessionUser(req, res);
    if (me is User.init)
        return res.redirect("/");
    auto csrf_token = req.session.get("csrf_token", "");
    auto post = posts[0];
    return res.render!("post.dt", post, csrf_token);
}


void getUserList(HTTPServerRequest req, HTTPServerResponse res)
{
    auto conn = client.lockConnection();

    User user;
    {
        auto select = conn.prepare("select * from users where account_name = ? and del_flg = 0");
        select.setArgs(req.params["account_name"]);
        auto range = select.query();
        auto row = range.front;
        user = User(
                    row[0].get!(int),
                    row[1].get!(string),
                    row[2].get!(string),
                    row[3].get!(byte).to!bool,
                    row[4].get!(byte).to!bool,
                    row[5].get!(DateTime)
                    );
    }
    if (user is User.init)
        return res.writeBody("", 404);


    Post[] posts;
    posts.reserve(POST_PER_PAGE);

    {
        auto select = conn.prepare("select id, user_id, body, mime, created_at from posts where user_id = ? order by created_at desc");
        select.setArgs(user.id);
        auto range = select.query();
        foreach (row; range) {
            posts ~= Post(
                          row[0].get!(int),
                          row[1].get!(int),
                          row[2].get!(string),
                          row[3].get!(string),
                          row[4].get!(DateTime),
                          );
        }
    }

    posts = makePosts(posts);

    int commentCount;
    {
        auto select = conn.prepare("select count(*) as count from comments where user_id = ?");
        select.setArgs(user.id);
        auto range = select.query();
        auto row = range.front;
        commentCount = row[0].get!(int);
    }

    uint[] postIds;
    {
        auto select = conn.prepare("select id from posts where user_id = ?");
        select.setArgs(user.id);
        auto range = select.query();
        foreach (row; range) {
            postIds ~= row[0].get!(int);
        }
    }
    size_t postCount = postIds.length;

    int commentedCount;
    if (postCount) {
        auto select = conn.prepare("select count(*) as count from comments where post_id in ?");
        select.setArgs(postIds);
        auto range = select.query();
        auto row = range.front;
        commentedCount = row[0].get!(int);
    }

    auto me = getSessionUser(req, res);
    string csrf_token = (me !is User.init) ? req.session.get("csrf_token", "") : "";

    return res.render!("user.dt", user, posts, postCount, commentCount, commentedCount, csrf_token);
}

// void getInitialize(HTTPServerRequest req, HTTPServerResponse res)
// {
//     dbInitialize();
// }


version(unittest) {}
else
shared static this()
{
    client = new MySQLPool("host=localhost;port=3306;user=root;pwd=password;db=isuconp");

    auto router = new URLRouter;
    router.get("/", &getIndex);
    router.post("/", &postIndex);
    router.get("/login", &getLogin);
    router.post("/login", &postLogin);
    router.get("/register", &getRegister);
    router.post("/register", &postRegister);
    router.get("/logout", &getLogout);
    router.get("/posts", &getPosts);
    router.get("/posts/:id", &getPostsId);
    router.get("/:account_name", &getUserList);

    router.get("*", serveStaticFiles("../public/"));

    // router.get("/initialize", &getInitialize);
    dbInitialize();

    auto settings = new HTTPServerSettings;
    settings.port = 8080;
    settings.bindAddresses = ["::1", "127.0.0.1"];
    settings.sessionStore = new MemorySessionStore;

    listenHTTP(settings, router);
}

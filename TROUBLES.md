# `body` が予約語

クエリが叩けない。

```
source/app.d(45,16): Error: no identifier for declarator string
source/app.d(45,16): Error: declaration expected, not 'body'
```

カラム名を body -> text に変更することで対処。

# mysql-litedで `update users set del_flg = 0` を叩くとAssertionで落ち、さらにSEGVる

mysql-litedのバージョンは `0.3.6`。その後 `3.12` にアップデートしているが同様の現象が続いている。

```
update users set del_flg = 0
core.exception.AssertError@../../../.dub/packages/mysql-lited-0.3.12/mysql-lited/src/mysql/packet.d(53): Assertion failure
Segmentation fault
```

gdbでみる。

```
(gdb) b _D5mysql6packet11InputPacket4skipMFmZv
Breakpoint 1 at 0x2e951c: file ../../../.dub/packages/mysql-lited-0.3.6/mysql-lited/src/mysql/packet.d, line 53.
(gdb) r
Starting program: /home/kubo39/dev/dlang/pixiv-isucon-dlang/isuapp
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, mysql.packet.InputPacket.skip(ulong) (this=..., count=1) at ../../../.dub/packages/mysql-lited-0.3.6/mysql-lited/src/mysql/packet.d:53
53                      assert(count <= in_.length);
(gdb) list
48                      if (x != eat!T)
49                              throw new MySQLProtocolException("Bad packet format");
50              }
51
52              void skip(size_t count) {
53                      assert(count <= in_.length);
54                      in_ = in_[count..$];
55              }
56
57              auto countUntil(ubyte x, bool expect) {
(gdb) p count
$1 = 1
(gdb) p in_.length
$2 = 67
...
Breakpoint 1, mysql.packet.InputPacket.skip(ulong) (this=..., count=10) at ../../../.dub/packages/mysql-lited-0.3.6/mysql-lited/src/mysql/packet.d:53
53                      assert(count <= in_.length);
(gdb) p count
$5 = 10
(gdb) p in_.length
$6 = 45
(gdb) c
Continuing.
object.Exception@../../../.dub/packages/vibe-d-0.7.30/vibe-d/source/vibe/core/drivers/libevent2_tcp.d(438): Connection error while reading from TCPConnection.

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff6f2348d in _d_criticalenter () from /home/kubo39/dlang/dmd-2.072.0/linux/lib64/libphobos2.so.0.72
```

- dmesg

```
[43426.121919] traps: isuapp[8288] general protection ip:7f810369648d sp:7fff8e066bd0 error:0 in libphobos2.so.0.72.0[7f81031e2000+5ad000]
```

とりあえず無視して実装をすすめる。

# mysql-litedのmasterが壊れてる？

master指定してビルドするとエラーに。(単純にgit cloneしてきて試したらおこらない)

その後 `0.3.13` で試した際も同様の事象が発生。

```
pixiv-isucon-dlang ~master: building configuration "application"...
../../../.dub/packages/mysql-lited-master/mysql-lited/src/mysql/connection.d(246,4): Error: undefined identifier 'func'
../../../.dub/packages/mysql-lited-master/mysql-lited/src/mysql/connection.d(246,4): Error: undefined identifier 'file', did you mean variable 'File'?
../../../.dub/packages/mysql-lited-master/mysql-lited/src/mysql/connection.d(246,4): Error: undefined identifier 'line', did you mean variable 'Line'?
source/app.d(32,21): Error: template instance mysql.connection.Connection!(VibeSocket, cast(ConnectionOptions)0).Connection.execute!("source/app.d", 32) error instantiating
../../../.dub/packages/mysql-lited-master/mysql-lited/src/mysql/connection.d(246,4): Error: undefined identifier 'func'
../../../.dub/packages/mysql-lited-master/mysql-lited/src/mysql/connection.d(246,4): Error: undefined identifier 'file', did you mean variable 'File'?
../../../.dub/packages/mysql-lited-master/mysql-lited/src/mysql/connection.d(246,4): Error: undefined identifier 'line', did you mean variable 'Line'?
source/app.d(51,17): Error: template instance mysql.connection.Connection!(VibeSocket, cast(ConnectionOptions)0).Connection.execute!("source/app.d", 51, void delegate(MySQLRow row) @system) error instantiating
```

ダウングレードして進めている。

# (Solved) dietテンプレートでダブルクォート内の変数展開ができない

(追記): diet-ngでは記法が変わったようだ。 https://github.com/rejectedsoftware/diet-ng

dietテンプレート側

```
...
    div.isu-posts
        - foreach (post; posts)
            div.isu-post(id="pid_!\{ post.id }", data-created-at="!\{  post.created_at }")
                div.isu-post-header
                div.isu-post-image
                    img.isu-image(src="!\{ post.image_url }")
...
```

生成されるHTML

```
<div class="isu-post" id="pid_!{ post.id }" data-created-at="!{  post.created_at }"><div class="isu-post-header"></div><div class="isu-post-image"><img class="isu-image" src="!{ post.image_url }"></div></div>
```

# デフォルトのエラー用ページがない

Flaskの `abort(422)` 相当のものがない。

とりあえずHTTPServerResponse の `erturn writeBody(string data, int status)` に  `return writeBody("", 422)` と書いた。

# SessionまわりでなにかあるとすぐにSEGVる

原因はSessionでnull参照なんだけどまじで辛い。

これはvibe.dのSessionの実装上どうしようもない。

# `select count(*) as count from comments where post_id = ?` の結果をマッピングするのが一苦労

`select count(*) as count from comments where post_id = ?` の返り値のマッピングがわからん。

# Rangeの実装まわり

構造体Userの配列usersで `if (users.length == 0)` のところを `users.empty` にしたい。

UsersにInputRangeを実装すればよさそうだが楽にできないかな。

# (Solved)MySQLのrowのマッピングがきっちりしてるので存在しないカラムあるときに例外でおちる

(追記) `auto user = row.toStruct!(User, Strict.no);` のように Strict.no オプションがあれば存在しないカラムに対するマッピングができる。

```
struct Post
{
    uint id;
    uint user_id;
    string text;  // `body` is reserved keyword in D.
    Date created_at;
    string mime;
    // カラムに存在しないメンバ
    string hoge;
}
...
```

`users ~= row.toStruct!User` のときhogeがあるので例外で落ちる。

# vibe.dのエラーメッセージがひどい

```
500 - Internal Server Error

Internal Server Error

Internal error information:
object.Exception@../../../.dub/packages/vibe-d-0.7.30/vibe-d/source/vibe/core/drivers/threadedfile.d(99): Failed to open file 'euph_st01_01.png'.
----------------
??:? vibe.core.drivers.threadedfile.ThreadedFileStream vibe.core.drivers.threadedfile.ThreadedFileStream.__ctor(vibe.inet.path.Path, vibe.core.file.FileMode) [0x1738255e]
??:? vibe.core.drivers.threadedfile.ThreadedFileStream vibe.core.drivers.libevent2.Libevent2Driver.openFile(vibe.inet.path.Path, vibe.core.file.FileMode) [0x173761e0]
??:? vibe.core.file.FileStream vibe.core.file.openFile(vibe.inet.path.Path, vibe.core.file.FileMode) [0x173ebab3]
??:? ubyte[] vibe.core.file.readFile(vibe.inet.path.Path, ubyte[], ulong) [0x17386543]
??:? void app.postIndex(vibe.http.server.HTTPServerRequest, vibe.http.server.HTTPServerResponse) [0x172649ae]
??:? void std.functional.DelegateFaker!(void function(vibe.http.server.HTTPServerRequest, vibe.http.server.HTTPServerResponse)*).DelegateFaker.doIt(vibe.http.server.HTTPServerRequest, vibe.http.server.HTTPServerResponse) [0x1730d27b]
??:? _D4vibe4http6router9URLRouter13handleRequestMFC4vibe4http6server17HTTPServerRequestC4vibe4http6server18HTTPServerResponseZ21__T9__lambda4TmTAAyaZ9__lambda4MFmMAAyaZb [0x172eff27]
??:? const(bool function(immutable(char)[], scope bool delegate(ulong, scope immutable(char)[][]))) vibe.http.router.MatchTree!(vibe.http.router.Route).MatchTree.doMatch [0x172f0d1c]
??:? bool vibe.http.router.MatchTree!(vibe.http.router.Route).MatchTree.match(immutable(char)[], scope bool delegate(ulong, scope immutable(char)[][])) [0x172f057b]
??:? void vibe.http.router.URLRouter.handleRequest(vibe.http.server.HTTPServerRequest, vibe.http.server.HTTPServerResponse) [0x172efbcb]
??:? bool vibe.http.server.handleRequest(vibe.core.stream.Stream, vibe.core.net.TCPConnection, vibe.http.server.HTTPListenInfo, ref vibe.http.server.HTTPServerSettings, ref bool) [0x1732dd93]
??:? void vibe.http.server.handleHTTPConnection(vibe.core.net.TCPConnection, vibe.http.server.HTTPListenInfo) [0x1732c35c]
??:? void vibe.http.server.listenHTTPPlain(vibe.http.server.HTTPServerSettings).doListen(vibe.http.server.HTTPListenInfo, bool, bool).__lambda4(vibe.core.net.TCPConnection) [0x1732bcd8]
??:? void vibe.core.drivers.libevent2_tcp.ClientTask.execute() [0x173eb615]
??:? void vibe.core.core.makeTaskFuncInfo!(void delegate()).makeTaskFuncInfo(ref void delegate()).callDelegate(vibe.core.core.TaskFuncInfo*) [0x173748f4]
??:? void vibe.core.core.CoreTask.run() [0x17372232]
??:? void core.thread.Fiber.run() [0x25520f3b]
??:? fiber_entryPoint [0x255201f6]
??:? [0xffffffff]
```

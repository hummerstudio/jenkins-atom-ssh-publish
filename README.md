# jenkins-atom-ssh-publish

把文件推到另一台机器，保持目录结构。

publish-over-ssh 插件驱动 scp/rsync 并带一大堆传输选项；有用的核心是「这些文件要原样出现在那边」。这个原子在内存里打一个 tar，通过一次 `ssh host 'tar -xf -'` 送过去——**远端只需要 sshd 和 tar**，而且是一次连接，不是每个文件一次。

- 模式匹配相对 `baseDir`（默认 workspace），`exclude` 再减一层
- 私钥可以给路径，也可以给内容（内容会写到 0600 的临时文件，用完删除）
- `deleteRemote` 用 `find -mindepth 1 -delete`，不会删掉目录本身，拒绝 `/` 这种路径
- 退出码非 0 才算失败；`Permission denied`/`Host key verification` 归 `USER`，其余归 `ENVIRONMENT`

```bash
mvn verify
```

`src/test/java/atom/SshPublishIT.java` 会在一个临时端口起一个**临时 sshd**（自己的 host key 与 authorized_keys，不碰系统配置），传完再回到磁盘上逐字节对账。

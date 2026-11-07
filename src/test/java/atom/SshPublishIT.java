package atom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.jenkinschina.atom.sdk.Json;
import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The ssh-publish atom against a real sshd on a throwaway port, real keys, and the files compared on disk.
 *
 * <p>These are the checks {@code tools/smoke.sh} made — the nested paths, a space and a UTF-8 name, exclude, the
 * runner's scratch never uploaded, deleteRemote, the key as a secret, and the failures (unreachable port, {@code /} as
 * remoteDir, nothing matched, a host key that changed).
 *
 * <p>The workspace is a real directory with a 0600 key file, handed to the atom as {@code atom_workspace}, because SSH
 * refuses a private key anyone else can read.
 */
class SshPublishIT {

    private static final Path SSHD = Path.of("/usr/sbin/sshd");

    private static Path dir;
    private static Path userKey;
    private static String user;
    private static int port;
    private static boolean started;

    private Atom atom;

    @BeforeAll
    static void startSshd() throws Exception {
        assumeTrue(Files.isExecutable(SSHD),
                "a real transfer needs a throwaway sshd: /usr/sbin/sshd is not installed on this agent");

        Path module = Path.of(System.getProperty("atom.module", System.getProperty("user.dir")));
        dir = Files.createDirectories(Path.of(System.getProperty("atom.scratch", module.resolve("target").toString()))
                .resolve("sshd-" + System.nanoTime()));
        Path hostKey = dir.resolve("host_key");
        userKey = dir.resolve("user_key");
        Path authorized = dir.resolve("authorized_keys");
        Path pid = dir.resolve("sshd.pid");
        Path log = dir.resolve("sshd.log");

        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey.toString());
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", userKey.toString());
        Files.copy(dir.resolve("user_key.pub"), authorized);
        Files.setPosixFilePermissions(authorized, PosixFilePermissions.fromString("rw-------"));

        user = System.getProperty("user.name");
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        Path config = dir.resolve("sshd_config");
        Files.writeString(config, """
                Port %d
                ListenAddress 127.0.0.1
                HostKey %s
                PidFile %s
                AuthorizedKeysFile %s
                PasswordAuthentication no
                UsePAM no
                StrictModes no
                """.formatted(port, hostKey, pid, authorized));

        Process sshd = new ProcessBuilder(SSHD.toString(), "-f", config.toString(), "-E", log.toString())
                .redirectErrorStream(true)
                .start();
        if (!sshd.waitFor(30, TimeUnit.SECONDS) || sshd.exitValue() != 0) {
            throw new IllegalStateException("could not start the throwaway sshd:\n"
                    + (Files.exists(log) ? Files.readString(log) : ""));
        }
        started = true;

        long deadline = System.currentTimeMillis() + 8_000;
        while (!accepts()) {
            if (System.currentTimeMillis() > deadline) {
                throw new IllegalStateException("the throwaway sshd never accepted the key:\n" + Files.readString(log));
            }
            Thread.sleep(200);
        }
    }

    private static boolean accepts() {
        try {
            Process probe = new ProcessBuilder("ssh", "-p", String.valueOf(port), "-i", userKey.toString(),
                    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null", user + "@127.0.0.1", "true")
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start();
            return probe.waitFor(10, TimeUnit.SECONDS) && probe.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static void command(String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
            throw new IllegalStateException(String.join(" ", command) + " failed");
        }
    }

    @AfterAll
    static void stopSshd() throws Exception {
        if (started) {
            Path pid = dir.resolve("sshd.pid");
            if (Files.isRegularFile(pid)) {
                command("kill", Files.readString(pid).trim());
            }
            started = false;
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        atom = Atom.of();
    }

    /** A workspace the atom will treat as the job workspace, with a private key only this user can read. */
    private Path workspace(Path dir) throws IOException {
        Files.createDirectories(dir);
        return dir;
    }

    private static Path write(Path ws, String path, String content) throws IOException {
        Path file = ws.resolve(path);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return file;
    }

    private static void deployKey(Path ws) throws IOException {
        Path key = write(ws, "deploy_key", Files.readString(userKey));
        Files.setPosixFilePermissions(key, PosixFilePermissions.fromString("rw-------"));
    }

    private Atom upload(Path ws, String remote) {
        return atom.input("atom_workspace", ws.toString())
                .input("host", "127.0.0.1")
                .input("port", String.valueOf(port))
                .input("user", user)
                .input("remoteDir", remote)
                .input("keyFile", "deploy_key")
                .input("knownHostsFile", "known_hosts");
    }

    @Test
    @DisplayName("a real transfer keeps nested paths, a name with spaces and a UTF-8 name, and honours exclude")
    void transfersFilesIntact(@TempDir Path ws) throws Exception {
        ws = workspace(ws);
        write(ws, "dist/app.jar", "jar-bytes\n");
        write(ws, "dist/nested/deep.txt", "deep\n");
        write(ws, "dist/a file with spaces.txt", "spaced\n");
        write(ws, "dist/报告.txt", "zh\n");
        write(ws, "secret/password.txt", "nope\n");
        deployKey(ws);
        Path root = dir.resolve("remote");

        AtomResult run = upload(ws, root.toString())
                .input("sourceFiles", "dist/**/*")
                .input("exclude", "**/*.log")
                .run();

        run.assertOk();
        assertEquals("4", run.field("filesUploaded"), run.toString());
        assertArrayEquals(Files.readAllBytes(ws.resolve("dist/app.jar")), Files.readAllBytes(root.resolve("dist/app.jar")),
                "app.jar did not arrive intact");
        assertArrayEquals(Files.readAllBytes(ws.resolve("dist/nested/deep.txt")),
                Files.readAllBytes(root.resolve("dist/nested/deep.txt")), "the nested path was flattened");
        assertArrayEquals(Files.readAllBytes(ws.resolve("dist/a file with spaces.txt")),
                Files.readAllBytes(root.resolve("dist/a file with spaces.txt")), "a name with spaces broke the transfer");
        assertArrayEquals(Files.readAllBytes(ws.resolve("dist/报告.txt")), Files.readAllBytes(root.resolve("dist/报告.txt")),
                "a UTF-8 name broke the transfer");
        assertFalse(Files.exists(root.resolve("secret/password.txt")), "a file outside the pattern must not be sent");
        assertTrue(Files.readString(ws.resolve("known_hosts")).contains("127.0.0.1"),
                "knownHostsFile should have recorded the host key");
    }

    @Test
    @DisplayName("the runner's own scratch is never uploaded, whatever the pattern says")
    void neverUploadsTheRunnerScratch(@TempDir Path ws) throws Exception {
        ws = workspace(ws);
        write(ws, "dist/sub/keep.txt", "ship\n");
        write(ws, ".atoms/run1/.secrets.json", "{\"token\": \"super-secret\"}");
        write(ws, ".atoms/run1/input.json", "{\"a\": 1}");
        deployKey(ws);
        Path root = dir.resolve("scratch");

        AtomResult run = upload(ws, root.toString()).input("sourceFiles", "**/*").run();

        run.assertOk();
        assertFalse(Files.exists(root.resolve(".atoms/run1/.secrets.json")), "the runner's secrets were uploaded");
        assertFalse(Files.exists(root.resolve(".atoms")), "the runner's scratch directory was uploaded");
        assertTrue(Files.exists(root.resolve("dist/sub/keep.txt")), "a real file was skipped along with the scratch");
    }

    @Test
    @DisplayName("deleteRemote clears what is no longer produced, and a repeat against known_hosts is a plain hit")
    void replacesWhatIsNoLongerProduced(@TempDir Path ws) throws Exception {
        ws = workspace(ws);
        write(ws, "dist/app.jar", "jar-bytes\n");
        write(ws, "dist/nested/deep.txt", "deep\n");
        deployKey(ws);
        Path root = dir.resolve("remote-delete");

        AtomResult first = upload(ws, root.toString()).input("sourceFiles", "dist/**/*").run();
        first.assertOk();

        write(ws, "dist/app.jar", "stale\n"); // the remote copy exists, then the source changes
        Files.writeString(root.resolve("dist/old.txt"), "stale\n");
        Files.delete(ws.resolve("dist/app.jar"));

        AtomResult second = upload(ws, root.toString())
                .input("sourceFiles", "dist/**/*")
                .input("deleteRemote", "true")
                .run();
        second.assertOk();
        assertFalse(Files.exists(root.resolve("dist/old.txt")), "deleteRemote should have removed the stale file");
        assertFalse(Files.exists(root.resolve("dist/app.jar")), "a deleted source must not survive remotely");
        assertTrue(Files.exists(root.resolve("dist/nested/deep.txt")), "the remaining files must still be there");

        write(ws, "dist/app.jar", "again\n");
        AtomResult repeat = upload(ws, root.toString()).input("sourceFiles", "dist/**/*").run();
        repeat.assertOk();
        assertArrayEquals(Files.readAllBytes(ws.resolve("dist/app.jar")), Files.readAllBytes(root.resolve("dist/app.jar")),
                "the repeat upload did not land");
    }

    @Test
    @DisplayName("the key can come as a secret instead of a path")
    void acceptsTheKeyAsASecret(@TempDir Path ws) throws Exception {
        ws = workspace(ws);
        write(ws, "out/x.txt", "x\n");
        Path root = dir.resolve("remote-secretkey");

        AtomResult run = atom.input("atom_workspace", ws.toString())
                .file(".secrets.json", Json.write(Map.of("key", Files.readString(userKey))))
                .input("host", "127.0.0.1")
                .input("port", String.valueOf(port))
                .input("user", user)
                .input("remoteDir", root.toString())
                .input("sourceFiles", "out/**/*")
                .input("knownHostsFile", "known_hosts")
                .run();

        run.assertOk();
        assertTrue(Files.exists(root.resolve("out/x.txt")), "the file sent with a key secret is not there");
    }

    @Test
    @DisplayName("a port with nothing listening, / as the target and a pattern that matches nothing all fail")
    void reportsTheFailures(@TempDir Path ws) throws Exception {
        ws = workspace(ws);
        write(ws, "dist/app.jar", "jar-bytes\n");
        deployKey(ws);

        AtomResult unreachable = atom.input("atom_workspace", ws.toString())
                .input("host", "127.0.0.1")
                .input("port", "1")
                .input("user", user)
                .input("remoteDir", "/tmp/x")
                .input("sourceFiles", "dist/**/*")
                .input("keyFile", "deploy_key")
                .run();
        assertNotEquals(0, unreachable.exit(), "a port with nothing listening must fail");
        assertTrue(unreachable.field("message").contains("ssh failed"),
                "the ssh failure must be reported:\n" + unreachable.toString());

        AtomResult root = upload(ws, "/").input("sourceFiles", "dist/**/*").run();
        assertNotEquals(0, root.exit(), "remoteDir / must be refused");
        assertTrue(root.field("message").contains("must be a real directory"), "message:\n" + root.toString());

        AtomResult nothing = upload(ws, dir.resolve("remote-nothing").toString())
                .input("sourceFiles", "nothing-here/**/*.jar")
                .run();
        assertNotEquals(0, nothing.exit(), "matching nothing must fail");
        assertTrue(nothing.field("message").contains("no file matched"), "message:\n" + nothing.toString());
    }

    @Test
    @DisplayName("a host key that changed under us is refused, and says why")
    void refusesAChangedHostKey(@TempDir Path ws) throws Exception {
        ws = workspace(ws);
        write(ws, "dist/app.jar", "jar-bytes\n");
        deployKey(ws);

        Path other = dir.resolve("other_key");
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other.toString());
        Files.writeString(ws.resolve("known_hosts"),
                "[127.0.0.1]:" + port + " " + Files.readString(dir.resolve("other_key.pub")).trim() + "\n");

        AtomResult run = upload(ws, dir.resolve("remote-badkey").toString())
                .input("sourceFiles", "dist/**/*")
                .run();

        assertNotEquals(0, run.exit(), "a bogus known_hosts entry must stop the upload");
        assertTrue(run.field("message").contains("IDENTIFICATION HAS CHANGED"),
                "the host-key warning must surface:\n" + run.toString());
    }
}

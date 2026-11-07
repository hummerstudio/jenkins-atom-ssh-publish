package com.jenkinschina.atom.sshpublish;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Glob;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Copy files to another machine over SSH, keeping the directory structure.
 *
 * <p>The publish-over-ssh plugin drives scp/rsync and a pile of transfer options; the useful core is "these files
 * end up over there, with their paths intact". This builds one tar stream in memory and feeds it to
 * {@code ssh host 'tar -xf -'}, which needs nothing on the far side but sshd and tar, and is one connection
 * instead of one per file.
 */
public class SshPublishAtom implements AtomTask {

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        Path workspace = context.getWorkspace();
        String host = context.getParam("host", "").trim();
        String user = context.getParam("user", "").trim();
        String port = context.getParam("port", "22").trim();
        String remoteDir = context.getParam("remoteDir", "").trim();
        String sourceFiles = context.getParam("sourceFiles", "**/*");
        String exclude = context.getParam("exclude", "");
        String baseDir = context.getParam("baseDir", "").trim();
        String keyFile = context.getParam("keyFile", "").trim();
        String knownHosts = context.getParam("knownHostsFile", "").trim();
        String strict = context.getParam("strictHostKeyChecking", "accept-new").trim();
        String key = context.getSecret("key");
        boolean deleteRemote = context.getBooleanParam("deleteRemote", false);
        int timeoutSeconds = Math.max(5, Math.min(context.getIntParam("timeoutSeconds", 120), 3600));

        if (host.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001, "host is required");
        }
        if (user.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40002, "user is required");
        }
        if (remoteDir.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40003, "remoteDir is required");
        }
        if (remoteDir.equals("/") || remoteDir.equals("*")) {
            return AtomResult.error(ErrorType.USER, 40004,
                    "remoteDir must be a real directory, not '" + remoteDir + "'");
        }
        if (!port.matches("\\d+")) {
            return AtomResult.error(ErrorType.USER, 40005, "port must be a number");
        }

        Path base = baseDir.isEmpty() ? workspace : workspace.resolve(baseDir).normalize();
        if (!base.startsWith(workspace) || !Files.isDirectory(base)) {
            return AtomResult.error(ErrorType.USER, 40006, "baseDir must be a directory inside the workspace");
        }

        List<Path> files = collect(base, sourceFiles, exclude);
        if (files.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40007,
                    "no file matched '" + sourceFiles + "'" + (exclude.isBlank() ? "" : " (excluding " + exclude + ")"));
        }

        byte[] archive = tar(base, files);
        Path keyPath = null;
        try {
            String keyOption = null;
            if (!keyFile.isEmpty()) {
                keyPath = workspace.resolve(keyFile).normalize();
                if (!Files.isRegularFile(keyPath)) {
                    return AtomResult.error(ErrorType.USER, 40008, "no private key at " + keyFile);
                }
                keyOption = keyPath.toString();
            } else if (key != null && !key.isBlank()) {
                keyPath = createOwnerOnlyTempFile("atom-ssh-", ".key");
                Files.writeString(keyPath, key.endsWith("\n") ? key : key + "\n", StandardCharsets.UTF_8);
                setOwnerOnly(keyPath);
                keyOption = keyPath.toString();
            }

            List<String> command = new ArrayList<>();
            command.add("ssh");
            command.add("-p");
            command.add(port);
            command.add("-o");
            command.add("BatchMode=yes");
            command.add("-o");
            command.add("StrictHostKeyChecking=" + (strict.isEmpty() ? "accept-new" : strict));
            // Debian/Ubuntu default to hashed known_hosts, which reads as "the key was never recorded" to a human
            // and to every script that greps the file. Keep the entries readable.
            command.add("-o");
            command.add("HashKnownHosts=no");
            if (!knownHosts.isEmpty()) {
                Path known = workspace.resolve(knownHosts).normalize();
                Files.createDirectories(known.getParent() == null ? workspace : known.getParent());
                if (!Files.exists(known)) {
                    Files.writeString(known, "", StandardCharsets.UTF_8);
                }
                command.add("-o");
                command.add("UserKnownHostsFile=" + known);
            }
            command.add("-o");
            command.add("ConnectTimeout=10");
            if (keyOption != null) {
                command.add("-i");
                command.add(keyOption);
            }
            command.add(user + "@" + host);

            String target = shellQuote(remoteDir);
            StringBuilder remote = new StringBuilder("mkdir -p " + target + " && ");
            if (deleteRemote) {
                // only inside a real path, and never the directory itself
                remote.append("find ").append(target).append(" -mindepth 1 -delete && ");
            }
            remote.append("tar -xf - -C ").append(target);
            command.add(remote.toString());

            context.log("[ssh] " + files.size() + " file(s), " + archive.length + " bytes -> "
                    + user + "@" + host + ":" + remoteDir);
            Result result = run(command, archive, timeoutSeconds);
            if (result.exit != 0) {
                String message = result.stderr.isBlank() ? result.stdout : result.stderr;
                ErrorType type = message.contains("Permission denied") || message.contains("Host key verification")
                        || message.contains("IDENTIFICATION HAS CHANGED") || message.contains("No such file or directory")
                                ? ErrorType.USER : ErrorType.ENVIRONMENT;
                return AtomResult.error(type, 40009, "ssh failed (exit " + result.exit + "): "
                        + oneLine(message));
            }
            return AtomResult.success()
                    .data("filesUploaded", String.valueOf(files.size()))
                    .data("bytes", String.valueOf(archive.length))
                    .data("remoteDir", remoteDir)
                    .data("host", host);
        } finally {
            if (keyPath != null && key != null && !key.isBlank()) {
                Files.deleteIfExists(keyPath);
            }
        }
    }

    /** Files under {@code base} matching any pattern in {@code sourceFiles}, minus anything in {@code exclude}. */

    /**
     * The runner keeps {@code input.json}, {@code .secrets.json} and {@code output.json} under
     * {@code .atoms/<runId>/}. An upload pattern of {@code **}{@code /*} would otherwise ship a credential file to a
     * remote host, so the runner's scratch directory is never part of the payload.
     */
    static boolean isRunnerScratch(String relative) {
        return relative.startsWith(".atoms/") || relative.equals(".atoms")
                || relative.endsWith("/.secrets.json") || relative.equals(".secrets.json");
    }

    private static List<Path> collect(Path base, String sourceFiles, String exclude) throws IOException {
        List<String> patterns = split(sourceFiles);
        List<String> excluded = split(exclude);
        Set<Path> matches = new LinkedHashSet<>();
        for (String pattern : patterns) {
            for (Path found : Glob.find(base, pattern)) {
                if (Files.isRegularFile(found)) {
                    matches.add(found.normalize());
                }
            }
            if (patterns.size() == 1 && matches.isEmpty()) {
                // a plain path is also an answer: "dist/app.jar" should not need a glob
                Path literal = base.resolve(pattern).normalize();
                if (literal.startsWith(base) && Files.isRegularFile(literal)) {
                    matches.add(literal);
                }
            }
        }
        List<Path> kept = new ArrayList<>();
        for (Path candidate : matches) {
            String relative = base.relativize(candidate).toString().replace('\\', '/');
            if (isRunnerScratch(relative)) {
                continue;
            }
            boolean skip = false;
            for (String pattern : excluded) {
                if (matchesPattern(relative, pattern)) {
                    skip = true;
                    break;
                }
            }
            if (!skip) {
                kept.add(candidate);
            }
        }
        return kept;
    }

    private static boolean matchesPattern(String relative, String pattern) {
        String regex = pattern.replace(".", "\\.").replace("**", "\u0000").replace("*", "[^/]*")
                .replace("\u0000", ".*").replace("?", ".");
        return relative.matches(regex) || relative.matches(".*/" + regex);
    }

    private static List<String> split(String value) {
        List<String> out = new ArrayList<>();
        for (String part : value.split("[,\\n]")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out;
    }

    /* ---------------------------------------------------------------- tar */

    /** ustar, no compression: ssh already encrypts, and tar is on every POSIX box. */
    static byte[] tar(Path base, List<Path> files) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] block = new byte[512];
        for (Path file : files) {
            String name = base.relativize(file).toString().replace('\\', '/');
            long size = Files.size(file);
            byte[] header = new byte[512];
            put(header, 0, 100, name);
            put(header, 100, 8, String.format(Locale.ROOT, "%07o", 0644));
            put(header, 108, 8, String.format(Locale.ROOT, "%07o", 0));
            put(header, 116, 8, String.format(Locale.ROOT, "%07o", 0));
            put(header, 124, 12, String.format(Locale.ROOT, "%011o", size));
            put(header, 136, 12, String.format(Locale.ROOT, "%011o", Files.getLastModifiedTime(file).toMillis() / 1000));
            put(header, 148, 8, "        "); // checksum is computed with this field blank
            header[156] = '0';              // regular file
            put(header, 257, 6, "ustar");
            put(header, 263, 2, "00");
            long sum = 0;
            for (byte value : header) {
                sum += value & 0xff;
            }
            put(header, 148, 8, String.format(Locale.ROOT, "%06o", sum) + "\u0000 ");

            out.write(header);
            try (var in = Files.newInputStream(file)) {
                in.transferTo(out);
            }
            int pad = (int) ((512 - (size % 512)) % 512);
            if (pad > 0) {
                out.write(new byte[pad]);
            }
        }
        out.write(block);
        out.write(block);
        return out.toByteArray();
    }

    private static void put(byte[] target, int offset, int length, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        System.arraycopy(bytes, 0, target, offset, Math.min(bytes.length, length));
    }

    /* ---------------------------------------------------------------- process */

    private record Result(int exit, String stdout, String stderr) {}

    private static Result run(List<String> command, byte[] stdin, int timeoutSeconds) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(command);
        Process process = builder.start();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        Thread outReader = pump(process.getInputStream(), out);
        Thread errReader = pump(process.getErrorStream(), err);
        try (OutputStream input = process.getOutputStream()) {
            input.write(stdin);
        } catch (IOException e) {
            // the far side may close early (a bad key, a full disk); the exit code tells the story
        }
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            return new Result(124, "", "timed out after " + timeoutSeconds + "s");
        }
        outReader.join(5000);
        errReader.join(5000);
        return new Result(process.exitValue(), out.toString(StandardCharsets.UTF_8),
                err.toString(StandardCharsets.UTF_8));
    }

    private static Thread pump(java.io.InputStream stream, ByteArrayOutputStream sink) {
        Thread thread = new Thread(() -> {
            try (stream) {
                stream.transferTo(sink);
            } catch (IOException ignored) {
                // the process went away; the exit code is the signal
            }
        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    /**
     * The key lands in a file nobody else can read: 0600 from creation, so there is no window where the private key
     * is readable by another account. A filesystem without POSIX modes has no group/world bit to drop, so the
     * attribute is left off there.
     */
    private static Path createOwnerOnlyTempFile(String prefix, String suffix) throws IOException {
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            return Files.createTempFile(prefix, suffix,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        }
        return Files.createTempFile(prefix, suffix, new FileAttribute<?>[0]);
    }

    private static void setOwnerOnly(Path file) {
        try {
            Files.setPosixFilePermissions(file, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (IOException | UnsupportedOperationException ignored) {
            // windows or a filesystem without POSIX modes: ssh will complain about the key, not us
        }
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String oneLine(String value) {
        String flat = value.replaceAll("\\s+", " ").trim();
        return flat.length() > 300 ? flat.substring(0, 300) + "…" : flat;
    }
}

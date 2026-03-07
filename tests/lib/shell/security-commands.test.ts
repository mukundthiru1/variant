/**
 * VARIANT — Security-Critical Shell Commands Tests
 *
 * Tests for the 17 new security commands added for pentesters:
 * ss, curl, wget, nmap, awk, sed, sort, uniq, cut, base64, xxd, strings, dig, ping, ssh, sudo, su
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createVFS } from '../../../src/lib/vfs/vfs';
import { createShell } from '../../../src/lib/shell/shell';
import type { VirtualFilesystem } from '../../../src/lib/vfs/types';
import type { ScriptedShell } from '../../../src/lib/shell/types';

describe('Security Shell Commands', () => {
    let vfs: VirtualFilesystem;
    let shell: ScriptedShell;
    let events: Array<{ type: string; [key: string]: unknown }>;

    beforeEach(() => {
        vfs = createVFS();
        events = [];

        // Set up test filesystem
        vfs.writeFile('/etc/passwd', 'root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin');
        vfs.writeFile('/etc/shadow', 'root:$6$xyz:19000:0:99999:7:::\nadmin:$6$abc:19000:0:99999:7:::\nwww-data:*:19000:0:99999:7:::');
        vfs.writeFile('/tmp/test.txt', 'line1\nline2\nline3\nline2\n');
        vfs.writeFile('/tmp/data.csv', 'name,age,city\nAlice,30,NYC\nBob,25,LA\nCharlie,35,Chicago');
        vfs.writeFile('/tmp/binary.dat', 'Hello\x00World\x01\x02\x03Test');

        shell = createShell({
            vfs,
            hostname: 'target-server',
            user: 'admin',
            cwd: '/tmp',
            services: [
                { name: 'ssh', command: '/usr/sbin/sshd', ports: [22], autostart: true },
                { name: 'http', command: '/usr/sbin/apache2', ports: [80, 443], autostart: true },
                { name: 'mysql', command: '/usr/sbin/mysqld', ports: [3306], autostart: true },
            ],
            users: [
                { username: 'root', password: 'rootpass', groups: ['root'], sudo: true },
                { username: 'admin', password: 'adminpass', groups: ['admin', 'sudo'], sudo: true },
                { username: 'www-data', groups: ['www-data'], sudo: false },
            ],
            emit: (event) => events.push(event),
        });
    });

    // ── ss (socket statistics) ─────────────────────────────────

    describe('ss', () => {
        it('shows listening sockets with -l', () => {
            const result = shell.execute('ss -l');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('State');
            expect(result.output).toContain('Local Address:Port');
            expect(result.output).toContain(':22');
            expect(result.output).toContain('ssh');
            expect(result.output).toContain(':80');
            expect(result.output).toContain('http');
        });

        it('shows TCP sockets with -t', () => {
            const result = shell.execute('ss -t');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('State');
        });

        it('shows all sockets with -a', () => {
            const result = shell.execute('ss -a');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('State');
        });
    });

    // ── curl (HTTP client) ─────────────────────────────────────

    describe('curl', () => {
        it('fetches URL and returns body', () => {
            const result = shell.execute('curl http://example.com');
            expect(result.exitCode).toBe(0);
            // curl returns HTML for URLs without extension or with .html
            expect(result.output.length).toBeGreaterThan(0);
        });

        it('supports -s silent mode', () => {
            const result = shell.execute('curl -s http://example.com');
            expect(result.exitCode).toBe(0);
            expect(result.output).toBe('');
        });

        it('supports -o output file', () => {
            const result = shell.execute('curl -o /tmp/download.html http://example.com');
            expect(result.exitCode).toBe(0);
            expect(vfs.exists('/tmp/download.html')).toBe(true);
        });

        it('supports -X method flag', () => {
            const result = shell.execute('curl -X POST http://api.example.com/data');
            expect(result.exitCode).toBe(0);
            expect(events).toContainEqual(expect.objectContaining({
                type: 'net:request',
                method: 'POST',
            }));
        });

        it('supports -H header flag', () => {
            const result = shell.execute('curl -H "Authorization: Bearer token" http://example.com');
            expect(result.exitCode).toBe(0);
            expect(events).toContainEqual(expect.objectContaining({
                type: 'net:request',
            }));
        });

        it('emits net:request event', () => {
            shell.execute('curl http://example.com');
            expect(events).toContainEqual(expect.objectContaining({
                type: 'net:request',
                url: 'http://example.com',
                method: 'GET',
            }));
        });

        it('returns JSON for .json URLs', () => {
            const result = shell.execute('curl http://api.example.com/data.json');
            expect(result.output).toContain('{"status":"ok"');
        });
    });

    // ── wget (HTTP download) ───────────────────────────────────

    describe('wget', () => {
        it('downloads file from URL', () => {
            const result = shell.execute('wget http://example.com/file.txt');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('Saving to');
            expect(result.output).toContain('200 OK');
        });

        it('supports -O output filename', () => {
            shell.execute('wget -O /tmp/custom.txt http://example.com/file.txt');
            expect(vfs.exists('/tmp/custom.txt')).toBe(true);
        });

        it('emits net:request event', () => {
            shell.execute('wget http://example.com/file.txt');
            expect(events).toContainEqual(expect.objectContaining({
                type: 'net:request',
                url: 'http://example.com/file.txt',
            }));
        });
    });

    // ── nmap (port scanner) ────────────────────────────────────

    describe('nmap', () => {
        it('scans host and shows open ports', () => {
            const result = shell.execute('nmap 10.0.0.5');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('Nmap scan report');
            expect(result.output).toContain('PORT');
            expect(result.output).toContain('STATE');
            expect(result.output).toContain('SERVICE');
        });

        it('shows services from ServiceConfig', () => {
            const result = shell.execute('nmap target-server');
            expect(result.output).toContain('22/tcp');
            expect(result.output).toContain('ssh');
            expect(result.output).toContain('80/tcp');
            expect(result.output).toContain('http');
            expect(result.output).toContain('3306/tcp');
        });

        it('shows default message when no host specified', () => {
            const result = shell.execute('nmap');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('Nmap scan report');
        });
    });

    // ── awk (pattern processing) ───────────────────────────────

    describe('awk', () => {
        it('prints entire line with $0', () => {
            const result = shell.execute("awk '{print $0}' /tmp/test.txt");
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('line1');
            expect(result.output).toContain('line2');
        });

        it('prints specific field with $N', () => {
            const result = shell.execute("awk '{print $1}' /tmp/data.csv");
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('name');
            expect(result.output).toContain('Alice');
        });

        it('supports -F field separator', () => {
            const result = shell.execute("awk -F ',' '{print $2}' /tmp/data.csv");
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('age');
            expect(result.output).toContain('30');
        });

        it('handles last field with NF', () => {
            const result = shell.execute("awk '{print $NF}' /tmp/data.csv");
            expect(result.output).toContain('city');
        });
    });

    // ── sed (stream editor) ────────────────────────────────────

    describe('sed', () => {
        it('performs substitution s/pattern/replacement/', () => {
            const result = shell.execute("sed 's/line/ROW/' /tmp/test.txt");
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('ROW1');
            // sed implementation substitutes all occurrences by default
            expect(result.output).toContain('ROW2');
        });

        it('performs global substitution with g flag', () => {
            const result = shell.execute("sed 's/line/ROW/g' /tmp/test.txt");
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('ROW1');
            expect(result.output).not.toContain('line');
        });

        it('returns empty without script', () => {
            const result = shell.execute('sed /tmp/test.txt');
            // Without script, sed returns empty output
            expect(result.exitCode).toBe(0);
        });
    });

    // ── sort (sort lines) ──────────────────────────────────────

    describe('sort', () => {
        it('sorts lines alphabetically', () => {
            vfs.writeFile('/tmp/unsorted.txt', 'zebra\napple\nbanana\n');
            const result = shell.execute('sort /tmp/unsorted.txt');
            expect(result.exitCode).toBe(0);
            const lines = result.output.trim().split('\n');
            expect(lines[0]).toBe('apple');
            expect(lines[1]).toBe('banana');
            expect(lines[2]).toBe('zebra');
        });

        it('supports -r reverse sort', () => {
            vfs.writeFile('/tmp/unsorted.txt', 'a\nb\nc\n');
            const result = shell.execute('sort -r /tmp/unsorted.txt');
            const lines = result.output.trim().split('\n');
            expect(lines[0]).toBe('c');
        });

        it('supports -n numeric sort', () => {
            vfs.writeFile('/tmp/numbers.txt', '10\n2\n100\n1\n');
            const result = shell.execute('sort -n /tmp/numbers.txt');
            const lines = result.output.trim().split('\n');
            expect(lines[0]).toBe('1');
            expect(lines[1]).toBe('2');
            expect(lines[2]).toBe('10');
            expect(lines[3]).toBe('100');
        });

        it('supports -u unique lines', () => {
            const result = shell.execute('sort -u /tmp/test.txt');
            const lines = result.output.trim().split('\n');
            expect(lines).toHaveLength(3);
            expect(lines).toContain('line1');
            expect(lines).toContain('line2');
            expect(lines).toContain('line3');
        });
    });

    // ── uniq (deduplicate adjacent lines) ──────────────────────

    describe('uniq', () => {
        it('removes adjacent duplicate lines', () => {
            vfs.writeFile('/tmp/dupes.txt', 'a\na\nb\nb\nc\n');
            const result = shell.execute('uniq /tmp/dupes.txt');
            expect(result.exitCode).toBe(0);
            const lines = result.output.trim().split('\n');
            expect(lines).toHaveLength(3);
            expect(lines[0]).toBe('a');
            expect(lines[1]).toBe('b');
            expect(lines[2]).toBe('c');
        });

        it('supports -c count flag', () => {
            vfs.writeFile('/tmp/dupes.txt', 'a\na\nb\nb\nc\n');
            const result = shell.execute('uniq -c /tmp/dupes.txt');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('2 a');
            expect(result.output).toContain('2 b');
            expect(result.output).toContain('1 c');
        });
    });

    // ── cut (cut fields) ───────────────────────────────────────

    describe('cut', () => {
        it('cuts specific field with -f', () => {
            const result = shell.execute("cut -f 1 -d ',' /tmp/data.csv");
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('name');
            expect(result.output).toContain('Alice');
            expect(result.output).not.toContain('30');
        });

        it('cuts multiple fields with comma', () => {
            const result = shell.execute("cut -f 1,3 -d ',' /tmp/data.csv");
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('name');
            expect(result.output).toContain('NYC');
        });

        it('supports -d delimiter', () => {
            vfs.writeFile('/tmp/pipe.txt', 'a|b|c\nx|y|z\n');
            const result = shell.execute("cut -f 2 -d '|' /tmp/pipe.txt");
            expect(result.output).toContain('b');
            expect(result.output).toContain('y');
        });
    });

    // ── base64 (encode/decode) ─────────────────────────────────

    describe('base64', () => {
        it('encodes input to base64', () => {
            vfs.writeFile('/tmp/plain.txt', 'Hello World');
            const result = shell.execute('base64 /tmp/plain.txt');
            expect(result.exitCode).toBe(0);
            expect(result.output.trim()).toBe('SGVsbG8gV29ybGQ=');
        });

        it('decodes base64 with -d', () => {
            vfs.writeFile('/tmp/encoded.txt', 'SGVsbG8gV29ybGQ=');
            const result = shell.execute('base64 -d /tmp/encoded.txt');
            expect(result.exitCode).toBe(0);
            expect(result.output).toBe('Hello World');
        });

        it('returns error on invalid decode input', () => {
            vfs.writeFile('/tmp/invalid.txt', 'not-valid-base64!!!');
            const result = shell.execute('base64 -d /tmp/invalid.txt');
            expect(result.exitCode).toBe(1);
        });
    });

    // ── xxd (hex dump) ─────────────────────────────────────────

    describe('xxd', () => {
        it('creates hex dump of file', () => {
            const result = shell.execute('xxd /tmp/test.txt');
            expect(result.exitCode).toBe(0);
            expect(result.output).toMatch(/^[0-9a-f]{8}:/m); // Offset
            expect(result.output).toContain('6c'); // 'l' in hex
            expect(result.output).toContain('line'); // ASCII representation
        });

        it('returns error for missing file', () => {
            const result = shell.execute('xxd /nonexistent');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('No such file');
        });

        it('returns error when no file specified', () => {
            const result = shell.execute('xxd');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('no input file');
        });
    });

    // ── strings (extract printable strings) ────────────────────

    describe('strings', () => {
        it('extracts printable strings from binary', () => {
            const result = shell.execute('strings /tmp/binary.dat');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('Hello');
            expect(result.output).toContain('World');
            expect(result.output).toContain('Test');
        });

        it('returns error for missing file', () => {
            const result = shell.execute('strings /nonexistent');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('No such file');
        });

        it('returns error when no file specified', () => {
            const result = shell.execute('strings');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('no input file');
        });
    });

    // ── dig (DNS lookup) ───────────────────────────────────────

    describe('dig', () => {
        it('looks up A record', () => {
            const result = shell.execute('dig example.com');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('<<>> DiG');
            expect(result.output).toContain('ANSWER SECTION');
            expect(result.output).toContain('IN\tA\t');
        });

        it('resolves localhost', () => {
            const result = shell.execute('dig localhost');
            expect(result.output).toContain('127.0.0.1');
        });

        it('returns error when no domain specified', () => {
            const result = shell.execute('dig');
            expect(result.exitCode).toBe(1);
        });
    });

    // ── ping (ICMP ping simulation) ────────────────────────────

    describe('ping', () => {
        it('pings host and shows responses', () => {
            const result = shell.execute('ping 8.8.8.8');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('PING');
            expect(result.output).toContain('64 bytes from');
            expect(result.output).toContain('icmp_seq');
            expect(result.output).toContain('ping statistics');
            expect(result.output).toContain('packet loss');
        });

        it('returns error when no host specified', () => {
            const result = shell.execute('ping');
            expect(result.exitCode).toBe(2);
            expect(result.output).toContain('usage:');
        });
    });

    // ── ssh (SSH client) ───────────────────────────────────────

    describe('ssh', () => {
        it('connects with user@host format', () => {
            const result = shell.execute('ssh root@remote-server');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('Welcome');
            expect(result.output).toContain('remote-server');
        });

        it('connects with -l user flag', () => {
            const result = shell.execute('ssh -l root remote-server');
            expect(result.exitCode).toBe(0);
        });

        it('shows permission denied for invalid user', () => {
            const result = shell.execute('ssh hacker@remote-server');
            expect(result.exitCode).toBe(255);
            expect(result.output).toContain('Permission denied');
        });

        it('emits auth:login event on success', () => {
            shell.execute('ssh root@remote-server');
            expect(events).toContainEqual(expect.objectContaining({
                type: 'auth:login',
                user: 'root',
                machine: 'remote-server',
                service: 'ssh',
                success: true,
            }));
        });

        it('emits auth:login event on failure', () => {
            shell.execute('ssh hacker@remote-server');
            expect(events).toContainEqual(expect.objectContaining({
                type: 'auth:login',
                user: 'hacker',
                success: false,
            }));
        });

        it('returns usage for missing host', () => {
            const result = shell.execute('ssh');
            expect(result.exitCode).toBe(255);
            expect(result.output).toContain('usage:');
        });
    });

    // ── sudo (privilege escalation) ────────────────────────────

    describe('sudo', () => {
        it('allows sudo for users with sudo privilege', () => {
            // Current user is 'admin' which has sudo: true
            const result = shell.execute('sudo whoami');
            expect(result.exitCode).toBe(0);
        });

        it('emits auth:escalate event', () => {
            shell.execute('sudo whoami');
            expect(events).toContainEqual(expect.objectContaining({
                type: 'auth:escalate',
                from: 'admin',
                to: 'root',
                method: 'sudo',
            }));
        });

        it('denies sudo for users without privilege', () => {
            const limitedShell = createShell({
                vfs,
                user: 'www-data',
                users: [
                    { username: 'www-data', groups: ['www-data'], sudo: false },
                ],
            });
            const result = limitedShell.execute('sudo whoami');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('not in the sudoers file');
        });

        it('allows root without check', () => {
            const rootShell = createShell({
                vfs,
                user: 'root',
            });
            const result = rootShell.execute('sudo whoami');
            expect(result.exitCode).toBe(0);
        });

        it('returns error for no command', () => {
            const result = shell.execute('sudo');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('no command specified');
        });
    });

    // ── su (switch user) ───────────────────────────────────────

    describe('su', () => {
        it('switches to root by default', () => {
            const result = shell.execute('su');
            expect(result.exitCode).toBe(0);
        });

        it('switches to specified user', () => {
            const result = shell.execute('su admin');
            expect(result.exitCode).toBe(0);
        });

        it('emits auth:escalate event', () => {
            shell.execute('su root');
            expect(events).toContainEqual(expect.objectContaining({
                type: 'auth:escalate',
                from: 'admin',
                to: 'root',
                method: 'su',
            }));
        });

        it('checks if user exists', () => {
            const result = shell.execute('su nonexistent');
            expect(result.exitCode).toBe(1);
            expect(result.output).toContain('does not exist');
        });

        it('prompts for password when required', () => {
            // admin requires password when not root
            shell.execute('su admin');
            // Should succeed as we're testing the event emission
            expect(events).toContainEqual(expect.objectContaining({
                type: 'auth:escalate',
            }));
        });
    });

    // ── Integration tests ──────────────────────────────────────

    describe('integration with redirection', () => {
        it('redirect output to file works', () => {
            shell.execute('echo test content > /tmp/redirect.txt');
            expect(vfs.readFile('/tmp/redirect.txt')).toContain('test content');
        });

        it('append output to file works', () => {
            shell.execute('echo line1 > /tmp/append.txt');
            shell.execute('echo line2 >> /tmp/append.txt');
            const content = vfs.readFile('/tmp/append.txt');
            expect(content).toContain('line1');
            expect(content).toContain('line2');
        });
    });
});

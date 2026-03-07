import { describe, it, expect, beforeEach } from 'vitest';
import { createMemoryForensicsEngine } from '../../../src/lib/memory';
import type { MemoryForensicsEngine } from '../../../src/lib/memory';

describe('Memory Forensics Engine', () => {
    let engine: MemoryForensicsEngine;

    beforeEach(() => {
        engine = createMemoryForensicsEngine();
    });

    // ── Process Management ───────────────────────────────────

    it('adds and retrieves processes', () => {
        engine.addProcess({
            pid: 1, name: 'init', ppid: 0, user: 'root',
            commandLine: '/sbin/init', hidden: false, injected: false, hollowed: false,
            regions: [{ baseAddress: '0x400000', size: 4096, type: 'code', protection: 'r-x' }],
        });
        const proc = engine.getProcess(1);
        expect(proc).not.toBeNull();
        expect(proc!.name).toBe('init');
        expect(proc!.pid).toBe(1);
    });

    it('returns null for unknown PID', () => {
        expect(engine.getProcess(9999)).toBeNull();
    });

    it('listProcesses excludes hidden by default', () => {
        engine.addProcess({
            pid: 1, name: 'init', ppid: 0, user: 'root', commandLine: '/sbin/init',
            hidden: false, injected: false, hollowed: false, regions: [],
        });
        engine.addProcess({
            pid: 666, name: 'rootkit', ppid: 1, user: 'root', commandLine: './rootkit',
            hidden: true, injected: false, hollowed: false, regions: [],
        });
        expect(engine.listProcesses()).toHaveLength(1);
        expect(engine.listProcesses(true)).toHaveLength(2);
    });

    // ── String Extraction ────────────────────────────────────

    it('extractStrings returns content from regions', () => {
        engine.addProcess({
            pid: 100, name: 'app', ppid: 1, user: 'www', commandLine: './app',
            hidden: false, injected: false, hollowed: false,
            regions: [
                { baseAddress: '0x7fff0000', size: 4096, type: 'heap', protection: 'rw-', content: 'password=secret123' },
                { baseAddress: '0x7fff1000', size: 4096, type: 'heap', protection: 'rw-', content: 'https://api.example.com/data' },
            ],
        });
        const strings = engine.extractStrings(100);
        expect(strings).toHaveLength(2);
        expect(strings).toContain('password=secret123');
    });

    it('extractStrings returns empty for unknown PID', () => {
        expect(engine.extractStrings(9999)).toHaveLength(0);
    });

    // ── Injection Scanning ───────────────────────────────────

    it('detects RWX memory regions', () => {
        engine.addProcess({
            pid: 200, name: 'svchost.exe', ppid: 1, user: 'SYSTEM', commandLine: 'svchost.exe',
            hidden: false, injected: false, hollowed: false,
            regions: [
                { baseAddress: '0x10000', size: 65536, type: 'private', protection: 'rwx' },
            ],
        });
        const artifacts = engine.scanInjection();
        const rwx = artifacts.find(a => a.type === 'injected_code');
        expect(rwx).toBeDefined();
        expect(rwx!.severity).toBe('high');
        expect(rwx!.mitre).toBe('T1055');
    });

    it('detects injected process flag', () => {
        engine.addProcess({
            pid: 300, name: 'explorer.exe', ppid: 1, user: 'user', commandLine: 'explorer.exe',
            hidden: false, injected: true, hollowed: false, regions: [],
        });
        const artifacts = engine.scanInjection();
        const inj = artifacts.find(a => a.type === 'dll_injection');
        expect(inj).toBeDefined();
        expect(inj!.severity).toBe('critical');
        expect(inj!.mitre).toBe('T1055.001');
    });

    it('detects hollowed process', () => {
        engine.addProcess({
            pid: 400, name: 'notepad.exe', ppid: 1, user: 'user', commandLine: 'notepad.exe',
            hidden: false, injected: false, hollowed: true, regions: [],
        });
        const artifacts = engine.scanInjection();
        const hollow = artifacts.find(a => a.type === 'process_hollowing');
        expect(hollow).toBeDefined();
        expect(hollow!.mitre).toBe('T1055.012');
    });

    it('detects suspicious strings (mimikatz)', () => {
        engine.addProcess({
            pid: 500, name: 'proc', ppid: 1, user: 'admin', commandLine: 'proc',
            hidden: false, injected: false, hollowed: false,
            regions: [
                { baseAddress: '0x20000', size: 4096, type: 'heap', protection: 'rw-', content: 'sekurlsa::logonpasswords' },
            ],
        });
        const artifacts = engine.scanInjection();
        const suspicious = artifacts.find(a => a.type === 'shellcode');
        expect(suspicious).toBeDefined();
        expect(suspicious!.severity).toBe('high');
    });

    // ── Hidden Process Scanning ──────────────────────────────

    it('detects hidden processes', () => {
        engine.addProcess({
            pid: 666, name: 'rootkit', ppid: 0, user: 'root', commandLine: './rootkit',
            hidden: true, injected: false, hollowed: false, regions: [],
        });
        const artifacts = engine.scanHiddenProcesses();
        expect(artifacts).toHaveLength(1);
        expect(artifacts[0]!.type).toBe('hidden_process');
        expect(artifacts[0]!.mitre).toBe('T1014');
    });

    it('no hidden process artifacts when none are hidden', () => {
        engine.addProcess({
            pid: 1, name: 'init', ppid: 0, user: 'root', commandLine: '/sbin/init',
            hidden: false, injected: false, hollowed: false, regions: [],
        });
        expect(engine.scanHiddenProcesses()).toHaveLength(0);
    });

    // ── Credential Scanning ──────────────────────────────────

    it('detects credentials in memory', () => {
        engine.addProcess({
            pid: 100, name: 'app', ppid: 1, user: 'www', commandLine: './app',
            hidden: false, injected: false, hollowed: false,
            regions: [
                { baseAddress: '0x30000', size: 4096, type: 'heap', protection: 'rw-', content: 'DB_PASSWORD=hunter2' },
            ],
        });
        const artifacts = engine.scanCredentials();
        const cred = artifacts.find(a => a.type === 'credential');
        expect(cred).toBeDefined();
        expect(cred!.severity).toBe('high');
    });

    it('detects crypto keys in memory', () => {
        engine.addProcess({
            pid: 101, name: 'ssh', ppid: 1, user: 'root', commandLine: 'sshd',
            hidden: false, injected: false, hollowed: false,
            regions: [
                { baseAddress: '0x40000', size: 4096, type: 'heap', protection: 'rw-', content: '-----BEGIN RSA PRIVATE KEY-----\nMIIE...' },
            ],
        });
        const artifacts = engine.scanCredentials();
        const key = artifacts.find(a => a.type === 'crypto_key');
        expect(key).toBeDefined();
        expect(key!.mitre).toBe('T1552.004');
    });

    it('detects URLs in memory', () => {
        engine.addProcess({
            pid: 102, name: 'browser', ppid: 1, user: 'user', commandLine: 'firefox',
            hidden: false, injected: false, hollowed: false,
            regions: [
                { baseAddress: '0x50000', size: 4096, type: 'heap', protection: 'rw-', content: 'callback to https://c2.evil.com/beacon' },
            ],
        });
        const artifacts = engine.scanCredentials();
        const url = artifacts.find(a => a.type === 'url');
        expect(url).toBeDefined();
        expect(url!.data).toContain('https://c2.evil.com');
    });

    it('detects AWS access keys', () => {
        engine.addProcess({
            pid: 103, name: 'aws-cli', ppid: 1, user: 'user', commandLine: 'aws s3 ls',
            hidden: false, injected: false, hollowed: false,
            regions: [
                { baseAddress: '0x60000', size: 4096, type: 'heap', protection: 'rw-', content: 'AKIAIOSFODNN7EXAMPLE' },
            ],
        });
        const artifacts = engine.scanCredentials();
        const awsKey = artifacts.find(a => a.type === 'crypto_key');
        expect(awsKey).toBeDefined();
    });

    // ── Full Scan ────────────────────────────────────────────

    it('fullScan combines all scan types', () => {
        engine.addProcess({
            pid: 1, name: 'init', ppid: 0, user: 'root', commandLine: '/sbin/init',
            hidden: false, injected: false, hollowed: false, regions: [],
        });
        engine.addProcess({
            pid: 666, name: 'rootkit', ppid: 0, user: 'root', commandLine: './rootkit',
            hidden: true, injected: true, hollowed: false,
            regions: [
                { baseAddress: '0x10000', size: 4096, type: 'private', protection: 'rwx' },
                { baseAddress: '0x20000', size: 4096, type: 'heap', protection: 'rw-', content: 'password=backdoor' },
            ],
        });
        const all = engine.fullScan();
        const types = new Set(all.map(a => a.type));
        expect(types.has('hidden_process')).toBe(true);
        expect(types.has('dll_injection')).toBe(true);
        expect(types.has('injected_code')).toBe(true);
        expect(types.has('credential')).toBe(true);
    });

    // ── Memory Dump ──────────────────────────────────────────

    it('createDump creates snapshot', () => {
        engine.addProcess({
            pid: 1, name: 'init', ppid: 0, user: 'root', commandLine: '/sbin/init',
            hidden: false, injected: false, hollowed: false,
            regions: [
                { baseAddress: '0x400000', size: 8192, type: 'code', protection: 'r-x' },
                { baseAddress: '0x600000', size: 4096, type: 'heap', protection: 'rw-' },
            ],
        });
        const dump = engine.createDump();
        expect(dump.id).toBeTruthy();
        expect(dump.totalProcesses).toBe(1);
        expect(dump.totalMemoryBytes).toBe(12288);
        expect(dump.processes).toHaveLength(1);
    });

    // ── Stats ────────────────────────────────────────────────

    it('getStats returns accurate counts', () => {
        engine.addProcess({
            pid: 1, name: 'init', ppid: 0, user: 'root', commandLine: '/sbin/init',
            hidden: false, injected: false, hollowed: false,
            regions: [{ baseAddress: '0x400000', size: 4096, type: 'code', protection: 'r-x' }],
        });
        engine.addProcess({
            pid: 666, name: 'evil', ppid: 1, user: 'root', commandLine: './evil',
            hidden: true, injected: true, hollowed: true,
            regions: [{ baseAddress: '0x10000', size: 4096, type: 'private', protection: 'rwx' }],
        });

        const stats = engine.getStats();
        expect(stats.totalProcesses).toBe(2);
        expect(stats.hiddenProcesses).toBe(1);
        expect(stats.injectedProcesses).toBe(1);
        expect(stats.hollowedProcesses).toBe(1);
        expect(stats.totalMemoryRegions).toBe(2);
        expect(stats.rwxRegions).toBe(1);
        expect(stats.totalArtifactsFound).toBeGreaterThan(0);
    });
});

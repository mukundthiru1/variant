/**
 * VARIANT — FTP Service Handler tests
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createFTPService } from '../../../src/lib/services/ftp-service';
import { createVFS } from '../../../src/lib/vfs/vfs';
import { createShell } from '../../../src/lib/shell/shell';
import type { ServiceContext, ServiceRequest } from '../../../src/lib/services/types';
import type { ServiceConfig } from '../../../src/core/world/types';

function makeRequest(text: string, sourceIP: string = '10.0.0.10'): ServiceRequest {
    return {
        sourceIP,
        sourcePort: 12345,
        payload: new TextEncoder().encode(text),
        payloadText: text,
    };
}

function makeContext(): ServiceContext {
    const vfs = createVFS();
    // Set up /etc/shadow for auth
    vfs.writeFile('/etc/shadow', 'ftpuser:secret123\nanonymous:anon');
    // Set up some files for FTP
    vfs.writeFile('/home/ftpuser/readme.txt', 'Hello from FTP');
    vfs.writeFile('/srv/ftp/public.txt', 'Public file');

    const shell = createShell({ vfs, hostname: 'ftp-01' });

    return {
        vfs,
        shell,
        hostname: 'ftp-01',
        ip: '10.0.1.20',
        emit: vi.fn(),
    };
}

function makeServiceConfig(overrides?: Record<string, unknown>): ServiceConfig {
    const base: ServiceConfig = {
        name: 'ftp',
        command: 'vsftpd',
        ports: [21],
        autostart: true,
    };
    if (overrides !== undefined) {
        return { ...base, config: overrides };
    }
    return base;
}

function decode(payload: Uint8Array): string {
    return new TextDecoder().decode(payload);
}

describe('FTPService', () => {
    let ctx: ServiceContext;

    beforeEach(() => {
        ctx = makeContext();
    });

    it('returns banner on empty request', () => {
        const service = createFTPService(makeServiceConfig());
        const response = service.handle(makeRequest(''), ctx);
        expect(response).not.toBeNull();
        const text = decode(response!.payload);
        expect(text).toContain('220');
        expect(text).toContain('vsFTPd');
    });

    it('authenticates with valid USER/PASS', () => {
        const service = createFTPService(makeServiceConfig());

        const userResp = service.handle(makeRequest('USER ftpuser'), ctx);
        expect(decode(userResp!.payload)).toContain('331');

        const passResp = service.handle(makeRequest('PASS secret123'), ctx);
        expect(decode(passResp!.payload)).toContain('230');
        expect(decode(passResp!.payload)).toContain('Login successful');
    });

    it('rejects invalid password', () => {
        const service = createFTPService(makeServiceConfig());

        service.handle(makeRequest('USER ftpuser'), ctx);
        const passResp = service.handle(makeRequest('PASS wrongpass'), ctx);
        expect(decode(passResp!.payload)).toContain('530');
        expect(decode(passResp!.payload)).toContain('Login incorrect');
    });

    it('requires USER before PASS', () => {
        const service = createFTPService(makeServiceConfig());
        const resp = service.handle(makeRequest('PASS secret123'), ctx);
        expect(decode(resp!.payload)).toContain('503');
    });

    it('allows anonymous login when configured', () => {
        const service = createFTPService(makeServiceConfig({ allowAnonymous: true }));
        const resp = service.handle(makeRequest('USER anonymous'), ctx);
        expect(decode(resp!.payload)).toContain('230');
        expect(decode(resp!.payload)).toContain('Login successful');
    });

    it('denies anonymous login when not configured', () => {
        const service = createFTPService(makeServiceConfig({ allowAnonymous: false }));
        const resp = service.handle(makeRequest('USER anonymous'), ctx);
        expect(decode(resp!.payload)).toContain('331');
    });

    it('returns PWD after authentication', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);

        const pwdResp = service.handle(makeRequest('PWD'), ctx);
        expect(decode(pwdResp!.payload)).toContain('257');
        expect(decode(pwdResp!.payload)).toContain('/home/ftpuser');
    });

    it('denies PWD without authentication', () => {
        const service = createFTPService(makeServiceConfig());
        const resp = service.handle(makeRequest('PWD'), ctx);
        expect(decode(resp!.payload)).toContain('530');
    });

    it('changes directory with CWD', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);

        const cwdResp = service.handle(makeRequest('CWD /tmp'), ctx);
        expect(decode(cwdResp!.payload)).toContain('250');

        const pwdResp = service.handle(makeRequest('PWD'), ctx);
        expect(decode(pwdResp!.payload)).toContain('/tmp');
    });

    it('retrieves file with RETR', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);

        const retrResp = service.handle(makeRequest('RETR /home/ftpuser/readme.txt'), ctx);
        const text = decode(retrResp!.payload);
        expect(text).toContain('150');
        expect(text).toContain('Hello from FTP');
        expect(text).toContain('226');
    });

    it('returns 550 for missing file on RETR', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);

        const retrResp = service.handle(makeRequest('RETR /nonexistent.txt'), ctx);
        expect(decode(retrResp!.payload)).toContain('550');
    });

    it('handles STOR command', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);

        const storResp = service.handle(makeRequest('STOR /home/ftpuser/upload.txt'), ctx);
        expect(decode(storResp!.payload)).toContain('226');
    });

    it('handles SYST command', () => {
        const service = createFTPService(makeServiceConfig());
        const resp = service.handle(makeRequest('SYST'), ctx);
        expect(decode(resp!.payload)).toContain('215');
        expect(decode(resp!.payload)).toContain('UNIX');
    });

    it('handles FEAT command', () => {
        const service = createFTPService(makeServiceConfig());
        const resp = service.handle(makeRequest('FEAT'), ctx);
        const text = decode(resp!.payload);
        expect(text).toContain('211');
        expect(text).toContain('PASV');
        expect(text).toContain('UTF8');
    });

    it('handles QUIT and closes connection', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);

        const quitResp = service.handle(makeRequest('QUIT'), ctx);
        expect(decode(quitResp!.payload)).toContain('221');
        expect(quitResp!.close).toBe(true);
    });

    it('returns 502 for unknown commands', () => {
        const service = createFTPService(makeServiceConfig());
        const resp = service.handle(makeRequest('UNKNOWN'), ctx);
        expect(decode(resp!.payload)).toContain('502');
    });

    it('emits login events on successful auth', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);

        expect(ctx.emit).toHaveBeenCalledWith(
            expect.objectContaining({
                type: 'service:custom',
                service: 'ftp',
                action: 'login',
                details: expect.objectContaining({ username: 'ftpuser', success: true }),
            }),
        );
    });

    it('emits download events on RETR', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);
        service.handle(makeRequest('RETR /home/ftpuser/readme.txt'), ctx);

        expect(ctx.emit).toHaveBeenCalledWith(
            expect.objectContaining({
                type: 'service:custom',
                service: 'ftp',
                action: 'download',
                details: expect.objectContaining({ path: '/home/ftpuser/readme.txt' }),
            }),
        );
    });

    it('maintains per-IP sessions', () => {
        const service = createFTPService(makeServiceConfig());

        // Authenticate IP1
        service.handle(makeRequest('USER ftpuser', '10.0.0.1'), ctx);
        service.handle(makeRequest('PASS secret123', '10.0.0.1'), ctx);

        // IP2 should not be authenticated
        const resp = service.handle(makeRequest('PWD', '10.0.0.2'), ctx);
        expect(decode(resp!.payload)).toContain('530');
    });

    it('clears sessions on stop', () => {
        const service = createFTPService(makeServiceConfig());
        service.handle(makeRequest('USER ftpuser'), ctx);
        service.handle(makeRequest('PASS secret123'), ctx);

        service.stop?.();

        // After stop, session should be gone — new request is unauthenticated
        const resp = service.handle(makeRequest('PWD'), ctx);
        expect(decode(resp!.payload)).toContain('530');
    });

    it('respects allowedUsers config', () => {
        const service = createFTPService(makeServiceConfig({ allowedUsers: ['admin'] }));

        service.handle(makeRequest('USER ftpuser'), ctx);
        const resp = service.handle(makeRequest('PASS secret123'), ctx);
        expect(decode(resp!.payload)).toContain('530');
    });
});

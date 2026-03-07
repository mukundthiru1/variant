/**
 * VARIANT — Credential Ecosystem tests
 */
import { describe, it, expect } from 'vitest';
import { generateCredentialEcosystem } from '../../../src/lib/creds/types';

const basicConfig = {
    hostname: 'web-01',
    domain: 'corp.local',
    users: [
        { username: 'root', uid: 0, gid: 0, home: '/root', shell: '/bin/bash', password: 'toor123', sudo: true, gecos: 'root' },
        { username: 'admin', uid: 1000, gid: 1000, home: '/home/admin', shell: '/bin/bash', password: 'admin456', sudo: true, groups: ['sudo', 'adm'] as readonly string[] },
        { username: 'www-data', uid: 33, gid: 33, home: '/var/www', shell: '/usr/sbin/nologin', locked: true },
        { username: 'deploy', uid: 1001, gid: 1001, home: '/home/deploy', shell: '/bin/bash', password: 'deploypass' },
    ],
    hosts: [
        { ip: '10.0.1.10', hostname: 'web-01.corp.local', aliases: ['web-01'] as readonly string[] },
        { ip: '10.0.1.20', hostname: 'db-01.corp.local', aliases: ['db-01'] as readonly string[] },
    ],
    nameservers: ['10.0.0.1', '8.8.8.8'],
    sshTrust: [
        { fromUser: 'deploy', toUser: 'deploy', keyId: 'deploy-key-1' },
        { fromUser: 'admin', toUser: 'root', keyId: 'admin-root-key' },
    ],
    bashHistory: new Map([
        ['admin', [
            'sudo systemctl restart nginx',
            'cat /etc/app.conf',
            'mysql -u root -p',
            'cd /var/www && ls -la',
            'tail -f /var/log/auth.log',
            'ssh deploy@db-01',
        ]],
        ['deploy', [
            'git pull origin main',
            'npm install',
            'pm2 restart app',
            'cat .env',
        ]],
    ]),
    appCredentials: [
        {
            path: '/var/www/.env',
            format: 'env' as const,
            values: new Map([
                ['DB_HOST', 'db-01.corp.local'],
                ['DB_USER', 'appuser'],
                ['DB_PASS', 'S3cretDbP@ss!'],
                ['JWT_SECRET', 'my-jwt-secret-key-do-not-share'],
                ['API_KEY', 'sk-prod-abc123def456'],
            ]),
            owner: 'www-data',
        },
        {
            path: '/var/www/config/database.json',
            format: 'json' as const,
            values: new Map([
                ['host', 'db-01.corp.local'],
                ['port', '3306'],
                ['username', 'appuser'],
                ['password', 'S3cretDbP@ss!'],
                ['database', 'production_db'],
            ]),
            owner: 'www-data',
        },
    ],
    configFiles: new Map([
        ['/etc/nginx/nginx.conf', {
            content: 'worker_processes auto;\nevents { worker_connections 1024; }\nhttp {\n    server {\n        listen 80;\n        server_name web-01.corp.local;\n        root /var/www/public;\n    }\n}\n',
            owner: 'root',
            mode: 0o644,
        }],
    ]),
    motd: 'Welcome to web-01.corp.local\nAuthorized access only.\n',
    crontabs: new Map([
        ['root', [
            '0 2 * * * /usr/sbin/logrotate /etc/logrotate.conf',
            '*/5 * * * * /usr/local/bin/health-check.sh',
        ]],
    ]),
    services: [
        { name: 'nginx', description: 'Nginx HTTP Server', command: '/usr/sbin/nginx', enabled: true },
        { name: 'app', description: 'Node.js Application', command: '/usr/bin/node /var/www/app.js', user: 'www-data', enabled: true },
    ],
};

describe('CredentialEcosystem', () => {
    const overlay = generateCredentialEcosystem(basicConfig);

    describe('/etc/passwd', () => {
        it('generates valid passwd entries', () => {
            const passwd = overlay.files.get('/etc/passwd');
            expect(passwd).toBeDefined();
            const content = typeof passwd!.content === 'string' ? passwd!.content : '';
            expect(content).toContain('root:x:0:0');
            expect(content).toContain('admin:x:1000:1000');
            expect(content).toContain('www-data:x:33:33');
            expect(content).toContain('/usr/sbin/nologin');
        });

        it('includes system accounts', () => {
            const content = typeof overlay.files.get('/etc/passwd')!.content === 'string'
                ? overlay.files.get('/etc/passwd')!.content as string : '';
            expect(content).toContain('sshd:x:');
            expect(content).toContain('nobody:x:');
        });
    });

    describe('/etc/shadow', () => {
        it('generates hashed passwords', () => {
            const shadow = overlay.files.get('/etc/shadow');
            expect(shadow).toBeDefined();
            const content = typeof shadow!.content === 'string' ? shadow!.content : '';
            // SHA-512 format: $6$salt$hash
            expect(content).toContain('root:$6$');
            expect(content).toContain('admin:$6$');
        });

        it('locks accounts correctly', () => {
            const content = typeof overlay.files.get('/etc/shadow')!.content === 'string'
                ? overlay.files.get('/etc/shadow')!.content as string : '';
            expect(content).toContain('www-data:!:');
        });

        it('has restrictive permissions', () => {
            expect(overlay.files.get('/etc/shadow')!.mode).toBe(0o640);
        });
    });

    describe('SSH keys', () => {
        it('creates authorized_keys for trust targets', () => {
            const authKeys = overlay.files.get('/home/deploy/.ssh/authorized_keys');
            expect(authKeys).toBeDefined();
            const content = typeof authKeys!.content === 'string' ? authKeys!.content : '';
            expect(content).toContain('ssh-rsa');
        });

        it('creates private keys for trust sources', () => {
            const privKey = overlay.files.get('/home/deploy/.ssh/id_rsa');
            expect(privKey).toBeDefined();
            const content = typeof privKey!.content === 'string' ? privKey!.content : '';
            expect(content).toContain('BEGIN OPENSSH PRIVATE KEY');
            expect(content).toContain('END OPENSSH PRIVATE KEY');
        });

        it('SSH keys have correct permissions', () => {
            expect(overlay.files.get('/home/deploy/.ssh/id_rsa')!.mode).toBe(0o600);
        });
    });

    describe('bash history', () => {
        it('creates .bash_history with breadcrumbs', () => {
            const history = overlay.files.get('/home/admin/.bash_history');
            expect(history).toBeDefined();
            const content = typeof history!.content === 'string' ? history!.content : '';
            expect(content).toContain('mysql -u root -p');
            expect(content).toContain('ssh deploy@db-01');
        });

        it('history has correct permissions', () => {
            expect(overlay.files.get('/home/admin/.bash_history')!.mode).toBe(0o600);
        });
    });

    describe('application credentials', () => {
        it('generates .env files', () => {
            const envFile = overlay.files.get('/var/www/.env');
            expect(envFile).toBeDefined();
            const content = typeof envFile!.content === 'string' ? envFile!.content : '';
            expect(content).toContain('DB_PASS=S3cretDbP@ss!');
            expect(content).toContain('JWT_SECRET=my-jwt-secret-key-do-not-share');
        });

        it('generates JSON config files', () => {
            const jsonFile = overlay.files.get('/var/www/config/database.json');
            expect(jsonFile).toBeDefined();
            const content = typeof jsonFile!.content === 'string' ? jsonFile!.content : '';
            const parsed = JSON.parse(content);
            expect(parsed.password).toBe('S3cretDbP@ss!');
        });

        it('app credential files have correct owner', () => {
            expect(overlay.files.get('/var/www/.env')!.owner).toBe('www-data');
        });
    });

    describe('system files', () => {
        it('generates /etc/hostname', () => {
            const hostname = overlay.files.get('/etc/hostname');
            const content = typeof hostname!.content === 'string' ? hostname!.content : '';
            expect(content.trim()).toBe('web-01');
        });

        it('generates /etc/hosts with entries', () => {
            const hosts = overlay.files.get('/etc/hosts');
            const content = typeof hosts!.content === 'string' ? hosts!.content : '';
            expect(content).toContain('10.0.1.10');
            expect(content).toContain('db-01.corp.local');
        });

        it('generates /etc/resolv.conf', () => {
            const resolv = overlay.files.get('/etc/resolv.conf');
            const content = typeof resolv!.content === 'string' ? resolv!.content : '';
            expect(content).toContain('nameserver 10.0.0.1');
            expect(content).toContain('search corp.local');
        });

        it('generates sudoers', () => {
            const sudoers = overlay.files.get('/etc/sudoers');
            const content = typeof sudoers!.content === 'string' ? sudoers!.content : '';
            expect(content).toContain('admin ALL=(ALL:ALL) NOPASSWD: ALL');
        });

        it('generates crontabs', () => {
            const crontab = overlay.files.get('/var/spool/cron/crontabs/root');
            const content = typeof crontab!.content === 'string' ? crontab!.content : '';
            expect(content).toContain('logrotate');
            expect(content).toContain('health-check');
        });

        it('generates init scripts', () => {
            const initScript = overlay.files.get('/etc/init.d/nginx');
            expect(initScript).toBeDefined();
            expect(initScript!.mode).toBe(0o755);
        });

        it('generates custom config files', () => {
            const nginx = overlay.files.get('/etc/nginx/nginx.conf');
            const content = typeof nginx!.content === 'string' ? nginx!.content : '';
            expect(content).toContain('listen 80');
        });

        it('generates MOTD', () => {
            const motd = overlay.files.get('/etc/motd');
            const content = typeof motd!.content === 'string' ? motd!.content : '';
            expect(content).toContain('Authorized access only');
        });
    });
});

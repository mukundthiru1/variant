/**
 * VARIANT — Cloud Metadata Service
 *
 * Simulates AWS/GCP/Azure instance metadata endpoints.
 * Players learn SSRF exploitation, credential harvesting
 * from metadata, and cloud IAM abuse.
 *
 * Endpoints:
 *   AWS:   http://169.254.169.254/latest/meta-data/
 *   GCP:   http://metadata.google.internal/computeMetadata/v1/
 *   Azure: http://169.254.169.254/metadata/instance
 *
 * All data is pure simulation — no real cloud calls.
 */

// ── Types ─────────────────────────────────────────────────

export interface CloudMetadataConfig {
    readonly provider: CloudProvider;
    readonly instanceId: string;
    readonly region: string;
    readonly availabilityZone: string;
    readonly instanceType: string;
    readonly privateIP: string;
    readonly publicIP?: string;
    readonly hostname: string;
    readonly iamRole?: string;
    readonly iamCredentials?: IAMCredentials;
    readonly userData?: string;
    readonly securityGroups?: readonly string[];
    readonly vpcId?: string;
    readonly subnetId?: string;
    readonly accountId?: string;
    readonly tags?: Readonly<Record<string, string>>;
    readonly imdsV2Required?: boolean;
}

export type CloudProvider = 'aws' | 'gcp' | 'azure';

export interface IAMCredentials {
    readonly accessKeyId: string;
    readonly secretAccessKey: string;
    readonly sessionToken: string;
    readonly expiration: string;
    readonly type: string;
}

export interface MetadataRequest {
    readonly path: string;
    readonly headers?: Readonly<Record<string, string>>;
    readonly method?: string;
}

export interface MetadataResponse {
    readonly statusCode: number;
    readonly body: string;
    readonly headers: Readonly<Record<string, string>>;
    readonly contentType: string;
}

export interface CloudMetadataService {
    /** Handle a metadata request. */
    handleRequest(request: MetadataRequest): MetadataResponse;
    /** Get the provider. */
    getProvider(): CloudProvider;
    /** Get the config. */
    getConfig(): CloudMetadataConfig;
    /** Check if IMDSv2 token is required. */
    isIMDSv2Required(): boolean;
    /** Generate an IMDSv2 token. */
    generateToken(ttlSeconds: number): string;
}

// ── Factory ──────────────────────────────────────────────

export function createCloudMetadataService(config: CloudMetadataConfig): CloudMetadataService {
    const validTokens = new Set<string>();
    let tokenCounter = 0;

    function makeResponse(statusCode: number, body: string, contentType?: string): MetadataResponse {
        return {
            statusCode,
            body,
            headers: { 'Content-Type': contentType ?? 'text/plain' },
            contentType: contentType ?? 'text/plain',
        };
    }

    function make404(): MetadataResponse {
        return makeResponse(404, 'Not Found');
    }

    function make401(): MetadataResponse {
        return makeResponse(401, 'Unauthorized');
    }

    function handleAWS(path: string): MetadataResponse {
        const p = path.replace(/^\/latest\//, '').replace(/\/$/, '');

        // Top-level listing
        if (p === 'meta-data' || p === '') {
            return makeResponse(200, [
                'ami-id', 'hostname', 'instance-id', 'instance-type',
                'local-hostname', 'local-ipv4', 'placement/',
                'public-hostname', 'public-ipv4', 'security-groups',
                'iam/', 'network/', 'tags/',
            ].join('\n'));
        }

        // Instance metadata
        if (p === 'meta-data/instance-id') return makeResponse(200, config.instanceId);
        if (p === 'meta-data/instance-type') return makeResponse(200, config.instanceType);
        if (p === 'meta-data/hostname' || p === 'meta-data/local-hostname') return makeResponse(200, config.hostname);
        if (p === 'meta-data/local-ipv4') return makeResponse(200, config.privateIP);
        if (p === 'meta-data/public-ipv4') return makeResponse(200, config.publicIP ?? '');
        if (p === 'meta-data/ami-id') return makeResponse(200, `ami-${config.instanceId.slice(-8)}`);
        if (p === 'meta-data/placement/availability-zone') return makeResponse(200, config.availabilityZone);
        if (p === 'meta-data/placement/region') return makeResponse(200, config.region);
        if (p === 'meta-data/security-groups') {
            return makeResponse(200, (config.securityGroups ?? []).join('\n'));
        }

        // IAM role credentials (the juicy part for SSRF)
        if (p === 'meta-data/iam/security-credentials' || p === 'meta-data/iam/security-credentials/') {
            return makeResponse(200, config.iamRole ?? '');
        }
        if (config.iamRole && p === `meta-data/iam/security-credentials/${config.iamRole}`) {
            if (config.iamCredentials) {
                return makeResponse(200, JSON.stringify({
                    Code: 'Success',
                    LastUpdated: new Date().toISOString(),
                    Type: config.iamCredentials.type,
                    AccessKeyId: config.iamCredentials.accessKeyId,
                    SecretAccessKey: config.iamCredentials.secretAccessKey,
                    Token: config.iamCredentials.sessionToken,
                    Expiration: config.iamCredentials.expiration,
                }, null, 2), 'application/json');
            }
        }

        // User data
        if (p === 'user-data') {
            return makeResponse(200, config.userData ?? '');
        }

        // Identity document
        if (p === 'dynamic/instance-identity/document') {
            return makeResponse(200, JSON.stringify({
                accountId: config.accountId ?? '123456789012',
                instanceId: config.instanceId,
                region: config.region,
                availabilityZone: config.availabilityZone,
                instanceType: config.instanceType,
                privateIp: config.privateIP,
            }, null, 2), 'application/json');
        }

        // Tags
        if (config.tags && p.startsWith('meta-data/tags/instance/')) {
            const tagKey = p.replace('meta-data/tags/instance/', '');
            if (tagKey === '' || tagKey === '/') {
                return makeResponse(200, Object.keys(config.tags).join('\n'));
            }
            const tagValue = config.tags[tagKey];
            if (tagValue !== undefined) return makeResponse(200, tagValue);
        }

        // Network
        if (p === 'meta-data/network/interfaces/macs') {
            return makeResponse(200, '02:42:ac:11:00:02/');
        }

        // IMDSv2 token endpoint
        if (p === 'api/token') {
            return make404(); // GET not allowed for token, use PUT
        }

        return make404();
    }

    function handleGCP(path: string): MetadataResponse {
        const p = path.replace(/^\/computeMetadata\/v1\//, '').replace(/\/$/, '');

        if (p === '' || p === 'project' || p === 'instance') {
            return makeResponse(200, 'project/\ninstance/', 'text/plain');
        }

        if (p === 'instance/hostname') return makeResponse(200, config.hostname);
        if (p === 'instance/id') return makeResponse(200, config.instanceId);
        if (p === 'instance/machine-type') return makeResponse(200, `zones/${config.availabilityZone}/machineTypes/${config.instanceType}`);
        if (p === 'instance/zone') return makeResponse(200, `projects/${config.accountId ?? 'project'}/zones/${config.availabilityZone}`);
        if (p === 'instance/network-interfaces/0/ip') return makeResponse(200, config.privateIP);
        if (p === 'instance/network-interfaces/0/access-configs/0/external-ip') return makeResponse(200, config.publicIP ?? '');

        if (p === 'instance/service-accounts/' || p === 'instance/service-accounts') {
            return makeResponse(200, config.iamRole ? `${config.iamRole}/\ndefault/` : 'default/');
        }

        if (p === 'instance/service-accounts/default/token' || (config.iamRole && p === `instance/service-accounts/${config.iamRole}/token`)) {
            if (config.iamCredentials) {
                return makeResponse(200, JSON.stringify({
                    access_token: config.iamCredentials.sessionToken,
                    expires_in: 3600,
                    token_type: 'Bearer',
                }), 'application/json');
            }
        }

        if (p === 'project/project-id') return makeResponse(200, config.accountId ?? 'my-project');
        if (p === 'project/numeric-project-id') return makeResponse(200, '123456789');

        if (p === 'instance/attributes/startup-script') {
            return makeResponse(200, config.userData ?? '');
        }

        return make404();
    }

    function handleAzure(path: string): MetadataResponse {
        const p = path.replace(/^\/metadata\//, '').replace(/\/$/, '');

        if (p === 'instance' || p.startsWith('instance?')) {
            return makeResponse(200, JSON.stringify({
                compute: {
                    vmId: config.instanceId,
                    name: config.hostname,
                    vmSize: config.instanceType,
                    location: config.region,
                    osType: 'Linux',
                    subscriptionId: config.accountId ?? 'sub-123',
                    resourceGroupName: 'rg-default',
                    tags: config.tags ? Object.entries(config.tags).map(([k, v]) => `${k}:${v}`).join(';') : '',
                },
                network: {
                    interface: [{
                        ipv4: {
                            ipAddress: [{ privateIpAddress: config.privateIP, publicIpAddress: config.publicIP ?? '' }],
                        },
                    }],
                },
            }, null, 2), 'application/json');
        }

        if (p === 'identity/oauth2/token' || p.startsWith('identity/oauth2/token?')) {
            if (config.iamCredentials) {
                return makeResponse(200, JSON.stringify({
                    access_token: config.iamCredentials.sessionToken,
                    refresh_token: '',
                    expires_in: '3600',
                    expires_on: String(Math.floor(Date.now() / 1000) + 3600),
                    not_before: String(Math.floor(Date.now() / 1000)),
                    resource: 'https://management.azure.com/',
                    token_type: 'Bearer',
                }), 'application/json');
            }
        }

        return make404();
    }

    return {
        handleRequest(request: MetadataRequest): MetadataResponse {
            // IMDSv2 token generation (AWS PUT /latest/api/token)
            if (config.provider === 'aws' && request.method === 'PUT' && request.path.includes('/api/token')) {
                const ttl = parseInt(request.headers?.['X-aws-ec2-metadata-token-ttl-seconds'] ?? '21600', 10);
                const token = `imdsv2-token-${++tokenCounter}-${Date.now().toString(36)}`;
                validTokens.add(token);
                return {
                    statusCode: 200,
                    body: token,
                    headers: { 'Content-Type': 'text/plain', 'X-aws-ec2-metadata-token-ttl-seconds': String(ttl) },
                    contentType: 'text/plain',
                };
            }

            // IMDSv2 enforcement
            if (config.provider === 'aws' && config.imdsV2Required) {
                const token = request.headers?.['X-aws-ec2-metadata-token'];
                if (!token || !validTokens.has(token)) {
                    return make401();
                }
            }

            // GCP requires Metadata-Flavor header
            if (config.provider === 'gcp') {
                if (request.headers?.['Metadata-Flavor'] !== 'Google') {
                    return makeResponse(403, 'Missing Metadata-Flavor:Google header');
                }
            }

            // Azure requires Metadata header
            if (config.provider === 'azure') {
                if (request.headers?.['Metadata'] !== 'true') {
                    return makeResponse(400, 'Must include Metadata:true header');
                }
            }

            switch (config.provider) {
                case 'aws': return handleAWS(request.path);
                case 'gcp': return handleGCP(request.path);
                case 'azure': return handleAzure(request.path);
                default: return make404();
            }
        },

        getProvider(): CloudProvider {
            return config.provider;
        },

        getConfig(): CloudMetadataConfig {
            return config;
        },

        isIMDSv2Required(): boolean {
            return config.imdsV2Required ?? false;
        },

        generateToken(_ttlSeconds: number): string {
            const token = `imdsv2-token-${++tokenCounter}-${Date.now().toString(36)}`;
            validTokens.add(token);
            return token;
        },
    };
}

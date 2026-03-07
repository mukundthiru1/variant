/**
 * VARIANT — Cloud Metadata Service tests
 */
import { describe, it, expect } from 'vitest';
import { createCloudMetadataService } from '../../../src/lib/services/cloud-metadata-service';
import type { CloudMetadataConfig } from '../../../src/lib/services/cloud-metadata-service';

function makeAWSConfig(overrides?: Partial<CloudMetadataConfig>): CloudMetadataConfig {
    return {
        provider: 'aws',
        instanceId: 'i-1234567890abcdef0',
        region: 'us-east-1',
        availabilityZone: 'us-east-1a',
        instanceType: 't3.medium',
        privateIP: '10.0.1.50',
        publicIP: '54.123.45.67',
        hostname: 'ip-10-0-1-50.ec2.internal',
        iamRole: 'WebServerRole',
        iamCredentials: {
            accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
            secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            sessionToken: 'FwoGZXIvYXdzEBYaDHqa0AP1HGnKHnq...',
            expiration: '2026-03-06T12:00:00Z',
            type: 'AWS-HMAC',
        },
        securityGroups: ['sg-web-01', 'sg-default'],
        accountId: '123456789012',
        tags: { Name: 'web-server-01', Environment: 'production' },
        ...overrides,
    };
}

function makeGCPConfig(overrides?: Partial<CloudMetadataConfig>): CloudMetadataConfig {
    return {
        provider: 'gcp',
        instanceId: '1234567890123456789',
        region: 'us-central1',
        availabilityZone: 'us-central1-a',
        instanceType: 'n2-standard-2',
        privateIP: '10.128.0.2',
        hostname: 'instance-1.us-central1-a.c.project.internal',
        iamRole: 'default',
        iamCredentials: {
            accessKeyId: '',
            secretAccessKey: '',
            sessionToken: 'ya29.c.ElqBBV...',
            expiration: '',
            type: 'Bearer',
        },
        accountId: 'my-project-123',
        ...overrides,
    };
}

function makeAzureConfig(overrides?: Partial<CloudMetadataConfig>): CloudMetadataConfig {
    return {
        provider: 'azure',
        instanceId: 'vm-12345',
        region: 'eastus',
        availabilityZone: 'eastus-1',
        instanceType: 'Standard_D2s_v3',
        privateIP: '10.0.0.4',
        hostname: 'vm-web-01',
        iamCredentials: {
            accessKeyId: '',
            secretAccessKey: '',
            sessionToken: 'eyJ0eXAiOiJKV1QiLC...',
            expiration: '',
            type: 'Bearer',
        },
        accountId: 'sub-12345-6789',
        ...overrides,
    };
}

describe('CloudMetadataService', () => {
    // ── AWS ───────────────────────────────────────────────

    describe('AWS', () => {
        it('returns instance ID', () => {
            const svc = createCloudMetadataService(makeAWSConfig());
            const resp = svc.handleRequest({ path: '/latest/meta-data/instance-id' });
            expect(resp.statusCode).toBe(200);
            expect(resp.body).toBe('i-1234567890abcdef0');
        });

        it('returns private IP', () => {
            const svc = createCloudMetadataService(makeAWSConfig());
            const resp = svc.handleRequest({ path: '/latest/meta-data/local-ipv4' });
            expect(resp.body).toBe('10.0.1.50');
        });

        it('lists IAM role', () => {
            const svc = createCloudMetadataService(makeAWSConfig());
            const resp = svc.handleRequest({ path: '/latest/meta-data/iam/security-credentials/' });
            expect(resp.body).toBe('WebServerRole');
        });

        it('returns IAM credentials (SSRF target)', () => {
            const svc = createCloudMetadataService(makeAWSConfig());
            const resp = svc.handleRequest({ path: '/latest/meta-data/iam/security-credentials/WebServerRole' });
            expect(resp.statusCode).toBe(200);
            const creds = JSON.parse(resp.body);
            expect(creds.AccessKeyId).toBe('AKIAIOSFODNN7EXAMPLE');
            expect(creds.SecretAccessKey).toBeTruthy();
            expect(creds.Token).toBeTruthy();
        });

        it('returns security groups', () => {
            const svc = createCloudMetadataService(makeAWSConfig());
            const resp = svc.handleRequest({ path: '/latest/meta-data/security-groups' });
            expect(resp.body).toContain('sg-web-01');
        });

        it('returns user data', () => {
            const svc = createCloudMetadataService(makeAWSConfig({ userData: '#!/bin/bash\necho hello' }));
            const resp = svc.handleRequest({ path: '/latest/user-data' });
            expect(resp.body).toContain('#!/bin/bash');
        });

        it('returns identity document', () => {
            const svc = createCloudMetadataService(makeAWSConfig());
            const resp = svc.handleRequest({ path: '/latest/dynamic/instance-identity/document' });
            const doc = JSON.parse(resp.body);
            expect(doc.accountId).toBe('123456789012');
            expect(doc.region).toBe('us-east-1');
        });

        it('returns 404 for unknown paths', () => {
            const svc = createCloudMetadataService(makeAWSConfig());
            const resp = svc.handleRequest({ path: '/latest/meta-data/nonexistent' });
            expect(resp.statusCode).toBe(404);
        });

        it('returns metadata listing', () => {
            const svc = createCloudMetadataService(makeAWSConfig());
            const resp = svc.handleRequest({ path: '/latest/meta-data' });
            expect(resp.body).toContain('instance-id');
            expect(resp.body).toContain('iam/');
        });
    });

    // ── AWS IMDSv2 ────────────────────────────────────────

    describe('AWS IMDSv2', () => {
        it('blocks requests without token when IMDSv2 required', () => {
            const svc = createCloudMetadataService(makeAWSConfig({ imdsV2Required: true }));
            const resp = svc.handleRequest({ path: '/latest/meta-data/instance-id' });
            expect(resp.statusCode).toBe(401);
        });

        it('generates and accepts IMDSv2 tokens', () => {
            const svc = createCloudMetadataService(makeAWSConfig({ imdsV2Required: true }));

            // Get token via PUT
            const tokenResp = svc.handleRequest({
                path: '/latest/api/token',
                method: 'PUT',
                headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '21600' },
            });
            expect(tokenResp.statusCode).toBe(200);
            const token = tokenResp.body;

            // Use token
            const dataResp = svc.handleRequest({
                path: '/latest/meta-data/instance-id',
                headers: { 'X-aws-ec2-metadata-token': token },
            });
            expect(dataResp.statusCode).toBe(200);
            expect(dataResp.body).toBe('i-1234567890abcdef0');
        });

        it('allows requests without token when IMDSv1 enabled', () => {
            const svc = createCloudMetadataService(makeAWSConfig({ imdsV2Required: false }));
            const resp = svc.handleRequest({ path: '/latest/meta-data/instance-id' });
            expect(resp.statusCode).toBe(200);
        });
    });

    // ── GCP ───────────────────────────────────────────────

    describe('GCP', () => {
        it('requires Metadata-Flavor header', () => {
            const svc = createCloudMetadataService(makeGCPConfig());
            const resp = svc.handleRequest({ path: '/computeMetadata/v1/instance/hostname' });
            expect(resp.statusCode).toBe(403);
        });

        it('returns instance hostname', () => {
            const svc = createCloudMetadataService(makeGCPConfig());
            const resp = svc.handleRequest({
                path: '/computeMetadata/v1/instance/hostname',
                headers: { 'Metadata-Flavor': 'Google' },
            });
            expect(resp.statusCode).toBe(200);
            expect(resp.body).toContain('instance-1');
        });

        it('returns service account token', () => {
            const svc = createCloudMetadataService(makeGCPConfig());
            const resp = svc.handleRequest({
                path: '/computeMetadata/v1/instance/service-accounts/default/token',
                headers: { 'Metadata-Flavor': 'Google' },
            });
            expect(resp.statusCode).toBe(200);
            const data = JSON.parse(resp.body);
            expect(data.access_token).toBeTruthy();
            expect(data.token_type).toBe('Bearer');
        });

        it('returns project ID', () => {
            const svc = createCloudMetadataService(makeGCPConfig());
            const resp = svc.handleRequest({
                path: '/computeMetadata/v1/project/project-id',
                headers: { 'Metadata-Flavor': 'Google' },
            });
            expect(resp.body).toBe('my-project-123');
        });
    });

    // ── Azure ─────────────────────────────────────────────

    describe('Azure', () => {
        it('requires Metadata header', () => {
            const svc = createCloudMetadataService(makeAzureConfig());
            const resp = svc.handleRequest({ path: '/metadata/instance' });
            expect(resp.statusCode).toBe(400);
        });

        it('returns instance metadata', () => {
            const svc = createCloudMetadataService(makeAzureConfig());
            const resp = svc.handleRequest({
                path: '/metadata/instance',
                headers: { Metadata: 'true' },
            });
            expect(resp.statusCode).toBe(200);
            const data = JSON.parse(resp.body);
            expect(data.compute.vmId).toBe('vm-12345');
            expect(data.compute.name).toBe('vm-web-01');
        });

        it('returns OAuth token', () => {
            const svc = createCloudMetadataService(makeAzureConfig());
            const resp = svc.handleRequest({
                path: '/metadata/identity/oauth2/token?api-version=2018-02-01',
                headers: { Metadata: 'true' },
            });
            expect(resp.statusCode).toBe(200);
            const data = JSON.parse(resp.body);
            expect(data.access_token).toBeTruthy();
            expect(data.token_type).toBe('Bearer');
        });
    });

    // ── General ───────────────────────────────────────────

    it('reports provider correctly', () => {
        const aws = createCloudMetadataService(makeAWSConfig());
        expect(aws.getProvider()).toBe('aws');
        const gcp = createCloudMetadataService(makeGCPConfig());
        expect(gcp.getProvider()).toBe('gcp');
    });

    it('exposes config', () => {
        const svc = createCloudMetadataService(makeAWSConfig());
        expect(svc.getConfig().instanceId).toBe('i-1234567890abcdef0');
    });
});

/**
 * VARIANT — Cloud API Module Tests
 *
 * Tests for simulated cloud provider APIs: S3, IAM, Lambda,
 * STS, EC2, Secrets Manager.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { createCloudApiModule } from '../../src/modules/cloud-api';
import type { ExternalRequest, ExternalServiceHandler } from '../../src/core/fabric/types';
import type { CloudInfraSpec } from '../../src/core/world/types';

// ── Helpers ────────────────────────────────────────────────────

const decoder = new TextDecoder();

function makeRequest(method: string, path: string, headers?: Record<string, string>, body?: string): ExternalRequest {
    const headerMap = new Map<string, string>();
    if (headers) {
        for (const [k, v] of Object.entries(headers)) {
            headerMap.set(k, v);
        }
    }
    return {
        method,
        path,
        headers: headerMap,
        body: body !== undefined ? new TextEncoder().encode(body) : null,
    };
}

function responseText(handler: ExternalServiceHandler, req: ExternalRequest): string {
    return decoder.decode(handler.handleRequest(req).body);
}

function responseJson(handler: ExternalServiceHandler, req: ExternalRequest): any {
    return JSON.parse(responseText(handler, req));
}

function responseStatus(handler: ExternalServiceHandler, req: ExternalRequest): number {
    return handler.handleRequest(req).status;
}

function createMockContext(cloud: CloudInfraSpec) {
    const registeredHandlers: ExternalServiceHandler[] = [];
    const registeredDNS: Array<{ domain: string; ip: string; type: string; ttl: number }> = [];
    const emittedEvents: any[] = [];

    const context = {
        world: { cloud } as any,
        fabric: {
            addDNSRecord(record: any) { registeredDNS.push(record); },
            registerExternal(handler: ExternalServiceHandler) { registeredHandlers.push(handler); },
        } as any,
        events: { emit(event: any) { emittedEvents.push(event); } } as any,
        vms: new Map(),
        tick: 0,
        services: {} as any,
    };

    return { context, registeredHandlers, registeredDNS, emittedEvents };
}

function findHandler(handlers: ExternalServiceHandler[], domain: string): ExternalServiceHandler | undefined {
    return handlers.find(h => h.domain === domain);
}

// ── Fixtures ───────────────────────────────────────────────────

function makeCloudSpec(): CloudInfraSpec & {
    snsTopics?: readonly { readonly name: string; readonly arn?: string }[];
    sqsQueues?: readonly { readonly name: string; readonly url?: string }[];
    userData?: string;
    imdsV2Required?: boolean;
} {
    return {
        provider: 'aws',
        accountId: '123456789012',
        buckets: [
            {
                name: 'public-assets',
                access: 'public-read',
                policy: JSON.stringify({
                    Version: '2012-10-17',
                    Statement: [{
                        Sid: 'PublicRead',
                        Effect: 'Allow',
                        Principal: { AWS: '*' },
                        Action: ['s3:GetObject'],
                        Resource: 'arn:aws:s3:::public-assets/*',
                    }],
                }),
                versioning: true,
                objects: {
                    'config/database.yml': {
                        content: 'host: db.internal\npassword: s3cret_p4ss\nport: 5432',
                        contentType: 'text/yaml',
                    },
                    'backup/users.csv': {
                        content: 'username,password,role\nadmin,P@ssw0rd!,admin\nuser,changeme,user',
                        contentType: 'text/csv',
                    },
                    'index.html': {
                        content: '<html><body>Public assets</body></html>',
                        contentType: 'text/html',
                    },
                },
            },
            {
                name: 'private-secrets',
                access: 'private',
                objects: {
                    'ssh-keys/id_rsa': {
                        content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----',
                        contentType: 'application/x-pem-file',
                    },
                },
            },
        ],
        iamUsers: [
            {
                username: 'admin',
                accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
                secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                attachedPolicies: ['AdministratorAccess'],
                inlinePolicy: JSON.stringify({
                    Version: '2012-10-17',
                    Statement: [{
                        Effect: 'Allow',
                        Action: ['iam:CreateAccessKey', 'sns:Publish', 'sqs:SendMessage'],
                        Resource: '*',
                    }],
                }),
                mfaEnabled: false,
                lastActivity: '2024-06-15T10:30:00Z',
                groups: ['admins', 'devops'],
            },
            {
                username: 'deploy-bot',
                accessKeyId: 'AKIAI44QH8DHBEXAMPLE',
                secretAccessKey: 'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY',
                attachedPolicies: ['S3FullAccess'],
                groups: ['deployers'],
            },
        ],
        iamRoles: [
            {
                roleName: 'admin-role',
                trustPolicy: JSON.stringify({
                    Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole' }],
                }),
                attachedPolicies: ['arn:aws:iam::123456789012:policy/AdminPolicy'],
            },
        ],
        iamPolicies: [
            {
                policyId: 'ANPA12345',
                policyName: 'AdminPolicy',
                document: JSON.stringify({
                    Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
                }),
                description: 'Full admin access',
            },
        ],
        functions: [
            {
                name: 'auth-handler',
                runtime: 'python3.11',
                code: 'import boto3\nimport os\n\nDB_PASSWORD = os.environ["DB_PASSWORD"]\n\ndef handler(event, context):\n    return {"statusCode": 200}',
                env: {
                    DB_PASSWORD: 's3cret_db_p4ss',
                    API_KEY: 'sk-live-abc123def456',
                },
                executionRole: 'lambda-exec-role',
                timeout: 30,
                memoryMB: 256,
            },
        ],
        secrets: [
            {
                name: 'prod/database/password',
                value: 'SuperS3cretDBP4ss!',
                description: 'Production database password',
                kmsKeyId: 'aws/secretsmanager',
                tags: { environment: 'production', team: 'platform' },
            },
            {
                name: 'prod/api/stripe-key',
                value: 'sk_test_VARIANT_abc123def456ghi789',
                description: 'Stripe API key',
            },
        ],
        vpcs: [
            {
                vpcId: 'vpc-abc123',
                cidr: '10.0.0.0/16',
                subnets: [
                    { subnetId: 'subnet-pub1', cidr: '10.0.1.0/24', availabilityZone: 'us-east-1a', public: true },
                    { subnetId: 'subnet-priv1', cidr: '10.0.2.0/24', availabilityZone: 'us-east-1a', public: false },
                ],
                securityGroups: [
                    {
                        groupId: 'sg-web',
                        name: 'web-servers',
                        ingressRules: [
                            { protocol: 'tcp', fromPort: 80, toPort: 80, source: '0.0.0.0/0', description: 'HTTP' },
                            { protocol: 'tcp', fromPort: 443, toPort: 443, source: '0.0.0.0/0', description: 'HTTPS' },
                            { protocol: 'tcp', fromPort: 22, toPort: 22, source: '0.0.0.0/0', description: 'SSH (MISCONFIGURED - open to world)' },
                        ],
                        egressRules: [
                            { protocol: '-1', fromPort: 0, toPort: 65535, source: '0.0.0.0/0' },
                        ],
                    },
                ],
            },
        ],
        instances: [
            {
                instanceId: 'i-0abc123def',
                instanceType: 'm5.large',
                state: 'running',
                privateIp: '10.0.1.42',
                publicIp: '203.0.113.42',
                subnetId: 'subnet-pub1',
                securityGroups: ['sg-web'],
                iamRole: 'admin-role',
                tags: { Name: 'web-server-1', Environment: 'production' },
            },
        ],
        snsTopics: [
            { name: 'alerts' },
        ],
        sqsQueues: [
            { name: 'work-queue' },
        ],
        userData: '#!/bin/bash\necho hello world',
        imdsV2Required: false,
    };
}

// ── Tests ──────────────────────────────────────────────────────

describe('createCloudApiModule', () => {
    it('creates module with correct metadata', () => {
        const mod = createCloudApiModule();
        expect(mod.id).toBe('cloud-api');
        expect(mod.version).toBe('1.0.0');
    });

    it('does nothing when cloud is undefined', () => {
        const mod = createCloudApiModule();
        const { context, registeredHandlers } = createMockContext(undefined as any);
        context.world.cloud = undefined;
        mod.init(context);
        expect(registeredHandlers.length).toBe(0);
    });

    it('registers DNS and handlers for all cloud services', () => {
        const { context, registeredHandlers, registeredDNS, emittedEvents } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);

        // 9 service endpoints + 2 bucket virtual hosts
        expect(registeredHandlers.length).toBe(11);
        expect(registeredDNS.length).toBe(11);

        // Check activation event
        expect(emittedEvents.length).toBe(1);
        expect(emittedEvents[0].message).toContain('2 buckets');
        expect(emittedEvents[0].message).toContain('2 IAM users');
        expect(emittedEvents[0].message).toContain('1 functions');
    });
});

describe('S3 API', () => {
    let s3: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        s3 = findHandler(registeredHandlers, 's3.variant.cloud')!;
    });

    it('lists all buckets', () => {
        const text = responseText(s3, makeRequest('GET', '/'));
        expect(text).toContain('public-assets');
        expect(text).toContain('private-secrets');
        expect(text).toContain('ListAllMyBucketsResult');
    });

    it('lists objects in a public bucket', () => {
        const text = responseText(s3, makeRequest('GET', '/public-assets/'));
        expect(text).toContain('config/database.yml');
        expect(text).toContain('backup/users.csv');
        expect(text).toContain('index.html');
    });

    it('gets object content from public bucket', () => {
        const text = responseText(s3, makeRequest('GET', '/public-assets/config/database.yml'));
        expect(text).toContain('s3cret_p4ss');
    });

    it('gets CSV with leaked credentials', () => {
        const text = responseText(s3, makeRequest('GET', '/public-assets/backup/users.csv'));
        expect(text).toContain('P@ssw0rd!');
        expect(text).toContain('admin');
    });

    it('returns 403 for private bucket without auth', () => {
        expect(responseStatus(s3, makeRequest('GET', '/private-secrets/'))).toBe(403);
    });

    it('allows private bucket access with auth header', () => {
        const text = responseText(s3, makeRequest('GET', '/private-secrets/', { authorization: 'AWS4-HMAC-SHA256 ...' }));
        expect(text).toContain('ssh-keys/id_rsa');
    });

    it('returns 404 for nonexistent bucket', () => {
        const text = responseText(s3, makeRequest('GET', '/nonexistent/'));
        expect(text).toContain('NoSuchBucket');
    });

    it('returns 404 for nonexistent object', () => {
        const text = responseText(s3, makeRequest('GET', '/public-assets/nonexistent'));
        expect(text).toContain('NoSuchKey');
    });

    it('supports prefix filtering', () => {
        const text = responseText(s3, makeRequest('GET', '/public-assets/?prefix=config'));
        expect(text).toContain('config/database.yml');
        expect(text).not.toContain('backup/users.csv');
    });

    it('returns bucket policy, ACL, and versioning metadata', () => {
        const policy = responseText(s3, makeRequest('GET', '/public-assets/?policy'));
        const acl = responseText(s3, makeRequest('GET', '/public-assets/?acl'));
        const versioning = responseText(s3, makeRequest('GET', '/public-assets/?versioning'));

        expect(policy).toContain('<GetBucketPolicyResponse');
        expect(policy).toContain('PublicRead');
        expect(acl).toContain('<AccessControlList>');
        expect(acl).toContain('public-read');
        expect(versioning).toContain('<Status>Enabled</Status>');
    });

    it('supports writing objects with PUT and deleting with DELETE', () => {
        const putStatus = responseStatus(
            s3,
            makeRequest(
                'PUT',
                '/private-secrets/exports/keys.txt',
                { authorization: 'AWS4-HMAC-SHA256 ...', 'x-amz-acl': 'private', 'content-type': 'text/plain' },
                'secret-archive\nline-two',
            ),
        );
        expect(putStatus).toBe(200);

        const deleted = responseStatus(
            s3,
            makeRequest('DELETE', '/private-secrets/exports/keys.txt', { authorization: 'AWS4-HMAC-SHA256 ...' }),
        );
        expect(deleted).toBe(204);

        const notFound = responseText(s3, makeRequest('GET', '/private-secrets/exports/keys.txt', { authorization: 'AWS4-HMAC-SHA256 ...' }));
        expect(notFound).toContain('NoSuchKey');
    });

    it('supports presigned URL download for protected objects and validates expiry', () => {
        const valid = responseText(
            s3,
            makeRequest('GET', '/private-secrets/ssh-keys/id_rsa?X-Amz-Signature=demo&X-Amz-Expires=120'),
        );
        expect(valid).toContain('BEGIN RSA PRIVATE KEY');

        const invalid = responseText(
            s3,
            makeRequest('GET', '/private-secrets/ssh-keys/id_rsa?X-Amz-Signature=demo&X-Amz-Expires=99999999'),
        );
        expect(invalid).toContain('InvalidRequest');
    });
});

describe('S3 virtual-hosted bucket', () => {
    it('serves objects via bucket subdomain', () => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        const bucketHandler = findHandler(registeredHandlers, 'public-assets.s3.variant.cloud')!;

        const text = responseText(bucketHandler, makeRequest('GET', '/config/database.yml'));
        expect(text).toContain('s3cret_p4ss');
    });
});

describe('IAM API', () => {
    let iam: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        iam = findHandler(registeredHandlers, 'iam.variant.cloud')!;
    });

    it('lists IAM users', () => {
        const data = responseJson(iam, makeRequest('GET', '/?Action=ListUsers'));
        const users = data.ListUsersResponse.ListUsersResult.Users;
        expect(users).toHaveLength(2);
        expect(users[0].UserName).toBe('admin');
        expect(users[1].UserName).toBe('deploy-bot');
    });

    it('lists IAM roles', () => {
        const data = responseJson(iam, makeRequest('GET', '/?Action=ListRoles'));
        const roles = data.ListRolesResponse.ListRolesResult.Roles;
        expect(roles).toHaveLength(1);
        expect(roles[0].RoleName).toBe('admin-role');
    });

    it('gets specific user details', () => {
        const data = responseJson(iam, makeRequest('GET', '/?Action=GetUser&UserName=admin'));
        const user = data.GetUserResponse.GetUserResult.User;
        expect(user.UserName).toBe('admin');
        expect(user.MFAEnabled).toBe(false);
    });

    it('lists policies', () => {
        const data = responseJson(iam, makeRequest('GET', '/?Action=ListPolicies'));
        const policies = data.ListPoliciesResponse.ListPoliciesResult.Policies;
        expect(policies).toHaveLength(1);
        expect(policies[0].PolicyName).toBe('AdminPolicy');
    });

    it('gets policy document', () => {
        const data = responseJson(iam, makeRequest('GET', '/?Action=GetPolicy&PolicyArn=arn:aws:iam::123456789012:policy/AdminPolicy'));
        const doc = data.GetPolicyResponse.GetPolicyResult.Policy.Document;
        const parsed = JSON.parse(doc);
        expect(parsed.Statement[0].Effect).toBe('Allow');
        expect(parsed.Statement[0].Action).toBe('*');
    });

    it('returns 404 for nonexistent user', () => {
        expect(responseStatus(iam, makeRequest('GET', '/?Action=GetUser&UserName=ghost'))).toBe(404);
    });

    it('returns error for unknown action', () => {
        expect(responseStatus(iam, makeRequest('GET', '/?Action=DeleteEverything'))).toBe(400);
    });

    it('creates a new access key for a user', () => {
        const data = responseJson(iam, makeRequest('GET', '/?Action=CreateAccessKey&UserName=admin'));
        expect(data.CreateAccessKeyResponse.AccessKey.AccessKeyId).toMatch(/^AKIA/);
        expect(data.CreateAccessKeyResponse.AccessKey.SecretAccessKey).toBeTruthy();
        expect(data.CreateAccessKeyResponse.AccessKey.UserName).toBe('admin');
    });

    it('simulates IAM policy decisions', () => {
        const simulation = responseJson(
            iam,
            makeRequest(
                'GET',
                '/?Action=SimulatePolicy&ActionName=iam:CreateAccessKey&PolicySourceArn=arn:aws:iam::123456789012:user/admin',
            ),
        );
        expect(simulation.EvaluationResults).toHaveLength(1);
        expect(simulation.EvaluationResults[0].EvalDecision).toBe('allowed');
    });

    it('returns inline policy details and groups for users', () => {
        const user = responseJson(iam, makeRequest('GET', '/?Action=GetUser&UserName=admin'));
        expect(user.GetUserResponse.GetUserResult.User.InlinePolicy).toContain('CreateAccessKey');

        const groups = responseJson(iam, makeRequest('GET', '/?Action=ListGroupsForUser&UserName=admin'));
        expect(groups.ListGroupsForUserResponse.Groups).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ GroupName: 'admins' }),
                expect.objectContaining({ GroupName: 'devops' }),
            ]),
        );

        const inline = responseJson(iam, makeRequest('GET', '/?Action=GetUserPolicy&UserName=admin&PolicyName=inline'));
        expect(inline.GetUserPolicyResponse.PolicyDocument).toContain('CreateAccessKey');
    });
});

describe('Lambda API', () => {
    let lambda: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        lambda = findHandler(registeredHandlers, 'lambda.variant.cloud')!;
    });

    it('lists functions', () => {
        const data = responseJson(lambda, makeRequest('GET', '/2015-03-31/functions'));
        expect(data.Functions).toHaveLength(1);
        expect(data.Functions[0].FunctionName).toBe('auth-handler');
        expect(data.Functions[0].Runtime).toBe('python3.11');
    });

    it('gets function configuration with env vars (secrets!)', () => {
        const data = responseJson(lambda, makeRequest('GET', '/2015-03-31/functions/auth-handler/configuration'));
        expect(data.FunctionName).toBe('auth-handler');
        expect(data.Environment.Variables.DB_PASSWORD).toBe('s3cret_db_p4ss');
        expect(data.Environment.Variables.API_KEY).toBe('sk-live-abc123def456');
    });

    it('gets function code', () => {
        const data = responseJson(lambda, makeRequest('GET', '/2015-03-31/functions/auth-handler/code'));
        expect(data.Code).toContain('DB_PASSWORD');
        expect(data.Code).toContain('import boto3');
    });

    it('returns 404 for nonexistent function', () => {
        expect(responseStatus(lambda, makeRequest('GET', '/2015-03-31/functions/ghost'))).toBe(404);
    });

    it('invokes a function with payload and returns function response', () => {
        const data = responseJson(lambda, makeRequest('POST', '/2015-03-31/functions/auth-handler/invocations', undefined, JSON.stringify({ ping: 'pong' })));
        expect(data.StatusCode).toBe(200);
        expect(data.ExecutedVersion).toBe('$LATEST');

        const payload = JSON.parse(data.Payload);
        expect(payload.functionName).toBe('auth-handler');
        expect(payload.received).toEqual({ ping: 'pong' });
    });

    it('lists layers', () => {
        const data = responseJson(lambda, makeRequest('GET', '/2018-10-31/layers'));
        expect(data.Layers).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ LayerName: 'auth-handler-runtime-layer' }),
            ]),
        );
    });

    it('updates function environment variables', () => {
        const updated = responseJson(
            lambda,
            makeRequest(
                'POST',
                '/2015-03-31/functions/auth-handler/configuration',
                { 'content-type': 'application/json' },
                JSON.stringify({
                    Environment: {
                        Variables: {
                            NEW_TOKEN: 'rotation-1',
                            DB_PASSWORD: 'rotated-pass',
                        },
                    },
                }),
            ),
        );
        expect(updated.FunctionName).toBe('auth-handler');
        expect(updated.Environment.Variables.NEW_TOKEN).toBe('rotation-1');
        expect(updated.Environment.Variables.DB_PASSWORD).toBe('rotated-pass');
        expect(updated.Environment.Variables.API_KEY).toBe('sk-live-abc123def456');
    });
});

describe('CloudWatch Logs API', () => {
    let lambda: ExternalServiceHandler;
    let logs: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        lambda = findHandler(registeredHandlers, 'lambda.variant.cloud')!;
        logs = findHandler(registeredHandlers, 'cloudwatch-logs.variant.cloud')!;
    });

    it('describes available log groups', () => {
        const data = responseJson(logs, makeRequest('GET', '/?Action=DescribeLogGroups'));
        expect(data.logGroups).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ logGroupName: '/aws/lambda/auth-handler' }),
            ]),
        );
    });

    it('returns log events and supports filtering', () => {
        const invokeRes = responseJson(
            lambda,
            makeRequest('POST', '/2015-03-31/functions/auth-handler/invocations', undefined, JSON.stringify({ ping: 'pong' })),
        );
        expect(invokeRes.StatusCode).toBe(200);

        const events = responseJson(logs, makeRequest('GET', '/?Action=FilterLogEvents&logGroupName=/aws/lambda/auth-handler&filterPattern=Invocation'));
        expect(events.events).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ message: expect.stringContaining('Invocation for auth-handler') }),
            ]),
        );

        const limited = responseJson(logs, makeRequest('GET', '/?Action=GetLogEvents&logGroupName=/aws/lambda/auth-handler&limit=1'));
        expect(limited.events).toHaveLength(1);
    });
});

describe('SNS/SQS APIs', () => {
    let sns: ExternalServiceHandler;
    let sqs: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        sns = findHandler(registeredHandlers, 'sns.variant.cloud')!;
        sqs = findHandler(registeredHandlers, 'sqs.variant.cloud')!;
    });

    it('lists topics and publishes a message', () => {
        const topics = responseJson(sns, makeRequest('GET', '/?Action=ListTopics'));
        expect(topics.Topics.length).toBeGreaterThan(0);

        const topicArn = 'arn:aws:sns:us-east-1:123456789012:topic/alerts';
        const published = responseJson(
            sns,
            makeRequest('POST', `/?Action=Publish&TopicArn=${encodeURIComponent(topicArn)}&Message=api+token+found`),
        );
        expect(published.MessageId).toMatch(/^msg/);
        expect(published.TopicArn).toBe(topicArn);
    });

    it('sends and receives sensitive queue messages', () => {
        const queueUrl = 'https://sqs.us-east-1.amazonaws.com/123456789012/work-queue';
        const sent = responseJson(
            sqs,
            makeRequest('POST', '/?Action=SendMessage&QueueUrl=' + encodeURIComponent(queueUrl) + '&MessageBody=' + encodeURIComponent('SECRET_TOKEN=topsecret')), 
        );
        expect(sent.MessageId).toMatch(/^msg/);

        const received = responseJson(sqs, makeRequest('GET', '/?Action=ReceiveMessage&QueueUrl=' + encodeURIComponent(queueUrl)));
        expect(received.Messages).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ Body: 'SECRET_TOKEN=topsecret' }),
            ]),
        );
    });
});

describe('STS API', () => {
    let sts: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        sts = findHandler(registeredHandlers, 'sts.variant.cloud')!;
    });

    it('returns caller identity', () => {
        const text = responseText(sts, makeRequest('GET', '/?Action=GetCallerIdentity'));
        expect(text).toContain('123456789012');
        expect(text).toContain('GetCallerIdentityResult');
    });

    it('allows assuming a role', () => {
        const text = responseText(sts, makeRequest('GET', '/?Action=AssumeRole&RoleArn=arn:aws:iam::123456789012:role/admin-role'));
        expect(text).toContain('AssumeRoleResult');
        expect(text).toContain('Credentials');
        expect(text).toContain('AccessKeyId');
    });

    it('denies assuming nonexistent role', () => {
        const res = sts!.handleRequest(makeRequest('GET', '/?Action=AssumeRole&RoleArn=arn:aws:iam::123456789012:role/ghost'));
        expect(res.status).toBe(403);
    });
});

describe('EC2 API', () => {
    let ec2: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        ec2 = findHandler(registeredHandlers, 'ec2.variant.cloud')!;
    });

    it('describes instances', () => {
        const data = responseJson(ec2, makeRequest('GET', '/?Action=DescribeInstances'));
        const instances = data.DescribeInstancesResponse.Reservations[0].Instances;
        expect(instances).toHaveLength(1);
        expect(instances[0].InstanceId).toBe('i-0abc123def');
        expect(instances[0].PublicIpAddress).toBe('203.0.113.42');
        expect(instances[0].Tags).toContainEqual({ Key: 'Name', Value: 'web-server-1' });
    });

    it('describes VPCs', () => {
        const data = responseJson(ec2, makeRequest('GET', '/?Action=DescribeVpcs'));
        expect(data.DescribeVpcsResponse.Vpcs).toHaveLength(1);
        expect(data.DescribeVpcsResponse.Vpcs[0].CidrBlock).toBe('10.0.0.0/16');
    });

    it('describes subnets', () => {
        const data = responseJson(ec2, makeRequest('GET', '/?Action=DescribeSubnets'));
        expect(data.DescribeSubnetsResponse.Subnets).toHaveLength(2);
        expect(data.DescribeSubnetsResponse.Subnets[0].MapPublicIpOnLaunch).toBe(true);
    });

    it('describes security groups with misconfigurations', () => {
        const data = responseJson(ec2, makeRequest('GET', '/?Action=DescribeSecurityGroups'));
        const groups = data.DescribeSecurityGroupsResponse.SecurityGroups;
        expect(groups).toHaveLength(1);
        const sshRule = groups[0].IpPermissions.find((r: any) => r.FromPort === 22);
        expect(sshRule).toBeDefined();
        expect(sshRule.IpRanges[0].CidrIp).toBe('0.0.0.0/0');
        expect(sshRule.IpRanges[0].Description).toContain('MISCONFIGURED');
    });

    it('supports IMDSv2 token flow and returns metadata paths', () => {
        const token = responseText(ec2, makeRequest('PUT', '/latest/api/token', { 'x-aws-ec2-metadata-token-ttl-seconds': '60' }));
        expect(token.length).toBeGreaterThan(0);

        const identity = JSON.parse(
            responseText(ec2, makeRequest('GET', '/latest/dynamic/instance-identity/document', { 'x-aws-ec2-metadata-token': token })),
        );
        expect(identity.accountId).toBe('123456789012');
        expect(identity.instanceId).toBe('i-0abc123def');

        const userData = responseText(ec2, makeRequest('GET', '/latest/user-data', { 'x-aws-ec2-metadata-token': token }));
        expect(userData).toContain('#!/bin/bash');
    });

    it('returns 401 for IMDSv2-required metadata path without token', () => {
        const customCloud = {
            ...makeCloudSpec(),
            imdsV2Required: true,
        };
        const { context, registeredHandlers } = createMockContext(customCloud);
        createCloudApiModule().init(context);
        const metadata = findHandler(registeredHandlers, 'ec2.variant.cloud')!;
        const response = metadata.handleRequest(makeRequest('GET', '/latest/meta-data/instance-id'));
        expect(response.status).toBe(401);
    });
});

describe('Secrets Manager API', () => {
    let sm: ExternalServiceHandler;

    beforeEach(() => {
        const { context, registeredHandlers } = createMockContext(makeCloudSpec());
        createCloudApiModule().init(context);
        sm = findHandler(registeredHandlers, 'secretsmanager.variant.cloud')!;
    });

    it('lists secrets', () => {
        const data = responseJson(sm, makeRequest('GET', '/?Action=ListSecrets', { 'x-amz-target': 'secretsmanager.ListSecrets' }));
        expect(data.SecretList).toHaveLength(2);
        expect(data.SecretList[0].Name).toBe('prod/database/password');
    });

    it('gets secret value via query param', () => {
        const data = responseJson(sm, makeRequest('GET', '/?Action=GetSecretValue&SecretId=prod/database/password', { 'x-amz-target': 'secretsmanager.GetSecretValue' }));
        expect(data.SecretString).toBe('SuperS3cretDBP4ss!');
    });

    it('gets secret value via body', () => {
        const data = responseJson(sm, makeRequest(
            'POST', '/',
            { 'x-amz-target': 'secretsmanager.GetSecretValue' },
            JSON.stringify({ SecretId: 'prod/api/stripe-key' }),
        ));
        expect(data.SecretString).toBe('sk_test_VARIANT_abc123def456ghi789');
    });

    it('returns 404 for nonexistent secret', () => {
        const res = sm!.handleRequest(makeRequest('GET', '/?Action=GetSecretValue&SecretId=ghost', { 'x-amz-target': 'secretsmanager.GetSecretValue' }));
        expect(res.status).toBe(404);
    });
});

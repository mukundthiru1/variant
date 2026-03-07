/**
 * VARIANT — Cloud API Service Module
 *
 * Simulates cloud provider APIs (AWS S3, IAM, Lambda, STS, EC2)
 * within the air-gapped simulation. Players interact with these
 * through CLI tools (aws-cli on v86) or curl.
 *
 * Service endpoints:
 *   - s3.variant.cloud      → S3 bucket operations
 *   - iam.variant.cloud      → IAM user/role/policy queries
 *   - lambda.variant.cloud   → Lambda function listing/code
 *   - sts.variant.cloud      → STS assume-role, get-caller-identity
 *   - ec2.variant.cloud      → EC2 instance/VPC/SG listing and metadata
 *   - secretsmanager.variant.cloud → Secrets Manager
 *   - cloudwatch-logs.variant.cloud → Logs query/inspect
 *   - sns.variant.cloud       → SNS topic publish/list
 *   - sqs.variant.cloud       → SQS list/send
 *
 * Players can:
 *   1. Enumerate S3 buckets via ListBuckets / ListObjects
 *   2. Download objects from misconfigured public buckets
 *   3. Enumerate IAM users, roles, policies
 *   4. Assume roles with stolen credentials
 *   5. Read Lambda function code (find hardcoded secrets)
 *   6. Enumerate EC2 instances, VPCs, security groups
 *   7. Retrieve secrets from Secrets Manager
 *
 * SECURITY: Pure simulation. No real cloud calls. All data from WorldSpec.
 * MODULARITY: Swappable module. Reads CloudInfraSpec from WorldSpec.
 */

import type { Module, SimulationContext, Capability } from '../core/modules';
import type { ExternalRequest, ExternalResponse, ExternalServiceHandler } from '../core/fabric/types';
import type { CloudBucketSpec, CloudFunctionSpec, CloudInfraSpec, CloudObjectSpec } from '../core/world/types';

// ── Module ID ──────────────────────────────────────────────────

const MODULE_ID = 'cloud-api';
const MODULE_VERSION = '1.0.0';

type CloudWatchLogEvent = {
    timestamp: string;
    message: string;
    [key: string]: string;
};

type CloudWatchLogState = {
    groups: Array<{ logGroupName: string; events: CloudWatchLogEvent[] }>;
};

type SnsTopicState = {
    topics: Record<string, string[]>;
    arns: Record<string, string>;
};

type SqsQueueState = {
    queues: Record<string, string[]>;
    urls: Record<string, string>;
};

type Imdsv2MetadataState = {
    tokens: Map<string, number>;
    required: boolean;
};

function getHeaderValue(headers: ReadonlyMap<string, string>, key: string): string | undefined {
    const direct = headers.get(key);
    if (direct !== undefined) {
        return direct;
    }
    for (const [k, v] of headers.entries()) {
        if (k.toLowerCase() === key.toLowerCase()) {
            return v;
        }
    }
    return undefined;
}

function parseQuery(path: string): Map<string, string> {
    const result = new Map<string, string>();
    const qIdx = path.indexOf('?');
    if (qIdx === -1) return result;

    const queryString = path.slice(qIdx + 1);
    for (const part of queryString.split('&')) {
        if (part === '') continue;
        const eqIdx = part.indexOf('=');
        if (eqIdx === -1) {
            result.set(decodeURIComponent(part.replace(/\+/g, ' ')), '');
            continue;
        }

        const key = decodeURIComponent(part.slice(0, eqIdx).replace(/\+/g, ' '));
        const value = decodeURIComponent(part.slice(eqIdx + 1).replace(/\+/g, ' '));
        result.set(key, value);
    }

    return result;
}

function parseJsonBody(request: ExternalRequest): Record<string, unknown> | null {
    if (request.body === null) return null;
    try {
        return JSON.parse(new TextDecoder().decode(request.body));
    } catch {
        return null;
    }
}

function randomishId(prefix: string, seed: string, length = 16): string {
    let hash = 0;
    for (let i = 0; i < seed.length; i++) {
        hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
    }
    const suffix = hash.toString(16).padEnd(length, '0').slice(0, length);
    return `${prefix}${suffix}`;
}

function createImdsState(cloud: CloudInfraSpec): Imdsv2MetadataState {
    const ext = cloud as CloudInfraSpec & { imdsV2Required?: boolean };
    return {
        tokens: new Map<string, number>(),
        required: ext.imdsV2Required ?? false,
    };
}

function createCloudWatchState(cloud: CloudInfraSpec): CloudWatchLogState {
    const ext = cloud as CloudInfraSpec & {
        cloudWatchLogGroups?: Array<{
            readonly logGroupName: string;
            readonly events?: ReadonlyArray<{ readonly message: string; readonly timestamp?: string }>;
        }>;
    };

    const groupsFromSpec = (ext.cloudWatchLogGroups ?? []).map(group => ({
        logGroupName: group.logGroupName,
        events: (group.events ?? []).map(event => ({
            message: event.message,
            timestamp: event.timestamp ?? new Date().toISOString(),
            streamName: 'default',
        })),
    }));

    if (groupsFromSpec.length > 0) {
        return { groups: groupsFromSpec };
    }

    return {
        groups: (cloud.functions ?? []).map(fn => ({
            logGroupName: `/aws/lambda/${fn.name}`,
            events: [
                {
                    timestamp: '2024-01-01T00:00:00.000Z',
                    message: `Starting /aws/lambda/${fn.name} environment keys: ${(fn.env !== undefined) ? Object.keys(fn.env).join(',') : 'none'}`,
                    streamName: 'init',
                },
                {
                    timestamp: '2024-01-01T00:01:00.000Z',
                    message: `Function ${fn.name} code size: ${fn.code.length}`,
                    streamName: 'init',
                },
            ],
        })),
    };
}

function createSnsState(cloud: CloudInfraSpec): SnsTopicState {
    const ext = cloud as CloudInfraSpec & {
        snsTopics?: readonly { readonly name: string; readonly arn?: string }[];
    };
    const topics = (ext.snsTopics ?? []).reduce((acc, current) => {
        const arn = current.arn ?? `arn:aws:sns:us-east-1:${cloud.accountId}:topic/${current.name}`;
        acc.arns[current.name] = arn;
        acc.topics[arn] = [];
        return acc;
    }, { topics: Object.create(null) as Record<string, string[]>, arns: Object.create(null) as Record<string, string> });
    if (Object.keys(topics.arns).length === 0) {
        const defaults = ['alerts', 'security-events'];
        for (const name of defaults) {
            const arn = `arn:aws:sns:us-east-1:${cloud.accountId}:topic/${name}`;
            topics.arns[name] = arn;
            topics.topics[arn] = [];
        }
    }
    return topics;
}

function createSqsState(cloud: CloudInfraSpec): SqsQueueState {
    const ext = cloud as CloudInfraSpec & {
        sqsQueues?: readonly { readonly name: string; readonly url?: string }[];
    };
    const queues = (ext.sqsQueues ?? []).reduce((acc, current) => {
        const url = current.url ?? `https://sqs.us-east-1.amazonaws.com/${cloud.accountId}/${current.name}`;
        acc.urls[current.name] = url;
        acc.queues[url] = [];
        return acc;
    }, { queues: Object.create(null) as Record<string, string[]>, urls: Object.create(null) as Record<string, string> });
    if (Object.keys(queues.urls).length === 0) {
        const defaultQueue = 'work-queue';
        const url = `https://sqs.us-east-1.amazonaws.com/${cloud.accountId}/${defaultQueue}`;
        queues.urls[defaultQueue] = url;
        queues.queues[url] = [];
    }
    return queues;
}

// ── Response helpers ───────────────────────────────────────────

const encoder = new TextEncoder();

function xmlResponse(status: number, xml: string): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', 'application/xml');
    headers.set('server', 'AmazonS3');
    return { status, headers, body: encoder.encode(xml) };
}

function jsonResponse(status: number, data: unknown): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', 'application/json');
    headers.set('server', 'VARIANT-Cloud/1.0');
    return { status, headers, body: encoder.encode(JSON.stringify(data, null, 2)) };
}

function make403Xml(message: string): ExternalResponse {
    return xmlResponse(403, `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>${escapeXml(message)}</Message></Error>`);
}

function make404Xml(code: string, message: string): ExternalResponse {
    return xmlResponse(404, `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>${escapeXml(code)}</Code><Message>${escapeXml(message)}</Message></Error>`);
}

function escapeXml(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Factory ────────────────────────────────────────────────────

export function createCloudApiModule(): Module {
    return {
        id: MODULE_ID,
        type: 'engine',
        version: MODULE_VERSION,
        description: 'Simulates cloud provider APIs (S3, IAM, Lambda, STS, EC2, Secrets Manager)',

        provides: [{ name: 'cloud-api' }] as readonly Capability[],
        requires: [{ name: 'variant-internet' }] as readonly Capability[],

        init(context: SimulationContext): void {
            const cloud = context.world.cloud;
            if (cloud === undefined) return;

            const domain = cloud.provider === 'aws' ? 'variant.cloud' : 'cloud.variant.net';
            const imdsState = createImdsState(cloud);
            const cloudWatchState = createCloudWatchState(cloud);
            const snsState = createSnsState(cloud);
            const sqsState = createSqsState(cloud);

            // Register cloud API service endpoints
            const services: Array<{ subdomain: string; handler: (req: ExternalRequest) => ExternalResponse }> = [
                { subdomain: 's3', handler: (req) => handleS3(req, cloud) },
                { subdomain: 'iam', handler: (req) => handleIAM(req, cloud) },
                { subdomain: 'lambda', handler: (req) => handleLambda(req, cloud, cloudWatchState) },
                { subdomain: 'sts', handler: (req) => handleSTS(req, cloud) },
                { subdomain: 'ec2', handler: (req) => handleEC2(req, cloud, imdsState) },
                { subdomain: 'secretsmanager', handler: (req) => handleSecretsManager(req, cloud) },
                { subdomain: 'cloudwatch-logs', handler: (req) => handleCloudWatchLogs(req, cloud, cloudWatchState) },
                { subdomain: 'sns', handler: (req) => handleSNS(req, cloud, snsState) },
                    { subdomain: 'sqs', handler: (req) => handleSQS(req, sqsState) },
            ];

            for (const svc of services) {
                const fullDomain = `${svc.subdomain}.${domain}`;
                const handler: ExternalServiceHandler = {
                    domain: fullDomain,
                    description: `VARIANT Cloud: ${svc.subdomain} API at ${fullDomain}`,
                    handleRequest(request: ExternalRequest): ExternalResponse {
                        return svc.handler(request);
                    },
                };

                context.fabric.addDNSRecord({
                    domain: fullDomain,
                    ip: `172.16.1.${10 + services.indexOf(svc)}`,
                    type: 'A',
                    ttl: 3600,
                });

                context.fabric.registerExternal(handler);
            }

            // Also register virtual-hosted S3 bucket DNS entries
            if (cloud.buckets !== undefined) {
                for (const bucket of cloud.buckets) {
                    const bucketDomain = `${bucket.name}.s3.${domain}`;
                    context.fabric.addDNSRecord({
                        domain: bucketDomain,
                        ip: '172.16.1.10',
                        type: 'A',
                        ttl: 3600,
                    });
                    context.fabric.registerExternal({
                        domain: bucketDomain,
                        description: `VARIANT Cloud: S3 bucket ${bucket.name}`,
                        handleRequest(request: ExternalRequest): ExternalResponse {
                            return handleS3BucketRequest(request, bucket.name, cloud);
                        },
                    });
                }
            }

            context.events.emit({
                type: 'sim:alert',
                source: MODULE_ID,
                message: `Cloud API activated: ${cloud.provider} (${cloud.buckets?.length ?? 0} buckets, ${cloud.iamUsers?.length ?? 0} IAM users, ${cloud.functions?.length ?? 0} functions)`,
                timestamp: Date.now(),
            });
        },

        destroy(): void {
            // Handlers owned by fabric
        },
    };
}

// ── S3 ─────────────────────────────────────────────────────────

function hasS3Auth(request: ExternalRequest): boolean {
    return getHeaderValue(request.headers, 'authorization') !== undefined;
}

function hasValidPresignedGet(request: ExternalRequest): boolean {
    const query = parseQuery(request.path);
    const signature = query.get('X-Amz-Signature');
    const expiresRaw = query.get('X-Amz-Expires');
    if (signature === undefined || signature === '') return false;
    const expires = Number(expiresRaw);
    return Number.isInteger(expires) && expires > 0 && expires <= 604800;
}

function validatePresignedGet(request: ExternalRequest): ExternalResponse | null {
    const query = parseQuery(request.path);
    if (!query.has('X-Amz-Expires') && !query.has('X-Amz-Signature')) return null;
    if (!hasValidPresignedGet(request)) {
        return jsonResponse(400, { Error: { Code: 'InvalidRequest', Message: 'Invalid presigned URL parameters' } });
    }
    return null;
}

function canReadObject(
    bucket: CloudBucketSpec,
    obj: CloudObjectSpec | undefined,
    request: ExternalRequest,
): boolean {
    const effective = obj?.acl ?? bucket.access;
    if (effective === 'public-read' || effective === 'public-read-write') return true;
    if (effective === 'authenticated-read') return hasS3Auth(request);
    return hasS3Auth(request) || hasValidPresignedGet(request);
}

function canWriteBucket(bucket: CloudBucketSpec, request: ExternalRequest): boolean {
    if (bucket.access === 'public-read-write') return true;
    return hasS3Auth(request);
}

function handleS3(request: ExternalRequest, cloud: CloudInfraSpec): ExternalResponse {
    const buckets = cloud.buckets ?? [];

    // ListBuckets
    if (request.path === '/' || request.path === '') {
        const bucketsXml = buckets.map(b =>
            `<Bucket><Name>${escapeXml(b.name)}</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>`,
        ).join('');

        return xmlResponse(200, `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>${cloud.accountId}</ID><DisplayName>owner</DisplayName></Owner>
  <Buckets>${bucketsXml}</Buckets>
</ListAllMyBucketsResult>`);
    }

    // Path-style access: /bucket-name/key?params
    const pathWithoutQuery = request.path.split('?')[0]!;
    const queryString = request.path.includes('?') ? '?' + request.path.split('?').slice(1).join('?') : '';
    const pathParts = pathWithoutQuery.replace(/^\//, '').split('/');
    const bucketName = pathParts[0] ?? '';
    const objectKey = pathParts.slice(1).join('/');
    const innerPath = objectKey !== '' ? `/${objectKey}${queryString}` : `/${queryString}`;

    return handleS3BucketRequest(
        { ...request, path: innerPath },
        bucketName,
        cloud,
    );
}

function handleS3BucketRequest(
    request: ExternalRequest,
    bucketName: string,
    cloud: CloudInfraSpec,
): ExternalResponse {
    const bucket = (cloud.buckets ?? []).find(b => b.name === bucketName);
    if (bucket === undefined) {
        return make404Xml('NoSuchBucket', `The specified bucket does not exist: ${bucketName}`);
    }

    const rawKey = request.path.split('?')[0]!.replace(/^\//, '');
    const query = parseQuery(request.path);

    // ListObjects (root or with prefix)
    if (rawKey === '' || rawKey === '/') {
        if (!canReadObject(bucket, undefined, request)) {
            return make403Xml('Access Denied');
        }

        if (query.has('policy')) {
            return xmlResponse(200, `<?xml version="1.0" encoding="UTF-8"?>
<GetBucketPolicyResponse xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Policy>${escapeXml(bucket.policy ?? '{}')}</Policy>
</GetBucketPolicyResponse>`);
        }

        if (query.has('acl')) {
            return xmlResponse(200, `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>${escapeXml(cloud.accountId)}</ID><DisplayName>owner</DisplayName></Owner>
  <AccessControlList>
    <Grant>
      <Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>
      <Permission>${escapeXml(bucket.access)}</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>`);
        }

        if (query.has('versioning')) {
            return xmlResponse(200, `<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>${bucket.versioning ? 'Enabled' : 'Suspended'}</Status>
</VersioningConfiguration>`);
        }

        return listBucketObjectsXml(bucket, bucketName, query);
    }

    if (request.method === 'PUT') {
        if (!canWriteBucket(bucket, request)) return make403Xml('Access Denied');
        const objects = bucket.objects as Record<string, CloudObjectSpec>;
        const bodyText = request.body === null ? '' : new TextDecoder().decode(request.body);
        const acl = getHeaderValue(request.headers, 'x-amz-acl');
        const contentType = getHeaderValue(request.headers, 'content-type') ?? 'application/octet-stream';
        const newObj: CloudObjectSpec = {
            content: bodyText,
            contentType,
            size: bodyText.length,
            lastModified: new Date().toISOString(),
            metadata: {
                source: 'cloud-api-putobject',
            },
        };
        if (acl === 'public-read' || acl === 'private') {
            (newObj as { acl: string }).acl = acl;
        }
        objects[rawKey] = newObj;
        return xmlResponse(200, `<?xml version="1.0" encoding="UTF-8"?>
<PutObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <ETag>"${randomishId('etag', `${bucketName}:${rawKey}`, 16)}"</ETag>
</PutObjectResult>`);
    }

    if (request.method === 'DELETE') {
        if (!canWriteBucket(bucket, request)) return make403Xml('Access Denied');
        const objects = bucket.objects as Record<string, CloudObjectSpec>;
        if (objects[rawKey] === undefined) {
            return make404Xml('NoSuchKey', `The specified key does not exist: ${rawKey}`);
        }
        delete objects[rawKey];
        return { status: 204, headers: new Map(), body: new TextEncoder().encode('') };
    }

    const obj = bucket.objects[rawKey];
    if (obj === undefined) {
        return make404Xml('NoSuchKey', `The specified key does not exist: ${rawKey}`);
    }

    const presignValidation = validatePresignedGet(request);
    if (query.has('X-Amz-Signature') && presignValidation !== null) {
        return presignValidation;
    }

    if (!canReadObject(bucket, obj, request)) {
        return make403Xml('Access Denied');
    }

    const headers = new Map<string, string>();
    headers.set('content-type', obj.contentType);
    headers.set('content-length', String(obj.size ?? obj.content.length));
    headers.set('last-modified', obj.lastModified ?? 'Mon, 01 Jan 2024 00:00:00 GMT');
    headers.set('server', 'AmazonS3');
    if (obj.metadata !== undefined) {
        for (const [k, v] of Object.entries(obj.metadata)) {
            headers.set(`x-amz-meta-${k}`, v);
        }
    }

    return { status: 200, headers, body: encoder.encode(obj.content) };
}

function listBucketObjectsXml(
    bucket: CloudBucketSpec,
    bucketName: string,
    query: Map<string, string>,
): ExternalResponse {
    const prefix = query.get('prefix') ?? '';
    const objects = Object.entries(bucket.objects)
        .filter(([k]) => k.startsWith(prefix))
        .map(([k, v]) => `<Contents>
    <Key>${escapeXml(k)}</Key>
    <LastModified>${v.lastModified ?? '2024-01-01T00:00:00.000Z'}</LastModified>
    <Size>${v.size ?? v.content.length}</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>`).join('\n');

    return xmlResponse(200, `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>${escapeXml(bucketName)}</Name>
  <Prefix>${escapeXml(prefix)}</Prefix>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  ${objects}
</ListBucketResult>`);
}

// ── IAM ────────────────────────────────────────────────────────

function matchIamAction(pattern: string, action: string): boolean {
    if (pattern === '*') return true;
    if (pattern.includes('*')) {
        const regex = new RegExp(`^${pattern.replace(/\*/g, '.*')}$`);
        return regex.test(action);
    }
    return pattern === action;
}

function extractUserOrRolePolicyDocs(
    cloud: CloudInfraSpec,
    userName?: string,
    roleName?: string,
): string[] {
    const documents: string[] = [];
    if (userName !== undefined) {
        const user = (cloud.iamUsers ?? []).find(u => u.username === userName);
        if (user !== undefined && user.inlinePolicy !== undefined) {
            documents.push(user.inlinePolicy);
        }
        for (const policyName of user?.attachedPolicies ?? []) {
            const policy = (cloud.iamPolicies ?? []).find(p => p.policyName === policyName);
            if (policy !== undefined) documents.push(policy.document);
        }
    }
    if (roleName !== undefined) {
        const role = (cloud.iamRoles ?? []).find(r => r.roleName === roleName);
        if (role !== undefined && role.inlinePolicy !== undefined) {
            documents.push(role.inlinePolicy);
        }
        for (const policyArn of role?.attachedPolicies ?? []) {
            const policyName = policyArn.split('/').pop();
            const policy = (cloud.iamPolicies ?? []).find(p => p.policyName === (policyName ?? ''));
            if (policy !== undefined) documents.push(policy.document);
        }
    }
    return documents;
}

function isActionAllowedByPolicy(policyDocument: string, action: string): boolean {
    try {
        const parsed = JSON.parse(policyDocument);
        const statements = parsed.Statement;
        const statementArray = Array.isArray(statements) ? statements : [statements];
        for (const statement of statementArray) {
            if (statement === undefined || statement === null) continue;
            const actions = statement.Action;
            if (typeof actions === 'string' && matchIamAction(actions, action)) {
                if (statement.Effect === 'Allow' || statement.Effect === undefined) return true;
                if (statement.Effect === 'Deny') return false;
            }
            if (Array.isArray(actions) && actions.some((entry: unknown) => typeof entry === 'string' && matchIamAction(entry, action))) {
                if (statement.Effect === 'Deny') return false;
                return statement.Effect === 'Allow' || statement.Effect === undefined;
            }
        }
    } catch {
        // ignore invalid policy documents
    }
    return false;
}

function simulateIamAction(cloud: CloudInfraSpec, principalUser?: string, principalRole?: string, actionName = '', _resource = '*'): boolean {
    const documents = extractUserOrRolePolicyDocs(cloud, principalUser, principalRole);
    let allowed = false;
    for (const policyDocument of documents) {
        const docAllows = isActionAllowedByPolicy(policyDocument, actionName);
        if (!docAllows) continue;
        allowed = true;
    }
    return allowed;
}

function parseRequestPolicyParams(
    request: ExternalRequest,
): { actionName: string; resource: string; userName: string; roleName: string } {
    const body = parseJsonBody(request);
    const actionName = extractParam(request.path, 'ActionName')
        || (typeof body?.["ActionName"] === 'string' ? body["ActionName"] : '')
        || (typeof body?.["ActionToCheck"] === 'string' ? body["ActionToCheck"] : '');
    const resource = extractParam(request.path, 'Resource')
        || (typeof body?.["Resource"] === 'string' ? body["Resource"] : '*')
        || '*';
    const policySource = extractParam(request.path, 'PolicySourceArn') ?? '';
    const userName = body && typeof body["UserName"] === 'string' ? body["UserName"]
        : policySource.includes(':user/') ? policySource.split(':user/').pop() ?? ''
            : '';
    const roleName = body && typeof body["RoleName"] === 'string' ? body["RoleName"]
        : policySource.includes(':role/') ? policySource.split(':role/').pop() ?? ''
            : '';
    return { actionName, resource, userName, roleName };
}

function handleIAM(request: ExternalRequest, cloud: CloudInfraSpec): ExternalResponse {
    const action = extractParam(request.path, 'Action')
        ?? request.headers.get('x-amz-target')?.split('.').pop()
        ?? '';
    const body = parseJsonBody(request);
    const userName = extractParam(request.path, 'UserName')
        ?? (typeof body?.["UserName"] === 'string' ? body["UserName"] : '')
        ?? '';

    switch (action) {
        case 'CreateAccessKey': {
            const user = (cloud.iamUsers ?? []).find(u => u.username === userName);
            if (user === undefined) return jsonResponse(404, { Error: { Code: 'NoSuchEntity', Message: 'User not found' } });

            return jsonResponse(200, {
                CreateAccessKeyResponse: {
                    AccessKey: {
                        UserName: user.username,
                        AccessKeyId: randomishId('AKIA', `${user.username}${cloud.accountId}`, 16),
                        SecretAccessKey: randomishId('wJalrXUtnFEMI/K7MDENG', `${user.username}-secret`, 40),
                        Status: 'Active',
                        CreateDate: '2024-01-01T00:00:00Z',
                    },
                },
            });
        }

        case 'ListUsers': {
            const users = (cloud.iamUsers ?? []).map(u => ({
                UserName: u.username,
                UserId: `AIDA${u.username.toUpperCase().slice(0, 16)}`,
                Arn: `arn:aws:iam::${cloud.accountId}:user/${u.username}`,
                CreateDate: u.lastActivity ?? '2024-01-01T00:00:00Z',
                PasswordLastUsed: u.lastActivity,
            }));
            return jsonResponse(200, { ListUsersResponse: { ListUsersResult: { Users: users, IsTruncated: false } } });
        }

        case 'ListRoles': {
            const roles = (cloud.iamRoles ?? []).map(r => ({
                RoleName: r.roleName,
                RoleId: `AROA${r.roleName.toUpperCase().slice(0, 16)}`,
                Arn: `arn:aws:iam::${cloud.accountId}:role/${r.roleName}`,
                AssumeRolePolicyDocument: r.trustPolicy,
            }));
            return jsonResponse(200, { ListRolesResponse: { ListRolesResult: { Roles: roles, IsTruncated: false } } });
        }

        case 'ListPolicies': {
            const policies = (cloud.iamPolicies ?? []).map(p => ({
                PolicyName: p.policyName,
                PolicyId: p.policyId,
                Arn: `arn:aws:iam::${cloud.accountId}:policy/${p.policyName}`,
                Description: p.description ?? '',
            }));
            return jsonResponse(200, { ListPoliciesResponse: { ListPoliciesResult: { Policies: policies, IsTruncated: false } } });
        }

        case 'GetPolicy': {
            const policyName = extractParam(request.path, 'PolicyArn')?.split('/').pop() ?? '';
            const policy = (cloud.iamPolicies ?? []).find(p => p.policyName === policyName);
            if (policy === undefined) return jsonResponse(404, { Error: { Code: 'NoSuchEntity', Message: 'Policy not found' } });
            return jsonResponse(200, {
                GetPolicyResponse: {
                    GetPolicyResult: {
                        Policy: {
                            PolicyName: policy.policyName,
                            PolicyId: policy.policyId,
                            Document: policy.document,
                        },
                    },
                },
            });
        }

        case 'GetUser': {
            const userName = extractParam(request.path, 'UserName') ?? '';
            const user = (cloud.iamUsers ?? []).find(u => u.username === userName);
            if (user === undefined) return jsonResponse(404, { Error: { Code: 'NoSuchEntity', Message: 'User not found' } });
            return jsonResponse(200, {
                GetUserResponse: {
                    GetUserResult: {
                        User: {
                            UserName: user.username,
                            Arn: `arn:aws:iam::${cloud.accountId}:user/${user.username}`,
                            Groups: user.groups ?? [],
                            AttachedPolicies: user.attachedPolicies ?? [],
                            InlinePolicy: user.inlinePolicy ?? null,
                            MFAEnabled: user.mfaEnabled ?? false,
                        },
                    },
                },
            });
        }

        case 'ListUserPolicies': {
            const userName = extractParam(request.path, 'UserName') ?? '';
            const user = (cloud.iamUsers ?? []).find(u => u.username === userName);
            if (user === undefined) return jsonResponse(404, { Error: { Code: 'NoSuchEntity' } });
            return jsonResponse(200, {
                ListUserPoliciesResponse: {
                    ListUserPoliciesResult: {
                        PolicyNames: user.attachedPolicies ?? [],
                        IsTruncated: false,
                    },
                },
            });
        }

        case 'ListAttachedRolePolicies': {
            const roleName = extractParam(request.path, 'RoleName') ?? '';
            const role = (cloud.iamRoles ?? []).find(r => r.roleName === roleName);
            if (role === undefined) return jsonResponse(404, { Error: { Code: 'NoSuchEntity' } });
            return jsonResponse(200, {
                ListAttachedRolePoliciesResponse: {
                    ListAttachedRolePoliciesResult: {
                        AttachedPolicies: (role.attachedPolicies ?? []).map(arn => ({
                            PolicyArn: arn,
                            PolicyName: arn.split('/').pop(),
                        })),
                        IsTruncated: false,
                    },
                },
            });
        }

        case 'ListGroupsForUser': {
            const user = (cloud.iamUsers ?? []).find(u => u.username === userName);
            if (user === undefined) return jsonResponse(404, { Error: { Code: 'NoSuchEntity', Message: 'User not found' } });
            return jsonResponse(200, {
                ListGroupsForUserResponse: {
                    IsTruncated: false,
                    Groups: (user.groups ?? []).map(groupName => ({
                        Path: '/',
                        GroupName: groupName,
                        Arn: `arn:aws:iam::${cloud.accountId}:group/${groupName}`,
                        CreateDate: '2024-01-01T00:00:00Z',
                    })),
                },
            });
        }

        case 'GetUserPolicy': {
            const policyName = extractParam(request.path, 'PolicyName') ?? '';
            const user = (cloud.iamUsers ?? []).find(u => u.username === userName);
            if (user === undefined || user.inlinePolicy === undefined || policyName !== 'inline') {
                return jsonResponse(404, { Error: { Code: 'NoSuchEntity', Message: 'No such user policy' } });
            }
            return jsonResponse(200, {
                GetUserPolicyResponse: {
                    UserName: user.username,
                    PolicyName: policyName,
                    PolicyDocument: user.inlinePolicy,
                },
            });
        }

        case 'SimulatePolicy': {
            const { actionName, resource, userName, roleName } = parseRequestPolicyParams(request);
            const evaluated = simulateIamAction(cloud, userName, roleName, actionName, resource);
            return jsonResponse(200, {
                EvaluationResults: [
                    {
                        EvalActionName: actionName,
                        EvalResourceName: resource,
                        EvalDecision: evaluated ? 'allowed' : 'implicitDeny',
                    },
                ],
            });
        }

        default:
            return jsonResponse(400, { Error: { Code: 'InvalidAction', Message: `Unknown action: ${action}` } });
    }
}

// ── Lambda ─────────────────────────────────────────────────────

function getLambdaLayers(cloud: CloudInfraSpec): Array<{ LayerName: string; LayerArn: string }> {
    const ext = cloud as CloudInfraSpec & {
        lambdaLayers?: readonly { readonly layerName: string; readonly layerArn?: string }[];
    };
    if ((ext.lambdaLayers?.length ?? 0) > 0) {
        return ext.lambdaLayers!.map(layer => ({
            LayerName: layer.layerName,
            LayerArn: layer.layerArn ?? `arn:aws:lambda:us-east-1:${cloud.accountId}:layer:${layer.layerName}`,
        }));
    }
    return (cloud.functions ?? []).map(fn => ({
        LayerName: `${fn.name}-runtime-layer`,
        LayerArn: `arn:aws:lambda:us-east-1:${cloud.accountId}:layer:${fn.name}-runtime-layer`,
    }));
}

function appendLambdaInvocationLog(
    state: CloudWatchLogState,
    fnName: string,
    message: string,
): void {
    const groupName = `/aws/lambda/${fnName}`;
    const group = state.groups.find(g => g.logGroupName === groupName);
    if (group === undefined) return;
    group.events.push({
        timestamp: new Date().toISOString(),
        message,
        streamName: 'invocation',
    });
}

function handleLambda(request: ExternalRequest, cloud: CloudInfraSpec, cloudWatchState: CloudWatchLogState): ExternalResponse {
    const functions = cloud.functions ?? [];
    const layers = getLambdaLayers(cloud);
    const requestPath = request.path.toLowerCase();

    // ListFunctions
    if (request.path === '/2015-03-31/functions' || request.path === '/2015-03-31/functions/') {
        const fns = functions.map(f => ({
            FunctionName: f.name,
            Runtime: f.runtime,
            Role: f.executionRole ?? `arn:aws:iam::${cloud.accountId}:role/lambda-role`,
            Handler: 'index.handler',
            CodeSize: f.code.length,
            Timeout: f.timeout ?? 30,
            MemorySize: f.memoryMB ?? 128,
            LastModified: '2024-01-01T00:00:00.000+0000',
        }));
        return jsonResponse(200, { Functions: fns });
    }

    // ListLayers
    if (request.path === '/2018-10-31/layers' || request.path === '/2018-10-31/layers/') {
        return jsonResponse(200, {
            Layers: layers.map(layer => ({
                LayerName: layer.LayerName,
                LayerArn: layer.LayerArn,
            })),
        });
    }

    // GetFunction / GetFunctionCode
    const fnMatch = request.path.match(/\/2015-03-31\/functions\/([^/]+)/);
    if (fnMatch !== null) {
        const fnName = fnMatch[1]!;
        const fn = functions.find(f => f.name === decodeURIComponent(fnName));
        if (fn === undefined) {
            return jsonResponse(404, { Message: `Function not found: ${fnName}`, Type: 'ResourceNotFoundException' });
        }

        if (requestPath.endsWith('/invocations') && request.method.toUpperCase() === 'POST') {
            const payloadText = request.body === null ? '{}' : new TextDecoder().decode(request.body);
            let parsedPayload: unknown = null;
            try {
                parsedPayload = JSON.parse(payloadText);
            } catch {
                parsedPayload = payloadText;
            }
            appendLambdaInvocationLog(cloudWatchState, fnName, `Invocation for ${fnName}: ${payloadText}`);
            return jsonResponse(200, {
                StatusCode: 200,
                ExecutedVersion: '$LATEST',
                Payload: JSON.stringify({
                    functionName: fnName,
                    received: parsedPayload,
                }),
            });
        }

        // Get function configuration
        if (request.path.endsWith('/configuration')) {
            if (request.method.toUpperCase() === 'POST') {
                const body = parseJsonBody(request);
                const envField = (body as Record<string, unknown> | undefined)?.["Environment"] as Record<string, unknown> | undefined;
                const newVars = envField?.["Variables"];
                if (newVars !== undefined && typeof newVars === 'object' && newVars !== null) {
                    const mutableFunctions = functions as Array<CloudFunctionSpec & { env?: Record<string, string> }>;
                    const idx = mutableFunctions.findIndex(f => f.name === fn.name);
                    if (idx !== -1) {
                        const normalizedVars = newVars as Record<string, string>;
                        mutableFunctions[idx]!.env = { ...(mutableFunctions[idx]!.env ?? {}), ...normalizedVars };
                        appendLambdaInvocationLog(cloudWatchState, fn.name, `Environment variables updated on ${fn.name}`);
                    }
                }
            }

            return jsonResponse(200, {
                FunctionName: fn.name,
                Runtime: fn.runtime,
                Role: fn.executionRole ?? `arn:aws:iam::${cloud.accountId}:role/lambda-role`,
                Handler: 'index.handler',
                CodeSize: fn.code.length,
                Timeout: fn.timeout ?? 30,
                MemorySize: fn.memoryMB ?? 128,
                Environment: fn.env !== undefined ? { Variables: fn.env } : undefined,
                Triggers: fn.triggers ?? [],
            });
        }

        // Get function code (the juice — may contain secrets)
        if (request.path.endsWith('/code')) {
            return jsonResponse(200, {
                FunctionName: fn.name,
                Code: fn.code,
            });
        }
    }

    return jsonResponse(404, { Message: 'Not Found' });
}

// ── STS ────────────────────────────────────────────────────────

function handleSTS(request: ExternalRequest, cloud: CloudInfraSpec): ExternalResponse {
    const action = extractParam(request.path, 'Action') ?? '';

    switch (action) {
        case 'GetCallerIdentity': {
            return xmlResponse(200, `<?xml version="1.0" encoding="UTF-8"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::${cloud.accountId}:user/compromised-user</Arn>
    <UserId>AIDAEXAMPLE123</UserId>
    <Account>${cloud.accountId}</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`);
        }

        case 'AssumeRole': {
            const roleArn = extractParam(request.path, 'RoleArn') ?? '';
            const roleName = roleArn.split('/').pop() ?? '';
            const role = (cloud.iamRoles ?? []).find(r => r.roleName === roleName);

            if (role === undefined) {
                return xmlResponse(403, `<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse><Error><Code>AccessDenied</Code><Message>Not authorized to perform sts:AssumeRole on resource: ${escapeXml(roleArn)}</Message></Error></ErrorResponse>`);
            }

            return xmlResponse(200, `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIA${roleName.toUpperCase().slice(0, 16)}</AccessKeyId>
      <SecretAccessKey>assumed-role-secret-${roleName}-${Date.now().toString(36)}</SecretAccessKey>
      <SessionToken>FwoGZXIvYXdzEBYaDH...</SessionToken>
      <Expiration>2025-12-31T23:59:59Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <AssumedRoleId>AROA${roleName.toUpperCase().slice(0, 16)}:session</AssumedRoleId>
      <Arn>${escapeXml(roleArn)}/session</Arn>
    </AssumedRoleUser>
  </AssumeRoleResult>
</AssumeRoleResponse>`);
        }

        default:
            return jsonResponse(400, { Error: { Code: 'InvalidAction', Message: `Unknown action: ${action}` } });
    }
}

// ── EC2 ────────────────────────────────────────────────────────

function textResponse(status: number, body: string): ExternalResponse {
    const headers = new Map<string, string>();
    headers.set('content-type', 'text/plain');
    headers.set('server', 'AmazonEC2');
    return { status, headers, body: encoder.encode(body) };
}

function metadataInstanceFromCloud(cloud: CloudInfraSpec): { instanceId: string; instanceType: string; privateIp: string; publicIp: string; subnetId: string; } {
    const instance = (cloud.instances ?? [])[0];
    return {
        instanceId: instance?.instanceId ?? 'i-00000000000000000',
        instanceType: instance?.instanceType ?? 'm5.large',
        privateIp: instance?.privateIp ?? '10.0.0.10',
        publicIp: instance?.publicIp ?? '203.0.113.10',
        subnetId: instance?.subnetId ?? 'subnet-000',
    };
}

function handleEC2Metadata(request: ExternalRequest, cloud: CloudInfraSpec, metadataState: Imdsv2MetadataState): ExternalResponse {
    const instance = metadataInstanceFromCloud(cloud);
    const metadataPath = request.path.replace('/latest/', '');
    const normalized = normalizeMetadataPath(metadataPath);

    if (request.method === 'PUT' && normalized === 'api/token') {
        const ttlRaw = getHeaderValue(request.headers, 'x-aws-ec2-metadata-token-ttl-seconds') ?? '21600';
        const ttl = Number(ttlRaw);
        if (!Number.isInteger(ttl) || ttl <= 0 || ttl > 21600) {
            return textResponse(400, 'Invalid token TTL');
        }
        const token = randomishId('imdsv2', `${cloud.accountId}:${Date.now()}`, 24);
        metadataState.tokens.set(token, Date.now() + ttl * 1000);
        return textResponse(200, token);
    }

    if (metadataState.required) {
        const token = getHeaderValue(request.headers, 'x-aws-ec2-metadata-token');
        const expiry = token === undefined ? undefined : metadataState.tokens.get(token);
        if (token === undefined || expiry === undefined || expiry < Date.now()) {
            return textResponse(401, 'Unauthorized');
        }
    }

    const role = (cloud.instances ?? [])[0]?.iamRole ?? 'default-role';

    if (normalized === 'meta-data') {
        return textResponse(200, [
            'instance-id',
            'instance-type',
            'local-hostname',
            'local-ipv4',
            'public-ipv4',
            'public-hostname',
            'security-groups',
            'placement/',
            'iam/',
        ].join('\n'));
    }
    if (normalized === 'meta-data/instance-id') return textResponse(200, instance.instanceId);
    if (normalized === 'meta-data/instance-type') return textResponse(200, instance.instanceType);
    if (normalized === 'meta-data/hostname' || normalized === 'meta-data/local-hostname') return textResponse(200, `ip-${instance.privateIp.replace(/\\./g, '-')}.internal`);
    if (normalized === 'meta-data/local-ipv4') return textResponse(200, instance.privateIp);
    if (normalized === 'meta-data/public-ipv4') return textResponse(200, instance.publicIp);
    if (normalized === 'meta-data/placement/') return textResponse(200, 'availability-zone\nregion');
    if (normalized === 'meta-data/placement/availability-zone') return textResponse(200, 'us-east-1a');
    if (normalized === 'meta-data/placement/region') return textResponse(200, 'us-east-1');
    if (normalized === 'meta-data/security-groups') return textResponse(200, 'default');
    if (normalized === 'meta-data/iam/security-credentials') return textResponse(200, role);
    if (normalized === `meta-data/iam/security-credentials/${role}`) {
        return textResponse(200, JSON.stringify({
            Code: 'Success',
            Type: 'AWS-HMAC',
            AccessKeyId: `AKIA${instance.instanceId.slice(-16)}`,
            SecretAccessKey: `wJalrXUtnFEMI/K7MDENG/${instance.instanceId.slice(-12)}`,
            Token: randomishId('imdsv2token', `${role}`, 16),
            Expiration: '2025-12-31T23:59:59Z',
        }));
    }
    if (normalized === 'user-data') return textResponse(200, (cloud as CloudInfraSpec & { userData?: string }).userData ?? '');
    if (normalized === 'dynamic/instance-identity/document') {
        return textResponse(200, JSON.stringify({
            accountId: cloud.accountId,
            instanceId: instance.instanceId,
            region: 'us-east-1',
            availabilityZone: 'us-east-1a',
            instanceType: instance.instanceType,
        }));
    }

    return textResponse(404, 'Not Found');
}

function normalizeMetadataPath(path: string): string {
    if (path.startsWith('/')) return path.slice(1);
    return path;
}

function handleEC2(request: ExternalRequest, cloud: CloudInfraSpec, metadataState: Imdsv2MetadataState): ExternalResponse {
    if (request.path.startsWith('/latest/')) {
        return handleEC2Metadata(request, cloud, metadataState);
    }

    const action = extractParam(request.path, 'Action') ?? '';

    switch (action) {
        case 'DescribeInstances': {
            const instances = (cloud.instances ?? []).map(i => ({
                InstanceId: i.instanceId,
                InstanceType: i.instanceType,
                State: { Name: i.state },
                PrivateIpAddress: i.privateIp,
                PublicIpAddress: i.publicIp ?? null,
                SubnetId: i.subnetId,
                SecurityGroups: i.securityGroups.map(sg => ({ GroupId: sg })),
                IamInstanceProfile: i.iamRole ? { Arn: `arn:aws:iam::${cloud.accountId}:instance-profile/${i.iamRole}` } : null,
                Tags: i.tags ? Object.entries(i.tags).map(([k, v]) => ({ Key: k, Value: v })) : [],
            }));

            return jsonResponse(200, {
                DescribeInstancesResponse: {
                    Reservations: [{ Instances: instances }],
                },
            });
        }

        case 'DescribeVpcs': {
            const vpcs = (cloud.vpcs ?? []).map(v => ({
                VpcId: v.vpcId,
                CidrBlock: v.cidr,
                State: 'available',
                IsDefault: false,
            }));
            return jsonResponse(200, { DescribeVpcsResponse: { Vpcs: vpcs } });
        }

        case 'DescribeSubnets': {
            const subnets: Array<{ SubnetId: string; CidrBlock: string; VpcId: string; AvailabilityZone: string; MapPublicIpOnLaunch: boolean }> = [];
            for (const vpc of (cloud.vpcs ?? [])) {
                for (const subnet of vpc.subnets) {
                    subnets.push({
                        SubnetId: subnet.subnetId,
                        CidrBlock: subnet.cidr,
                        VpcId: vpc.vpcId,
                        AvailabilityZone: subnet.availabilityZone,
                        MapPublicIpOnLaunch: subnet.public,
                    });
                }
            }
            return jsonResponse(200, { DescribeSubnetsResponse: { Subnets: subnets } });
        }

        case 'DescribeSecurityGroups': {
            const groups: Array<unknown> = [];
            for (const vpc of (cloud.vpcs ?? [])) {
                for (const sg of vpc.securityGroups) {
                    groups.push({
                        GroupId: sg.groupId,
                        GroupName: sg.name,
                        VpcId: vpc.vpcId,
                        IpPermissions: sg.ingressRules.map(r => ({
                            IpProtocol: r.protocol,
                            FromPort: r.fromPort,
                            ToPort: r.toPort,
                            IpRanges: [{ CidrIp: r.source, Description: r.description ?? '' }],
                        })),
                        IpPermissionsEgress: sg.egressRules.map(r => ({
                            IpProtocol: r.protocol,
                            FromPort: r.fromPort,
                            ToPort: r.toPort,
                            IpRanges: [{ CidrIp: r.source }],
                        })),
                    });
                }
            }
            return jsonResponse(200, { DescribeSecurityGroupsResponse: { SecurityGroups: groups } });
        }

        default:
            return jsonResponse(400, { Error: { Code: 'InvalidAction', Message: `Unknown action: ${action}` } });
    }
}

// ── CloudWatch Logs ──────────────────────────────────────────

function handleCloudWatchLogs(request: ExternalRequest, cloud: CloudInfraSpec, state: CloudWatchLogState): ExternalResponse {
    const action = extractParam(request.path, 'Action') ?? '';

    switch (action) {
        case 'DescribeLogGroups': {
            return jsonResponse(200, {
                logGroups: state.groups.map(g => ({
                    logGroupName: g.logGroupName,
                    arn: `arn:aws:logs:us-east-1:${cloud.accountId}:log-group:${g.logGroupName}`,
                })),
            });
        }

        case 'GetLogEvents': {
            const logGroupName = extractParam(request.path, 'logGroupName') ?? '';
            const group = state.groups.find(g => g.logGroupName === logGroupName);
            if (group === undefined) return jsonResponse(404, { Error: { Code: 'ResourceNotFoundException', Message: `No such log group: ${logGroupName}` } });
            const limit = Number(extractParam(request.path, 'limit') ?? '100');
            const capped = Number.isInteger(limit) && limit > 0 ? limit : 100;
            return jsonResponse(200, {
                events: group.events.slice(0, capped).map(event => ({
                    message: event.message,
                    timestamp: event.timestamp,
                    ingestionTime: event.timestamp,
                })),
                nextBackwardToken: '0',
            });
        }

        case 'FilterLogEvents': {
            const logGroupName = extractParam(request.path, 'logGroupName');
            const pattern = extractParam(request.path, 'filterPattern') ?? '';
            const groups = logGroupName === null
                ? state.groups
                : state.groups.filter(group => group.logGroupName === logGroupName);

            const events = groups.flatMap(group => group.events.filter(event => event.message.includes(pattern)));
            return jsonResponse(200, {
                events: events.map(event => ({ message: event.message, timestamp: event.timestamp })),
                searchedLogStreams: groups.map(group => ({ logGroupName: group.logGroupName, storedBytes: group.events.length * 10 })),
            });
        }

        default:
            return jsonResponse(400, { Error: { Code: 'InvalidAction', Message: `Unknown action: ${action}` } });
    }
}

// ── SNS / SQS ────────────────────────────────────────────────

function getTopicFromRequest(state: SnsTopicState, request: ExternalRequest): string | undefined {
    const requested = extractParam(request.path, 'TopicArn');
    if (requested !== null && state.topics[requested] !== undefined) return requested;
    if (requested !== null) return requested;
    return state.arns[extractParam(request.path, 'TopicName') ?? ''];
}

function handleSNS(request: ExternalRequest, _cloud: CloudInfraSpec, state: SnsTopicState): ExternalResponse {
    const action = extractParam(request.path, 'Action') ?? '';
    const body = parseJsonBody(request);

    switch (action) {
        case 'ListTopics': {
            return jsonResponse(200, {
                Topics: Object.entries(state.topics).map(([topicArn]) => ({
                    TopicArn: topicArn,
                })),
                NextToken: null,
            });
        }

        case 'Publish':
        case 'PublishMessage': {
            const topicArn = getTopicFromRequest(state, request);
            if (topicArn === undefined || state.topics[topicArn] === undefined) {
                return jsonResponse(404, { Error: { Code: 'NotFound', Message: `Topic not found` } });
            }
            const message = extractParam(request.path, 'Message') ?? (typeof body?.['Message'] === 'string' ? body['Message'] : '');
            if (message === '') {
                return jsonResponse(400, { Error: { Code: 'MissingParameter', Message: 'Message is required' } });
            }
            state.topics[topicArn]!.push(message);
            return jsonResponse(200, {
                MessageId: randomishId('msg', `${topicArn}${Date.now()}`, 16),
                TopicArn: topicArn,
            });
        }

        default:
            return jsonResponse(400, { Error: { Code: 'InvalidAction', Message: `Unknown action: ${action}` } });
    }
}

function resolveQueueUrl(state: SqsQueueState, request: ExternalRequest): string | undefined {
    const target = extractParam(request.path, 'QueueUrl')
        ?? (parseJsonBody(request)?.["QueueUrl"] as string | undefined);
    if (target === undefined) return undefined;
    if (state.queues[target] !== undefined) return target;
    return state.urls[target];
}

function handleSQS(request: ExternalRequest, state: SqsQueueState): ExternalResponse {
    const action = extractParam(request.path, 'Action') ?? '';
    const body = parseJsonBody(request);

    switch (action) {
        case 'ListQueues': {
            return jsonResponse(200, {
                QueueUrls: Object.values(state.urls),
            });
        }

        case 'SendMessage': {
            const queueUrl = resolveQueueUrl(state, request);
            if (queueUrl === undefined || state.queues[queueUrl] === undefined) {
                return jsonResponse(404, { Error: { Code: 'QueueDoesNotExist', Message: 'Queue not found' } });
            }
            const messageBody = extractParam(request.path, 'MessageBody')
                ?? (typeof body?.["MessageBody"] === 'string' ? body["MessageBody"] : '');
            if (messageBody === '') {
                return jsonResponse(400, { Error: { Code: 'MissingParameter', Message: 'MessageBody is required' } });
            }
            state.queues[queueUrl]!.push(messageBody);
            return jsonResponse(200, {
                MessageId: randomishId('msg', `${queueUrl}${Date.now()}`, 16),
                MD5OfMessageBody: randomishId('md5', messageBody, 32),
            });
        }

        case 'ReceiveMessage': {
            const queueUrl = resolveQueueUrl(state, request);
            if (queueUrl === undefined || state.queues[queueUrl] === undefined) {
                return jsonResponse(404, { Error: { Code: 'QueueDoesNotExist', Message: 'Queue not found' } });
            }
            const messages = state.queues[queueUrl]!.map((message, index) => ({
                MessageId: `msg-${index}`,
                Body: message,
                ReceiptHandle: randomishId('rh', `${queueUrl}${index}`, 16),
            }));
            state.queues[queueUrl] = [];
            return jsonResponse(200, { Messages: messages });
        }

        default:
            return jsonResponse(400, { Error: { Code: 'InvalidAction', Message: `Unknown action: ${action}` } });
    }
}

// ── Secrets Manager ────────────────────────────────────────────

function handleSecretsManager(request: ExternalRequest, cloud: CloudInfraSpec): ExternalResponse {
    const secrets = cloud.secrets ?? [];
    const target = request.headers.get('x-amz-target') ?? '';

    // ListSecrets
    if (target.includes('ListSecrets') || request.path.includes('ListSecrets')) {
        return jsonResponse(200, {
            SecretList: secrets.map(s => ({
                Name: s.name,
                Description: s.description ?? '',
                KmsKeyId: s.kmsKeyId ?? 'aws/secretsmanager',
                RotationEnabled: s.rotation ?? false,
                LastRotatedDate: s.lastRotated ?? null,
                Tags: s.tags ? Object.entries(s.tags).map(([k, v]) => ({ Key: k, Value: v })) : [],
            })),
        });
    }

    // GetSecretValue
    if (target.includes('GetSecretValue') || request.path.includes('GetSecretValue')) {
        // Parse secret name from body or query param
        let secretName = extractParam(request.path, 'SecretId') ?? '';
        if (secretName === '' && request.body !== null) {
            try {
                const bodyText = new TextDecoder().decode(request.body);
                const parsed = JSON.parse(bodyText);
                secretName = parsed.SecretId ?? '';
            } catch {
                // ignore parse errors
            }
        }

        const secret = secrets.find(s => s.name === secretName);
        if (secret === undefined) {
            return jsonResponse(404, { __type: 'ResourceNotFoundException', Message: `Secret ${secretName} not found` });
        }

        return jsonResponse(200, {
            Name: secret.name,
            SecretString: secret.value,
            VersionId: 'v1',
            CreatedDate: secret.lastRotated ?? '2024-01-01T00:00:00Z',
        });
    }

    return jsonResponse(400, { Error: { Code: 'InvalidAction' } });
}

// ── Utility ────────────────────────────────────────────────────

function extractParam(path: string, param: string): string | null {
    const qIdx = path.indexOf('?');
    if (qIdx === -1) return null;
    const queryString = path.slice(qIdx + 1);
    for (const part of queryString.split('&')) {
        const eqIdx = part.indexOf('=');
        if (eqIdx === -1) continue;
        const key = decodeURIComponent(part.slice(0, eqIdx).replace(/\+/g, ' '));
        if (key === param) {
            return decodeURIComponent(part.slice(eqIdx + 1).replace(/\+/g, ' '));
        }
    }
    return null;
}

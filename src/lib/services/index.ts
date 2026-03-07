/**
 * VARIANT — Services barrel export.
 */
export type {
    ServiceHandler,
    ServiceRequest,
    ServiceResponse,
    ServiceContext,
    ServiceEvent,
    HTTPRequestEvent,
    SSHLoginEvent,
    DNSQueryEvent,
    FileAccessEvent,
    CustomServiceEvent,
    ServiceRegistry,
} from './types';
export { createServiceRegistry } from './types';

export type {
    HTTPRoute,
    HTTPServiceConfig,
} from './http-service';
export { createHTTPService } from './http-service';

export type {
    SearchEntry,
    SearchResult,
    SearchEngineConfig,
} from './search-engine';
export { createSearchEngine } from './search-engine';

export type {
    ServiceHandlerConstructor,
    ServiceHandlerMeta,
    ServiceHandlerFactory,
} from './factory';
export { createServiceHandlerFactory } from './factory';

export type {
    ProtocolHandler,
    ProtocolConnection,
    ProtocolContext,
    ProtocolEvent,
    ProtocolHandlerRegistry,
} from './protocol-handler';
export { createProtocolHandlerRegistry } from './protocol-handler';

export { createSSHService } from './ssh-service';

export { createSMTPService } from './smtp-service';

export type {
    DNSRecordType,
    DNSRecord,
    DNSZone,
} from './dns-service';
export { createDNSService, buildZoneFromNetwork } from './dns-service';

export { createFTPService } from './ftp-service';

export type {
    MySQLDatabase,
    MySQLTable,
} from './mysql-service';
export { createMySQLService } from './mysql-service';

export type {
    LDAPConfig,
    LDAPDirectory,
    LDAPEntry,
} from './ldap-service';
export { createLDAPService } from './ldap-service';

export type {
    SMBConfig,
    SMBShare,
    SMBSession,
} from './smb-service';
export { createSMBService } from './smb-service';

export type {
    IMAPConfig,
    IMailbox,
    IMAPMessage,
} from './imap-service';
export { createIMAPService } from './imap-service';

export type {
    TelnetConfig,
    TelnetSession,
} from './telnet-service';
export { createTelnetService } from './telnet-service';

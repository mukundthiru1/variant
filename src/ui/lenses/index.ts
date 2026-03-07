/**
 * VARIANT — Lens Components
 *
 * UI components for each lens type.
 */

export { LensCompositor } from './LensCompositor';
export type { LensCompositorProps } from './LensCompositor';

export { TerminalLens } from './TerminalLens';
export type { TerminalLensProps } from './TerminalLens';

export { BrowserLens } from './BrowserLens';
export type { BrowserLensProps, BrowserResponse } from './BrowserLens';

export { FileManagerLens } from './FileManagerLens';
export type { FileManagerLensProps, FileEntry } from './FileManagerLens';

export { LogViewerLens } from './LogViewerLens';
export type { LogViewerLensProps, LogEntry } from './LogViewerLens';

export { EmailLens } from './EmailLens';
export type { EmailLensProps, EmailMessage } from './EmailLens';

export { NetworkMapLens } from './NetworkMapLens';
export type { NetworkMapLensProps, NetworkNode, NetworkEdge, TrafficFlow } from './NetworkMapLens';

export { ProcessViewerLens } from './ProcessViewerLens';
export type { ProcessViewerLensProps, ProcessInfo } from './ProcessViewerLens';

export { PacketCaptureLens } from './PacketCaptureLens';
export type { PacketCaptureLensProps, CapturedPacket } from './PacketCaptureLens';

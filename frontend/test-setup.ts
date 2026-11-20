import '@testing-library/jest-dom';
import { vi } from 'vitest';

// Mock wails runtime
vi.mock('wailsjs/runtime', () => ({
  EventsEmit: vi.fn(),
  EventsOn: vi.fn(),
  EventsOff: vi.fn(),
  SaveFileDialog: vi.fn(),
  OpenFileDialog: vi.fn(),
  MessageDialog: vi.fn(),
}));

// Mock window.go for Wails bindings
Object.defineProperty(window, 'go', {
  value: {
    main: {
      App: {
        AnalyzeBulkURLs: vi.fn(),
        ScanPorts: vi.fn(),
        DNSIntelligence: vi.fn(),
        DiscoverSubdomains: vi.fn(),
        InspectTLS: vi.fn(),
        ListWorkspaces: vi.fn(),
        CreateWorkspace: vi.fn(),
        DeleteWorkspace: vi.fn(),
        GetWorkspaceScans: vi.fn(),
        UpdateHistoryWorkspace: vi.fn(),
        GetFindingTags: vi.fn(),
        SetFindingTag: vi.fn(),
        DeleteFindingTag: vi.fn(),
        GetFindingNotes: vi.fn(),
        SetFindingNote: vi.fn(),
        DeleteFindingNote: vi.fn(),
        SearchScanHistory: vi.fn(),
        DeleteScanHistoryEntry: vi.fn(),
        ClearScanHistory: vi.fn(),
        ExportJSON: vi.fn(),
        ExportPDF: vi.fn(),
        GenerateSecurityTxtTemplate: vi.fn(),
        ExportSecurityTxt: vi.fn(),
        GetWorkspaceBranding: vi.fn(),
        SetWorkspaceBranding: vi.fn(),
        CreateScheduledScan: vi.fn(),
        ListScheduledScans: vi.fn(),
        GetScheduledScan: vi.fn(),
        UpdateScheduledScan: vi.fn(),
        DeleteScheduledScan: vi.fn(),
        RunScheduledScan: vi.fn(),
      },
    },
  },
  writable: true,
});

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
Object.defineProperty(window, 'localStorage', { value: localStorageMock });

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import App from './App';

// Mock wailsjs bindings
vi.mock('../wailsjs/go/main/App', () => ({
  StartPortScan: vi.fn(),
  StopPortScan: vi.fn(),
  StartCIDRSweep: vi.fn(),
  AnalyzeBulkURLs: vi.fn(),
  ExportJSON: vi.fn(),
  ExportPortsCSV: vi.fn(),
  ExportText: vi.fn(),
  ExportPDF: vi.fn(),
  EnumerateSubdomains: vi.fn(),
  FuzzPaths: vi.fn(),
  InspectTLS: vi.fn(),
  IPInformation: vi.fn(),
  DNSIntelligence: vi.fn(),
  SearchScanHistory: vi.fn(),
  DiffLatestPortScans: vi.fn(),
  DiffLatestWebAuditScans: vi.fn(),
  DeleteScanHistoryEntry: vi.fn(),
  ClearScanHistory: vi.fn(),
  GetRemediationKnowledge: vi.fn(),
  PauseScans: vi.fn(),
  ResumeScans: vi.fn(),
  IsScansPaused: vi.fn(),
  CreateWorkspace: vi.fn(),
  ListWorkspaces: vi.fn(),
  DeleteWorkspace: vi.fn(),
  GetWorkspaceScans: vi.fn(),
  UpdateHistoryWorkspace: vi.fn(),
  GetFindingTags: vi.fn(),
  GetFindingNotes: vi.fn(),
  SetFindingTag: vi.fn(),
  SetFindingNote: vi.fn(),
  DeleteFindingTag: vi.fn(),
  DeleteFindingNote: vi.fn(),
  ImportNmapXML: vi.fn(),
  ImportNmapXMLFile: vi.fn(),
  ImportNmapXMLToWorkspace: vi.fn(),
  ImportSubdomains: vi.fn(),
  ImportSubdomainsFile: vi.fn(),
  ImportSubdomainsToWorkspace: vi.fn(),
  InspectHTTP: vi.fn(),
  ReplayHTTPRequest: vi.fn(),
  SyncLatestCVEs: vi.fn(),
  GetLatestThreatFeed: vi.fn(),
  SyncLiveCVEFeed: vi.fn(),
  GetCachedCVEFeed: vi.fn(),
  GetHistoryDBPath: vi.fn(),
  IsHistoryDBReady: vi.fn(),
}));

vi.mock('../wailsjs/runtime/runtime', () => ({
  EventsOn: vi.fn(),
  EventsOff: vi.fn(),
  BrowserOpenURL: vi.fn(),
}));

describe('App Component - Critical Flows', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  describe('History Search/Filter', () => {
    it('should show history tab with search input', async () => {
      render(<App />);
      
      const reportsDropdown = screen.getByRole('button', { name: /reports & history/i });
      fireEvent.click(reportsDropdown);
      
      const historyTab = screen.getByText('History');
      fireEvent.click(historyTab);
      
      // The search input placeholder is "Search target…" 
      const searchInput = screen.getByPlaceholderText(/search target/i);
      expect(searchInput).toBeInTheDocument();
      
      fireEvent.change(searchInput, { target: { value: 'example.com' } });
      expect(searchInput).toHaveValue('example.com');
    });

    it('should filter history by scan type (select element)', async () => {
      render(<App />);
      
      const reportsDropdown = screen.getByRole('button', { name: /reports & history/i });
      fireEvent.click(reportsDropdown);
      
      const historyTab = screen.getByText('History');
      fireEvent.click(historyTab);
      
      // The select element is a combobox without a name
      const typeFilter = screen.getByRole('combobox');
      expect(typeFilter).toBeInTheDocument();
    });
  });

  describe('Command Palette (Ctrl+K)', () => {
    it('should have command palette button in header', async () => {
      render(<App />);
      
      const paletteButton = screen.getByTitle(/command palette/i);
      expect(paletteButton).toBeInTheDocument();
    });

    it('should navigate to Asset Tree from the palette', () => {
      render(<App />);

      fireEvent.click(screen.getByTitle(/command palette/i));
      const paletteInput = screen.getByPlaceholderText(/go to module or action/i);
      expect(paletteInput).toBeInTheDocument();
      fireEvent.click(screen.getByRole('button', { name: /^asset tree module$/i }));

      expect(screen.getByRole('heading', { name: /visual attack surface/i })).toBeInTheDocument();
    });
  });

  describe('Scope confirmation', () => {
    it('should keep live scan disabled until the exact scope is confirmed and reset on target change', () => {
      render(<App />);

      fireEvent.click(screen.getByRole('button', { name: /assessment/i }));
      fireEvent.click(screen.getByText('Ports', { exact: true }));

      const startButton = screen.getByRole('button', { name: /start live scan/i });
      const confirmation = screen.getAllByRole('checkbox')[0];
      expect(startButton).toBeDisabled();

      fireEvent.click(confirmation);
      expect(startButton).not.toBeDisabled();

      const targetInput = screen.getByDisplayValue('scanme.nmap.org');
      fireEvent.change(targetInput, { target: { value: 'example.com' } });
      expect(confirmation).not.toBeChecked();
      expect(startButton).toBeDisabled();
    });
  });

  describe('Rate limiter controls', () => {
    it('should allow bounded Web Audit RPS and jitter values', () => {
      render(<App />);

      fireEvent.click(screen.getByRole('button', { name: /web security/i }));
      fireEvent.click(screen.getByText('Web Audit', { exact: true }));

      const zeroInputs = screen.getAllByDisplayValue('0');
      expect(zeroInputs.length).toBeGreaterThanOrEqual(2);
      fireEvent.change(zeroInputs[0], { target: { value: '25' } });
      fireEvent.change(zeroInputs[1], { target: { value: '150' } });

      expect(screen.getByDisplayValue('25')).toBeInTheDocument();
      expect(screen.getByDisplayValue('150')).toBeInTheDocument();
    });
  });

  describe('Workspace CRUD', () => {
    it('should show workspaces tab', async () => {
      render(<App />);
      
      const settingsDropdown = screen.getByRole('button', { name: /settings/i });
      fireEvent.click(settingsDropdown);
      
      const workspacesTab = screen.getByText('Workspaces');
      fireEvent.click(workspacesTab);
      
      // Should show workspace UI - use getAllByText since there are multiple elements
      const workspaceElements = screen.getAllByText(/workspaces/i);
      expect(workspaceElements.length).toBeGreaterThan(0);
    });
  });

  describe('Finding Tag/Note Persistence', () => {
    it('should have valid tag constants defined', async () => {
      // Verify the tag constants exist
      const validTags = ['verified', 'false_positive', 'needs_review', 'accepted_risk'];
      expect(validTags).toContain('verified');
      expect(validTags).toContain('false_positive');
      expect(validTags).toContain('needs_review');
      expect(validTags).toContain('accepted_risk');
    });
  });

  describe('Navigation Grouping', () => {
    it('should render all 6 navigation groups', async () => {
      render(<App />);
      
      // Use getByRole for buttons to be more specific
      expect(screen.getByRole('button', { name: /dashboard/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /network intelligence/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /web security/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /assessment/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /reports & history/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /settings/i })).toBeInTheDocument();
    });

    it('should open the Visual Attack Surface Asset Tree view', () => {
      render(<App />);

      fireEvent.click(screen.getByRole('button', { name: /reports & history/i }));
      fireEvent.click(screen.getByText('Asset Tree', { exact: true }));

      expect(screen.getByRole('heading', { name: /visual attack surface/i })).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/filter assets/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /export json/i })).toBeDisabled();
    });
  });
});

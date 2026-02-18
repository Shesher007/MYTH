import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Sidebar from './components/Sidebar';
import ChatWindow from './components/ChatWindow';
import CommandPalette from './components/CommandPalette';
import TopologyModal from './components/TopologyModal';
import PreviewModal from './components/PreviewModal';

import SettingsModal from './components/SettingsModal';
import NotificationToast from './components/NotificationToast';
import { useAgent } from './hooks/useAgent';
import { useSoundscape } from './hooks/useSoundscape';
import FpsIndicator from './components/FpsIndicator';
import LatencyIndicator from './components/LatencyIndicator';
import NetworkPingIndicator from './components/NetworkPingIndicator';
import { PanelLeft, Plus } from 'lucide-react';

// DEBUG VERSION 4: FULL RESTORATION
function App() {
  const {
    messages,
    sendMessage,
    isProcessing,
    currentStatus,
    activeNode,
    activeModel,
    usedTools,
    logs,
    thoughts,
    thinkingStartTime,
    stopGeneration,
    uploadDocument,
    uploadFileWithProgress,
    indexFolder,
    browseFolder,
    getFolderSummary,
    generatedFiles,
    downloadFile,
    deleteGeneratedFile,
    renameFile,
    setMessages,
    setLogs,
    systemStatus,

    networkConnections,
    securityAlerts,
    clearAlerts,
    isolateNode,
    systemSessions,
    complianceReport,
    isScanning,
    runSystemScan,
    vpnStatus,
    vpnNodes,
    toggleVpn,
    architectureMode,
    switchArchitecture,
    systemProcesses,
    speakingMode,
    setSpeakingMode,
    settingsKeys,
    updateSettingsKeys,
    purgeSession,
    notifications,
    dismissNotification,
    clearAllNotifications,
    addNotification
  } = useAgent();

  const { playChirp, playTick, playSuccess } = useSoundscape();
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = React.useState(false);
  const [isTopologyOpen, setIsTopologyOpen] = React.useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = React.useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = React.useState(false);
  const [windowWidth, setWindowWidth] = React.useState(window.innerWidth);
  const [isPreviewOpen, setIsPreviewOpen] = React.useState(false);
  const [activePreviewFile, setActivePreviewFile] = React.useState(null);

  // Command Palette Shortcut
  React.useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        playChirp();
        setIsCommandPaletteOpen(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [playChirp]);


  // Memoized handlers to prevent Sidebar re-renders
  const handleToggleCollapse = React.useCallback(() => {
    playTick();
    setIsSidebarCollapsed(prev => !prev);
  }, [playTick]);

  // handleClearMessages removed - superceded by purgeSession
  const handleOpenSettings = React.useCallback(() => setIsSettingsOpen(true), []);
  const handleCloseSettings = React.useCallback(() => setIsSettingsOpen(false), []);
  const handleCloseCommandPalette = React.useCallback(() => setIsCommandPaletteOpen(false), []);
  const handleCloseTopology = React.useCallback(() => setIsTopologyOpen(false), []);
  const handleTopologyOpen = React.useCallback(() => setIsTopologyOpen(true), []);

  const handlePreviewFile = React.useCallback((file) => {
    setActivePreviewFile(file);
    setIsPreviewOpen(true);
  }, []);

  const commandActions = React.useMemo(() => [
    {
      id: 'clear-session',
      label: 'Purge Session',
      description: 'Clear all messages and reset neural link',
      run: () => { purgeSession(); playSuccess(); }
    },
    {
      id: 'refresh-assets',
      label: 'Sync Assets',
      description: 'Synchronize local asset inventory',
      run: () => { playSuccess(); } // Now automatic via Telemetry
    },
    {
      id: 'system-scan',
      label: 'Run Deep Scan',
      description: 'Initiate full system diagnostic',
      run: () => { runSystemScan(); playSuccess(); }
    },
  ], [setMessages, playSuccess, runSystemScan, setIsTopologyOpen]);


  // Responsive Window Observer
  React.useEffect(() => {
    const handleResize = () => {
      const width = window.innerWidth;
      setWindowWidth(width);
      if (width < 1100 && !isSidebarCollapsed) {
        setIsSidebarCollapsed(true);
      }
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [isSidebarCollapsed]);

  return (
    <div className={`flex h-screen bg-[#050508] text-slate-300 overflow-hidden font-sans selection:bg-teal-500/30 relative`}>
      {/* Deep Chassis Grid Layer */}
      <div className="grid-background" />

      {/* Dual-Tone Neural Spark System - PERFORMANCE OPTIMIZED */}
      <div className="sparks-container">
        {/* Optimized Static Sparks to reduce JS execution overhead */}
        <div className="spark green" style={{ left: '10%', animationDelay: '0s', animationDuration: '4s' }} />
        <div className="spark" style={{ left: '50%', animationDelay: '4s', animationDuration: '5s' }} />
        <div className="spark green" style={{ left: '90%', animationDelay: '3s', animationDuration: '5s' }} />
      </div>

      {/* Global System Readiness Banner */}
      <AnimatePresence>
        {!systemStatus.ready && (
          <motion.div 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed top-0 left-0 right-0 z-[1000] flex justify-center pointer-events-none"
          >
            <div className="mt-4 px-6 py-2 bg-teal-500/10 border border-teal-500/30 backdrop-blur-xl rounded-full flex items-center gap-4 shadow-[0_0_30px_rgba(20,184,166,0.2)]">
              <div className="flex gap-1.5">
                <div className="w-1 h-3 bg-teal-500/60 animate-[pulse_1s_infinite]"></div>
                <div className="w-1 h-3 bg-teal-500/40 animate-[pulse_1s_infinite_0.2s]"></div>
                <div className="w-1 h-3 bg-teal-500/20 animate-[pulse_1s_infinite_0.4s]"></div>
              </div>
              <div className="flex flex-col">
                <span className="text-[10px] font-black text-teal-400 uppercase tracking-[0.3em] leading-none mb-0.5">System Re-initializing</span>
                <span className="text-[7px] font-mono text-teal-500/50 uppercase tracking-widest">Reloading Neural Matrix & MCP Infrastructure</span>
              </div>
              <div className="w-1.5 h-1.5 rounded-full bg-teal-500 animate-ping"></div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      <div
        className={`transition-all duration-500 ease-[cubic-bezier(0.4,0,0.2,1)] relative z-[200] sidebar-container h-screen overflow-hidden ${isSidebarCollapsed ? 'w-0' : 'w-[var(--sidebar-width)]'}`}
      >
        <Sidebar
          isCollapsed={isSidebarCollapsed}
          onToggleCollapse={handleToggleCollapse}
          logs={logs}
          onClearMessages={purgeSession}
          generatedFiles={generatedFiles}
          onDownloadFile={downloadFile}
          onDeleteFile={deleteGeneratedFile}
          onRenameFile={renameFile}
          onPreviewFile={handlePreviewFile}
          onRefreshFiles={() => {}} // Now automatic via Telemetry
          stats={systemStatus}
          securityAlerts={securityAlerts}
          onClearAlerts={clearAlerts}
          isolateNode={isolateNode}
          systemSessions={systemSessions}
          complianceReport={complianceReport}
          isScanning={isScanning}
          runSystemScan={runSystemScan}
          vpnStatus={vpnStatus}
          vpnNodes={vpnNodes}
          toggleVpn={toggleVpn}
          onOpenSettings={handleOpenSettings}
        />
      </div>

      <main className="flex-1 flex flex-col min-w-0 relative overflow-hidden">
        {/* Centralized Mission Watermark */}
        <div className="mission-backdrop" />
        {/* Neuro-Scan Pulse Header */}
        <div className="h-[2px] w-full bg-slate-900 relative overflow-hidden shrink-0">
          <motion.div
            className="absolute top-0 bottom-0 w-1/3 bg-gradient-to-r from-transparent via-teal-500/50 to-transparent"
            animate={{ x: ['-100%', '300%'] }}
            transition={{ repeat: Infinity, duration: 4, ease: "linear" }}
          />
        </div>

        <div className="h-12 border-b border-white/5 bg-black/40 backdrop-blur-md flex items-center justify-between px-6 shrink-0 z-10">
          <div className="flex items-center gap-6">
            <button
              onClick={() => { playTick(); setIsSidebarCollapsed(!isSidebarCollapsed); }}
              className={`p-1.5 rounded-md transition-all ${isSidebarCollapsed ? 'bg-teal-500/10 text-teal-400 border border-teal-500/30' : 'bg-white/5 text-slate-500 border border-white/10 hover:border-teal-500/30 hover:text-teal-400'}`}
              title={isSidebarCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
            >
              <PanelLeft size={16} className="hover:scale-110 transition-transform" />
            </button>
            <div className="flex flex-col gap-0.5">
              <span className="text-[10px] font-black text-slate-100 uppercase tracking-[0.3em] whitespace-nowrap">Synapse Console</span>
              <div className="flex items-center gap-2 telemetry-label-text">
                <div className="w-1.5 h-1.5 rounded-full bg-teal-500 shadow-[0_0_8px_rgba(20,184,166,0.6)] animate-pulse"></div>
                <span className="text-[7px] font-mono text-teal-500/70 uppercase">Telemetry: Active</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4 hud-module-gap">
            <button
              onClick={handleTopologyOpen}
              className="px-3 py-1.5 rounded border border-white/5 bg-white/[0.02] hover:bg-teal-500/10 hover:border-teal-500/30 text-slate-400 hover:text-teal-400 text-[9px] font-black uppercase tracking-widest transition-all"
            >
              Connectivity
            </button>
            <div className={`px-3 py-1.5 rounded border text-[9px] font-black uppercase tracking-widest transition-all ${vpnStatus.connected
              ? 'bg-teal-500/10 border-teal-500/30 text-teal-400 shadow-[0_0_10px_rgba(20,184,166,0.1)]'
              : 'bg-white/5 border-white/10 text-slate-500'
              }`}>
              {vpnStatus.connected ? 'Encrypted' : 'Standard'}
            </div>

            {/* Real-time Performance Indicators */}
            <div className="flex items-center gap-3">
              <FpsIndicator />
              <NetworkPingIndicator 
                networkPing={systemStatus.metrics.network_ping} 
                networkSpeed={systemStatus.metrics.network_speed}
              />
              <LatencyIndicator latency={systemStatus.metrics.latency} />
            </div>

            <div className="h-4 w-[1px] bg-white/10 mx-1"></div>

            <div className="flex items-center gap-2">
                {/* Legacy Links Removed */}
            </div>
          </div>

        </div>

        <div className="flex-1 min-h-0">
          <ChatWindow
            messages={messages}
            onSendMessage={sendMessage}
            isProcessing={isProcessing}
            currentStatus={currentStatus}
            activeNode={activeNode}
            activeModel={activeModel}
            usedTools={usedTools}
            logs={logs}
            thoughts={thoughts}
            thinkingStartTime={thinkingStartTime}
            onStopGeneration={stopGeneration}
            onUploadFile={uploadDocument}
            uploadFileWithProgress={uploadFileWithProgress}
            onIndexFolder={indexFolder}
            browseFolder={browseFolder}
            getFolderSummary={getFolderSummary}
            generatedFiles={generatedFiles}
            architectureMode={architectureMode}
            onSwitchArchitecture={switchArchitecture}
            speakingMode={speakingMode}
            setSpeakingMode={setSpeakingMode}
            onPreviewFile={handlePreviewFile}
          />
        </div>


      </main>

      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={handleCloseCommandPalette}
        actions={commandActions}
      />

      <TopologyModal
        isOpen={isTopologyOpen}
        onClose={handleCloseTopology}
        connections={networkConnections}
        activeNode={systemStatus.ip}
      />
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={handleCloseSettings}
        settingsKeys={settingsKeys}
        onSave={updateSettingsKeys}
      />

      <PreviewModal
        isOpen={isPreviewOpen}
        onClose={() => setIsPreviewOpen(false)}
        file={activePreviewFile}
      />
      
      {/* Industrial Notification Toast System */}
      <NotificationToast 
        notifications={notifications} 
        onDismiss={dismissNotification} 
        onClearAll={clearAllNotifications}
      />
    </div>
  );
}

export default App;

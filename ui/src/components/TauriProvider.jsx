// MYTH Desktop — Tauri Provider (Context + Gates)
// Wraps the app with Tauri-specific functionality:
// - License gate (activation screen if not licensed)
// - Maintenance mode overlay
// - Session memory indicator
// - Crash recovery banner
// - Native notification bridge

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import ActivationScreen from './ActivationScreen';
import MaintenanceScreen from './MaintenanceScreen';
import UpdatePrompt from './UpdatePrompt';
import CrashRecoveryBanner from './CrashRecoveryBanner';

const TauriContext = createContext(null);

export const useTauri = () => useContext(TauriContext);

// Detect if running in Tauri desktop shell
const IS_DESKTOP = typeof window !== 'undefined' && !!window.__TAURI__;

export default function TauriProvider({ children }) {
  const [appState, setAppState] = useState(null);
  const [isLoading, setIsLoading] = useState(IS_DESKTOP);
  const [maintenanceInfo, setMaintenanceInfo] = useState(null);
  const [updateInfo, setUpdateInfo] = useState(null);
  const [crashInfo, setCrashInfo] = useState(null);
  const [showCrashBanner, setShowCrashBanner] = useState(false);

  // Initialize Tauri state on mount
  useEffect(() => {
    if (!IS_DESKTOP) {
      setIsLoading(false);
      return;
    }

    const init = async () => {
      try {
        const { invoke } = await import('@tauri-apps/api/core');

        // Parallelize checks for ultra-fast startup (Feature: Remote Control Optimization)
        const [appStateResult, crashResult, maintenanceResult, updateResult] = await Promise.all([
          invoke('get_app_state').catch(e => { console.error('App state error:', e); return null; }),
          invoke('get_crash_info').catch(e => { console.warn('Crash check error:', e); return { crash_detected: false }; }),
          invoke('check_maintenance_mode').catch(e => { console.warn('Maintenance check error:', e); return { maintenance: false }; }),
          invoke('check_for_updates').catch(e => { console.warn('Update check error:', e); return { update_available: false }; })
        ]);

        // 1. App State
        if (appStateResult) {
          setAppState(appStateResult);

          // 2. Crash Recovery
          if (appStateResult.crash_detected && crashResult?.crash_detected) {
            setCrashInfo(crashResult);
            setShowCrashBanner(true);
          }
        }

        // 3. Maintenance Mode
        if (maintenanceResult?.maintenance) {
          setMaintenanceInfo(maintenanceResult);
        }

        // 4. Updates
        if (updateResult?.update_available || updateResult?.force_update) {
          setUpdateInfo(updateResult);
        }
      } catch (e) {
        console.error('[TAURI] Initialization failed:', e);
      } finally {
        setIsLoading(false);
      }
    };

    init();
  }, []);

  // License activation handler
  const handleActivation = useCallback(async (key) => {
    if (!IS_DESKTOP) return { success: false, error: 'Not desktop mode' };
    const { invoke } = await import('@tauri-apps/api/core');
    const result = await invoke('activate_license', { key });
    if (result.success) {
      setAppState(prev => ({ ...prev, license_valid: true }));
    }
    return result;
  }, []);

  // Native notification helper
  const sendNotification = useCallback(async (title, body, icon) => {
    if (!IS_DESKTOP) return;
    try {
      const { sendNotification: notify } = await import('@tauri-apps/plugin-notification');
      await notify({ title, body, icon });
    } catch (e) {
      console.warn('[TAURI] Notification failed:', e);
    }
  }, []);

  // If loading, show splash
  if (isLoading) {
    return (
      <div className="fixed inset-0 bg-[#0a0a0f] flex items-center justify-center z-[9999]">
        <div className="text-center">
          <div className="text-5xl mb-4 animate-pulse">⌬</div>
          <p className="text-gray-400 text-sm font-mono">Initializing MYTH Desktop Shell...</p>
          <div className="mt-4 w-48 h-1 bg-gray-800 rounded-full overflow-hidden mx-auto">
            <div className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 animate-[shimmer_1.5s_infinite]"
              style={{ width: '60%', animation: 'shimmer 1.5s ease-in-out infinite alternate' }} />
          </div>
        </div>
      </div>
    );
  }

  // Maintenance mode gate (Feature 7)
  if (maintenanceInfo?.maintenance) {
    return <MaintenanceScreen info={maintenanceInfo} />;
  }

  // Forced update gate (Feature 6)
  if (updateInfo?.force_update) {
    return <UpdatePrompt info={updateInfo} forced />;
  }

  // License gate (Feature 9) — Desktop only
  if (IS_DESKTOP && appState && !appState.license_valid) {
    return <ActivationScreen onActivate={handleActivation} />;
  }

  const tauriContext = {
    isDesktop: IS_DESKTOP,
    appState,
    sendNotification,
    updateInfo,
    crashInfo,
  };

  return (
    <TauriContext.Provider value={tauriContext}>
      {/* Crash recovery banner (Feature 17) */}
      {showCrashBanner && (
        <CrashRecoveryBanner
          info={crashInfo}
          onDismiss={() => setShowCrashBanner(false)}
        />
      )}

      {/* Optional update prompt (non-forced) */}
      {updateInfo?.update_available && !updateInfo?.force_update && (
        <UpdatePrompt info={updateInfo} onDismiss={() => setUpdateInfo(null)} />
      )}

      {/* Session memory indicator (Feature 4) */}
      {IS_DESKTOP && (
        <div className="fixed bottom-2 right-2 z-[9998] px-3 py-1.5 bg-gray-900/80 backdrop-blur-sm border border-gray-700/50 rounded-full text-[10px] text-gray-500 font-mono flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500/60 animate-pulse" />
          Temporary session memory
        </div>
      )}

      {children}
    </TauriContext.Provider>
  );
}

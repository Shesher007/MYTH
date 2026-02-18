import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, CheckCircle, Info, XCircle, X, Bell } from 'lucide-react';
import { useSoundscape } from '../hooks/useSoundscape';
import './NotificationToast.css';

/**
 * Industrial Cyber Notification Toast System
 * Displays a stack of animated toasts for errors, warnings, and system events.
 */
const NotificationToast = ({ notifications = [], onDismiss, onClearAll }) => {
  const { playChirp, playSuccess, playError } = useSoundscape();
  // Use a ref to track processed notification IDs to avoid double-chirping
  const processedIds = React.useRef(new Set());
  const lastSoundTime = React.useRef(0);
  const SOUND_COOLDOWN = 150; // ms

  // Listen for new notifications to play sounds
  React.useEffect(() => {
    const now = Date.now();
    let soundPlayed = false;

    notifications.forEach(notif => {
      if (!processedIds.current.has(notif.id)) {
        processedIds.current.add(notif.id);
        
        // Advanced Throttling: Only play sound if cooldown has passed
        if (!soundPlayed && (now - lastSoundTime.current) > SOUND_COOLDOWN) {
          // Play type-specific industrial sound
          switch (notif.type) {
            case 'ERROR': playError(); break;
            case 'SUCCESS': playSuccess(); break;
            default: playChirp(); break;
          }
          lastSoundTime.current = now;
          soundPlayed = true;
        }
      }
    });

    // Prune set to prevent memory bloom (keep only current active IDs)
    const currentIds = new Set(notifications.map(n => n.id));
    for (let id of processedIds.current) {
      if (!currentIds.has(id)) {
        processedIds.current.delete(id);
      }
    }
  }, [notifications, playChirp, playSuccess, playError]);

  const getIcon = (type) => {
    switch (type) {
      case 'ERROR': return <XCircle size={18} className="notification-icon error" />;
      case 'WARNING': return <AlertTriangle size={18} className="notification-icon warning" />;
      case 'SUCCESS': return <CheckCircle size={18} className="notification-icon success" />;
      case 'INFO':
      default: return <Info size={18} className="notification-icon info" />;
    }
  };

  const getTypeClass = (type) => {
    switch (type) {
      case 'ERROR': return 'toast-error';
      case 'WARNING': return 'toast-warning';
      case 'SUCCESS': return 'toast-success';
      case 'INFO':
      default: return 'toast-info';
    }
  };

  const formatTime = (timestamp) => {
    try {
      const date = new Date(timestamp);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return '--:--';
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // Subtle audio feedback for copy
    playChirp();
  };

  // Show only the latest 5 notifications
  const visibleNotifications = notifications.slice(-5);

  return (
    <div className="notification-container">
      <AnimatePresence mode="popLayout">
        {visibleNotifications.map((notif) => (
          <ToastItem 
            key={notif.id} 
            notif={notif} 
            onDismiss={onDismiss} 
            getIcon={getIcon}
            getTypeClass={getTypeClass}
            formatTime={formatTime}
            copyToClipboard={copyToClipboard}
          />
        ))}
      </AnimatePresence>

      <div className="notification-footer">
        {notifications.length > 1 && (
          <button className="notification-clear-btn" onClick={onClearAll}>
             Clear All Matrix
          </button>
        )}
        {notifications.length > 5 && (
          <div className="notification-overflow-badge">
            <Bell size={12} />
            <span>+{notifications.length - 5} more</span>
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * Individual Toast Item with internal timer, progress bar, and hover-pause
 */
const ToastItem = ({ notif, onDismiss, getIcon, getTypeClass, formatTime, copyToClipboard }) => {
  const AUTO_DISMISS_TIME = 8000; // 8 seconds
  const [remaining, setRemaining] = React.useState(AUTO_DISMISS_TIME);
  const [isPaused, setIsPaused] = React.useState(false);
  
  // Industrial Cyber Metadata
  const industrialId = React.useMemo(() => {
    const hex = Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0').toUpperCase();
    return `SEC_EVT_${hex}`;
  }, []);

  React.useEffect(() => {
    if (isPaused) return;

    const timer = setTimeout(() => {
      onDismiss && onDismiss(notif.id);
    }, remaining);
    
    const startTimeTick = Date.now();
    return () => {
      clearTimeout(timer);
      setRemaining(prev => Math.max(0, prev - (Date.now() - startTimeTick)));
    };
  }, [notif.id, onDismiss, isPaused]);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 100, scale: 0.9, rotateY: 20 }}
      animate={{ opacity: 1, x: 0, scale: 1, rotateY: 0 }}
      exit={{ opacity: 0, x: 100, scale: 0.9, rotateY: -20 }}
      transition={{ type: 'spring', stiffness: 400, damping: 30 }}
      className={`notification-toast ${getTypeClass(notif.type)} ${isPaused ? 'toast-paused' : ''}`}
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      <div className="toast-border-top-left" />
      <div className="toast-border-bottom-right" />
      <div className="toast-glow" />
      <div className="toast-scanline" />
      
      <div className="toast-content">
        <div className="toast-header">
          <div className="toast-id-badge">{industrialId}</div>
          <span className="toast-time">{formatTime(notif.timestamp)}</span>
          <button 
            className="toast-dismiss"
            onClick={() => onDismiss && onDismiss(notif.id)}
            aria-label="Dismiss notification"
          >
            <X size={12} />
          </button>
        </div>

        <div className="toast-body">
          <div className="toast-status-bar">
            {getIcon(notif.type)}
            <span className="toast-title">
              {notif.title}
              {notif.count > 1 && <span className="toast-count-badge">x{notif.count}</span>}
            </span>
          </div>
          
          <p 
            className={`toast-message ${notif.type === 'ERROR' ? 'glitch-text' : ''}`} 
            onClick={() => copyToClipboard(notif.message)}
            data-text={notif.message}
          >
            {notif.message}
          </p>
        </div>
      </div>

      <div 
        className="toast-progress" 
        style={{ 
          animationDuration: `${AUTO_DISMISS_TIME}ms`,
          animationPlayState: isPaused ? 'paused' : 'running'
        }} 
      />
    </motion.div>
  );
};




export default NotificationToast;

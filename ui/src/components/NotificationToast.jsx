import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';
import { useSoundscape } from '../hooks/useSoundscape';
import './NotificationToast.css';

/**
 * Tactical Command-Line Notification System
 * High-density, row-based alerts with industrial protocols.
 */
const NotificationToast = ({ notifications = [], onDismiss, onClearAll }) => {
  const { playChirp, playSuccess, playError } = useSoundscape();
  const processedIds = React.useRef(new Set());
  const lastSoundTime = React.useRef(0);
  const SOUND_COOLDOWN = 150;

  React.useEffect(() => {
    const now = Date.now();
    let soundPlayed = false;

    notifications.forEach(notif => {
      if (!processedIds.current.has(notif.id)) {
        processedIds.current.add(notif.id);

        // Priority Sound Filter: Only play for ERROR/WARNING
        if (['ERROR', 'WARNING'].includes(notif.type)) {
          if (!soundPlayed && (now - lastSoundTime.current) > SOUND_COOLDOWN) {
            if (notif.type === 'ERROR') playError();
            else playChirp(); // Using chirp for WARNING

            lastSoundTime.current = now;
            soundPlayed = true;
          }
        }
      }
    });

    const currentIds = new Set(notifications.map(n => n.id));
    for (let id of processedIds.current) {
      if (!currentIds.has(id)) processedIds.current.delete(id);
    }
  }, [notifications, playChirp, playSuccess, playError]);

  // Priority Visual Filter: Only materialize ERROR and WARNING protocols
  const priorityNotifications = notifications.filter(n => ['ERROR', 'WARNING'].includes(n.type));
  const visibleNotifications = priorityNotifications.slice(-8);


  return (
    <div className="notification-container">
      <AnimatePresence mode="popLayout">
        {visibleNotifications.map((notif) => (
          <ToastItem
            key={notif.id}
            notif={notif}
            onDismiss={onDismiss}
          />
        ))}
      </AnimatePresence>

      {notifications.length > 2 && (
        <div className="notification-footer">
          <button className="notification-clear-btn" onClick={onClearAll}>
            PURGE_LOGS
          </button>
        </div>
      )}
    </div>
  );
};

const ToastItem = ({ notif, onDismiss }) => {
  const AUTO_DISMISS_TIME = 6000;
  const [remaining, setRemaining] = React.useState(AUTO_DISMISS_TIME);
  const [isPaused, setIsPaused] = React.useState(false);

  const industrialId = React.useMemo(() => {
    return Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0').toUpperCase();
  }, []);

  const protocol = React.useMemo(() => {
    switch (notif.type) {
      case 'ERROR': return '[ FAILURE ]';
      case 'WARNING': return '[ WARNING ]';
      case 'SUCCESS': return '[ SYNC_OK ]';
      default: return '[ SEC_EVT ]';
    }
  }, [notif.type]);

  React.useEffect(() => {
    if (isPaused) return;
    const timer = setTimeout(() => onDismiss && onDismiss(notif.id), remaining);
    const startTimeTick = Date.now();
    return () => {
      clearTimeout(timer);
      setRemaining(prev => Math.max(0, prev - (Date.now() - startTimeTick)));
    };
  }, [notif.id, onDismiss, isPaused]);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: 20, filter: 'blur(10px)' }}
      animate={{ opacity: 1, x: 0, filter: 'blur(0px)' }}
      exit={{ opacity: 0, x: 40, filter: 'blur(10px)' }}
      className={`notification-toast toast-${notif.type.toLowerCase()}`}
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      <div className="toast-border-top-left" />
      <div className="toast-border-bottom-right" />
      <div className="toast-scanline" />

      <div className="toast-content">
        <div className="toast-header">
          <span className="toast-id-badge">ID_{industrialId}</span>
          <div className="toast-status-protocol">{protocol}</div>
        </div>

        <div className="toast-body">
          <span className="toast-title">{notif.title}</span>
          <span
            className={`toast-message ${notif.type === 'ERROR' ? 'glitch-text' : ''}`}
            title={notif.message}
          >
            {notif.message}
          </span>
        </div>

        <button
          className="toast-dismiss"
          onClick={() => onDismiss && onDismiss(notif.id)}
        >
          <X size={10} />
        </button>
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

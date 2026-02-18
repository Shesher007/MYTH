import { useState, useEffect, useRef } from 'react';

/**
 * useFPS Hook
 * Calculates high-fidelity instantaneous frames per second (FPS).
 * Uses a 60-frame rolling window to provide "ground truth" performance metrics
 * without the jitter of sub-frame measurement.
 * 
 * @param {number} windowSize - Number of frames to average for smooth but responsive telemetry.
 * @returns {number} The current calculated high-fidelity FPS.
 */
export function useFPS(windowSize = 60) {
  const [fps, setFps] = useState(0);
  const frameTimesRef = useRef([]);
  const frameCountRef = useRef(0);
  const requestRef = useRef();

  useEffect(() => {
    const animate = (time) => {
      const frameTimes = frameTimesRef.current;
      frameTimes.push(time);

      // Keep only the last N samples
      if (frameTimes.length > windowSize) {
        frameTimes.shift();
      }

      frameCountRef.current++;

      if (frameTimes.length > 1) {
        // Calculate average frame delta over the window
        const duration = frameTimes[frameTimes.length - 1] - frameTimes[0];
        const avgDelta = duration / (frameTimes.length - 1);
        
        // Convert to FPS
        const currentFps = Math.round(1000 / avgDelta);
        
        // Throttled state update: Update every 10th frame
        if (frameCountRef.current % 10 === 0) {
          setFps(currentFps);
        }
      }

      requestRef.current = requestAnimationFrame(animate);
    };

    requestRef.current = requestAnimationFrame(animate);
    
    return () => {
      if (requestRef.current) {
        cancelAnimationFrame(requestRef.current);
      }
    };
  }, [windowSize]);

  return fps;
}

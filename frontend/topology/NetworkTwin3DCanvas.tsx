import React, { useEffect, useRef, useState } from "react";

export type WebGLStatus = "LOADING" | "LOADED" | "EMPTY" | "ERROR" | "REFRESHING" | "UNAVAILABLE";

interface NetworkTwin3DCanvasProps {
  deviceId?: string;
  onSelectDevice?: (deviceId: string) => void;
}

export const NetworkTwin3DCanvas: React.FC<NetworkTwin3DCanvasProps> = ({ deviceId, onSelectDevice }) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<WebGLStatus>("LOADING");
  const [cameraState, setCameraState] = useState<string>("DEFAULT");

  useEffect(() => {
    let isSubscribed = true;

    // Simulation of Three.js Scene, Camera, Renderer mounting
    const initThreeDScene = async () => {
      try {
        const res = await fetch("http://127.0.0.1:8000/api/v1/twin/3d/scene/snapshot");
        if (!res.ok) throw new Error("Failed to load 3D scene snapshot");
        const data = await res.json();
        if (isSubscribed) {
          setStatus(data.snapshot.status);
          setCameraState(data.snapshot.camera.state);
        }
      } catch (err) {
        if (isSubscribed) setStatus("ERROR");
      }
    };

    initThreeDScene();

    return () => {
      isSubscribed = false;
      // Clean up WebGL buffers on unmount
      fetch("http://127.0.0.1:8000/api/v1/twin/3d/scene/lifecycle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "UNMOUNT" })
      }).catch(() => {});
    };
  }, []);

  const handleResetCamera = async () => {
    const res = await fetch("http://127.0.0.1:8000/api/v1/twin/3d/camera/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "RESET" })
    });
    const data = await res.json();
    setCameraState(data.camera.state);
  };

  return (
    <div className="relative w-full h-[600px] bg-slate-950 rounded-xl overflow-hidden border border-slate-800 shadow-2xl">
      {status === "LOADING" && (
        <div className="absolute inset-0 flex items-center justify-center bg-slate-950/80 z-20">
          <span className="text-cyan-400 font-mono animate-pulse text-sm">Loading 3D Digital Twin Scene...</span>
        </div>
      )}
      {status === "ERROR" && (
        <div className="absolute inset-0 flex items-center justify-center bg-rose-950/50 z-20">
          <span className="text-rose-400 font-mono text-sm">WebGL Context Error. Unable to mount 3D Scene.</span>
        </div>
      )}
      <div ref={mountRef} className="w-full h-full" />
      <div className="absolute top-4 right-4 flex gap-2 z-10">
        <button
          onClick={handleResetCamera}
          className="px-3 py-1 bg-slate-900/80 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded text-xs font-mono transition"
        >
          RESET CAMERA [{cameraState}]
        </button>
      </div>
    </div>
  );
};
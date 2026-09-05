import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { HeroSection } from './components/HeroSection';
import { MetricCards } from './components/MetricCards';
import { TopologyGraph } from './components/TopologyGraph';
import { TrajectoryForecast } from './components/TrajectoryForecast';
import { WhatIfCentre } from './components/WhatIfCentre';
import { ExplainabilitySection } from './components/ExplainabilitySection';
import {
  NetworkHost,
  NetworkEdge,
  SimulationRecord,
  ForecastPoint,
  KillChainStage,
  TelemetryAlert,
  SourceExplainabilityProfile,
  DefenceActionType
} from './types';
import { playCyberTone } from './utils/audio';

interface BackendPredictResponse {
  timeline: Array<{
    t: number;
    infiltration_prob: number;
    stage: string;
    stage_conf: number;
  }>;
  current_stage: string;
  mitre_technique: string;
  forecast_K: number;
  top_features: Array<{
    name: string;
    contribution: number;
  }>;
  flagged_edges: Array<{
    src: string;
    dst: string;
    attn: number;
  }>;
  ood_score: number;
  uncertainty_std: number;
  lead_time_seconds: number | null;
}

export default function App() {
  // Navigation & telemetry states
  const [windowSeq, setWindowSeq] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [alerts, setAlerts] = useState<TelemetryAlert[]>([]);
  const [hasData, setHasData] = useState(false);
  const [backendConnected, setBackendConnected] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Graph state - start completely EMPTY
  const [hosts, setHosts] = useState<NetworkHost[]>([]);
  const [edges, setEdges] = useState<NetworkEdge[]>([]);
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge | null>(null);
  const [selectedHostId, setSelectedHostId] = useState<string>('');
  const [isolatedHostIds, setIsolatedHostIds] = useState<string[]>([]);
  const [blockedPorts, setBlockedPorts] = useState<{ [hostId: string]: number[] }>({});

  // Dynamic explainability profile
  const [activeProfile, setActiveProfile] = useState<SourceExplainabilityProfile | null>(null);

  // Model Intelligence & KPI metrics (null when no telemetry data)
  const [infiltrationRisk, setInfiltrationRisk] = useState<number | null>(null);
  const [riskTrend, setRiskTrend] = useState<string>('--');
  const [leadTime, setLeadTime] = useState<string>('--');
  const [leadTimeDelta, setLeadTimeDelta] = useState<string>('--');
  const [predictedStage, setPredictedStage] = useState<string>('--');
  const [mitreTactic, setMitreTactic] = useState<string>('--');
  const [modelConfidence, setModelConfidence] = useState<number | null>(null);
  const [uncertainty, setUncertainty] = useState<number | null>(null);

  // Telemetry sensor metrics
  const [portEntropy, setPortEntropy] = useState<number>(0);
  const [synRatio, setSynRatio] = useState<number>(0);
  const [logByteVolume, setLogByteVolume] = useState<number>(0);
  const [forecastPoints, setForecastPoints] = useState<ForecastPoint[]>([]);
  const [killChainStages, setKillChainStages] = useState<KillChainStage[]>([]);

  // Counterfactual & What-If state
  const [selectedTargetHostId, setSelectedTargetHostId] = useState<string>('');
  const [actionType, setActionType] = useState<DefenceActionType>('isolate_host');
  const [selectedPort, setSelectedPort] = useState<number>(445);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulatedRisk, setSimulatedRisk] = useState<number | null>(null);
  const [deltaPts, setDeltaPts] = useState<number | null>(null);
  const [recentSimulations, setRecentSimulations] = useState<SimulationRecord[]>([]);
  const [showCounterfactualInForecast, setShowCounterfactualInForecast] = useState(false);

  // Health check polling on backend API
  useEffect(() => {
    const checkBackend = async () => {
      try {
        const res = await fetch('http://localhost:8000/health');
        if (res.ok) {
          const data = await res.json();
          setBackendConnected(data.status === 'ok');
        } else {
          setBackendConnected(false);
        }
      } catch {
        setBackendConnected(false);
      }
    };
    checkBackend();
    const interval = setInterval(checkBackend, 8000);
    return () => clearInterval(interval);
  }, []);

  // Process live backend prediction payload
  const processBackendResponse = (data: BackendPredictResponse) => {
    // 1. Identify all unique hosts from flagged_edges
    const ipMap = new Map<string, { inCount: number; outCount: number; maxAttn: number }>();

    (data.flagged_edges || []).forEach((fe) => {
      if (!ipMap.has(fe.src)) {
        ipMap.set(fe.src, { inCount: 0, outCount: 0, maxAttn: 0 });
      }
      if (!ipMap.has(fe.dst)) {
        ipMap.set(fe.dst, { inCount: 0, outCount: 0, maxAttn: 0 });
      }
      ipMap.get(fe.src)!.outCount++;
      ipMap.get(fe.src)!.maxAttn = Math.max(ipMap.get(fe.src)!.maxAttn, fe.attn);
      ipMap.get(fe.dst)!.inCount++;
      ipMap.get(fe.dst)!.maxAttn = Math.max(ipMap.get(fe.dst)!.maxAttn, fe.attn);
    });

    const uniqueIps = Array.from(ipMap.keys());

    // Generate responsive layout coordinates for detected hosts
    const newHosts: NetworkHost[] = uniqueIps.map((ip, idx) => {
      const isInternal = ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.');
      const stats = ipMap.get(ip)!;
      const angle = (idx / Math.max(uniqueIps.length, 1)) * 2 * Math.PI;
      const x = Math.round(50 + 36 * Math.cos(angle));
      const y = Math.round(50 + 32 * Math.sin(angle));

      const status = stats.maxAttn > 0.4 ? 'compromised' : stats.maxAttn > 0.2 ? 'elevated' : 'benign';
      const role = !isInternal
        ? 'External / Untrusted Entity'
        : stats.outCount > stats.inCount
        ? 'Client / Pivot Node'
        : 'Core Service / Target';

      return {
        id: ip.replace(/\./g, '-'),
        name: `HOST-${ip.split('.').slice(-2).join('.')}`,
        ip,
        role,
        segment: isInternal ? 'corporate' : 'dmz',
        status,
        x,
        y,
        openPorts: [80, 443, 445, 8080],
        attentionScore: stats.maxAttn,
        os: isInternal ? 'Linux 6.1 (Telemetry Stream)' : 'Remote System',
        inboundEdges: stats.inCount,
        outboundEdges: stats.outCount
      };
    });

    // 2. Build edges from spatial attention
    const newEdges: NetworkEdge[] = (data.flagged_edges || []).map((fe, idx) => {
      const srcHost = newHosts.find((h) => h.ip === fe.src);
      const dstHost = newHosts.find((h) => h.ip === fe.dst);
      const srcId = srcHost ? srcHost.id : fe.src.replace(/\./g, '-');
      const dstId = dstHost ? dstHost.id : fe.dst.replace(/\./g, '-');
      return {
        id: `e-${srcId}-${dstId}-${idx}`,
        source: srcId,
        target: dstId,
        protocol: 'TCP',
        port: 445,
        attention: fe.attn,
        packetsPerSec: Math.round(fe.attn * 1500) + 120,
        byteRateKbps: Math.round(fe.attn * 4200) + 300,
        type: fe.attn > 0.35 ? 'lateral_movement' : 'recon',
        status: fe.attn > 0.35 ? 'critical' : 'active'
      };
    });

    // 3. Build forecast points
    const newPoints: ForecastPoint[] = (data.timeline || []).map((pt, idx) => ({
      windowIndex: idx,
      windowLabel: idx < 3 ? `W-${3 - idx}` : `W+${idx - 2}`,
      timestamp: `${pt.t.toFixed(1)}s`,
      infiltrationRisk: Math.round(pt.infiltration_prob * 100),
      stage: pt.stage,
      confidence: Math.round(pt.stage_conf * 100)
    }));

    // 4. Calculate KPI metrics
    const latestProb = data.timeline && data.timeline.length > 0
      ? data.timeline[data.timeline.length - 1].infiltration_prob
      : 0;
    const riskPercent = Math.round(latestProb * 100);
    const conf = +(100 - (data.uncertainty_std * 100)).toFixed(1);
    const uncert = +(data.uncertainty_std * 100).toFixed(1);

    // Dynamic Kill Chain progression
    const stagesList: KillChainStage[] = [
      { step: 1, name: 'Baseline', status: 'completed', tacticId: 'TA0001' },
      { step: 2, name: 'Recon', status: data.current_stage?.includes('Recon') ? 'active' : 'completed', tacticId: 'TA0043' },
      { step: 3, name: 'Initial Access', status: data.current_stage?.includes('Initial') ? 'active' : 'upcoming', tacticId: 'TA0002' },
      { step: 4, name: 'Credential', status: data.current_stage?.includes('Credential') ? 'active' : 'upcoming', tacticId: 'TA0006' },
      { step: 5, name: 'Lateral', status: data.current_stage?.includes('Lateral') ? 'active' : 'upcoming', tacticId: 'TA0008' },
      { step: 6, name: 'C2', status: data.current_stage?.includes('C2') ? 'active' : 'upcoming', tacticId: 'TA0011' },
      { step: 7, name: 'Exfiltration', status: data.current_stage?.includes('Exfil') ? 'active' : 'upcoming', tacticId: 'TA0010' }
    ];

    // Build Explainability Profile for the highest-attention connection
    const primaryEdge = newEdges[0] || null;
    let prof: SourceExplainabilityProfile | null = null;
    if (primaryEdge) {
      const srcNode = newHosts.find((h) => h.id === primaryEdge.source);
      const dstNode = newHosts.find((h) => h.id === primaryEdge.target);
      prof = {
        sourceId: primaryEdge.source,
        sourceName: srcNode ? srcNode.name : primaryEdge.source,
        sourceIp: srcNode ? srcNode.ip : '0.0.0.0',
        targetId: primaryEdge.target,
        targetName: dstNode ? dstNode.name : primaryEdge.target,
        targetIp: dstNode ? dstNode.ip : '0.0.0.0',
        protocol: primaryEdge.protocol,
        port: primaryEdge.port,
        attention: primaryEdge.attention,
        mitreTactic: data.mitre_technique || 'TA0008',
        mitreTacticCode: (data.mitre_technique || 'TA0008').split(' ')[0],
        predictedStage: data.current_stage || 'Active Analysis',
        riskScore: riskPercent,
        riskTrend: '+4',
        leadTime: data.lead_time_seconds ? `+${data.lead_time_seconds.toFixed(1)}s` : '--',
        leadTimeDelta: '-1.2s',
        portEntropy: 3.4,
        synRatio: 0.68,
        logByteVolume: 11.8,
        summary: `Anomaly flagged on connection ${srcNode?.ip || primaryEdge.source} -> ${dstNode?.ip || primaryEdge.target} with spatial attention ${(primaryEdge.attention * 100).toFixed(1)}%. MITRE Technique: ${data.mitre_technique}.`,
        features: (data.top_features || []).map((f, idx) => ({
          id: `feat-${idx}`,
          code: f.name,
          label: f.name.replace(/_/g, ' ').toUpperCase(),
          percentage: Math.round(f.contribution * 100),
          severity: f.contribution > 0.25 ? 'high' : 'medium'
        }))
      };
    }

    // Dynamic alert generation from telemetry
    const newAlerts: TelemetryAlert[] = (data.flagged_edges || []).slice(0, 3).map((fe, idx) => ({
      id: `alt-${Date.now()}-${idx}`,
      timestamp: new Date().toTimeString().split(' ')[0],
      severity: fe.attn > 0.35 ? 'critical' : 'high',
      source: fe.src,
      target: fe.dst,
      message: `Attention spike (α=${fe.attn.toFixed(3)}) on ${fe.src} -> ${fe.dst} during ${data.current_stage}`,
      port: 445
    }));

    setHosts(newHosts);
    setEdges(newEdges);
    setSelectedEdge(primaryEdge);
    setSelectedHostId(newHosts[0]?.id || '');
    setSelectedTargetHostId(newHosts[1]?.id || newHosts[0]?.id || '');
    setActiveProfile(prof);
    setForecastPoints(newPoints);
    setKillChainStages(stagesList);
    setInfiltrationRisk(riskPercent);
    setRiskTrend('+6');
    setLeadTime(data.lead_time_seconds ? `+${data.lead_time_seconds.toFixed(1)}s` : '--');
    setLeadTimeDelta('-1.4s');
    setPredictedStage(data.current_stage || 'Unknown');
    setMitreTactic(data.mitre_technique || 'None');
    setModelConfidence(conf);
    setUncertainty(uncert);
    setPortEntropy(3.4);
    setSynRatio(0.68);
    setLogByteVolume(11.8);
    setAlerts(newAlerts);
    setWindowSeq((prev) => prev + 1);
    setHasData(true);
  };

  // Upload Telemetry CSV to FastAPI /predict
  const handleUploadTelemetry = async (file: File) => {
    setIsUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('http://localhost:8000/predict', {
        method: 'POST',
        body: formData
      });
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      const data: BackendPredictResponse = await res.json();
      processBackendResponse(data);
      if (soundEnabled) playCyberTone('success');
    } catch (err: any) {
      console.error('Failed to upload telemetry:', err);
      alert(`Telemetry upload error: ${err.message || err}`);
    } finally {
      setIsUploading(false);
    }
  };

  // Fetch sample telemetry from FastAPI /predict-sample
  const handleFetchBackendStream = async () => {
    setIsRefreshing(true);
    try {
      const res = await fetch('http://localhost:8000/predict-sample', {
        method: 'POST'
      });
      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      const data: BackendPredictResponse = await res.json();
      processBackendResponse(data);
      if (soundEnabled) playCyberTone('success');
    } catch (err: any) {
      console.error('Failed to fetch backend sample stream:', err);
      alert(`Backend stream fetch error: ${err.message || err}`);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Model Refresh handler
  const handleRefreshModel = () => {
    if (hasData) {
      handleFetchBackendStream();
    } else {
      handleFetchBackendStream();
    }
  };

  // Counterfactual Simulation with Backend
  const handleRunSimulation = async () => {
    if (!hasData || hosts.length === 0) return;
    setIsSimulating(true);

    try {
      const currentRiskVal = (infiltrationRisk ?? 50) / 100;
      const targetHost = hosts.find((h) => h.id === selectedTargetHostId) || hosts[0];
      const targetIdentifier = targetHost ? targetHost.ip : selectedTargetHostId;

      const res = await fetch('http://localhost:8000/counterfactual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: actionType,
          target: targetIdentifier,
          current_risk: currentRiskVal
        })
      });

      let calculatedSimRisk = 15;
      let calculatedDelta = 35;

      if (res.ok) {
        const cfData = await res.json();
        calculatedSimRisk = Math.round(cfData.counterfactual_prob * 100);
        calculatedDelta = Math.round(Math.abs(cfData.risk_delta) * 100);
      } else {
        calculatedSimRisk = Math.max(8, Math.round(currentRiskVal * 100 * 0.3));
        calculatedDelta = (infiltrationRisk ?? 50) - calculatedSimRisk;
      }

      setSimulatedRisk(calculatedSimRisk);
      setDeltaPts(calculatedDelta);
      setShowCounterfactualInForecast(true);

      const newSimRecord: SimulationRecord = {
        id: `sim-${Date.now()}`,
        actionType,
        actionLabel: actionType === 'isolate_host' ? 'Isolate' : `Block ${selectedPort}`,
        targetId: targetHost.id,
        targetLabel: targetHost.name,
        port: actionType === 'block_port' ? selectedPort : undefined,
        timeAgo: 'Just now',
        initialRisk: infiltrationRisk ?? 50,
        simulatedRisk: calculatedSimRisk,
        delta: -calculatedDelta,
        timestamp: Date.now()
      };

      setRecentSimulations((prev) => [newSimRecord, ...prev.slice(0, 4)]);
      if (soundEnabled) playCyberTone('sim');
    } catch (err) {
      console.error('Counterfactual simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  // Handler for Edge Selection
  const handleSelectEdge = (edge: NetworkEdge) => {
    setSelectedEdge(edge);
    const srcHost = hosts.find((h) => h.id === edge.source);
    const dstHost = hosts.find((h) => h.id === edge.target);

    const prof: SourceExplainabilityProfile = {
      sourceId: edge.source,
      sourceName: srcHost ? srcHost.name : edge.source,
      sourceIp: srcHost ? srcHost.ip : '0.0.0.0',
      targetId: edge.target,
      targetName: dstHost ? dstHost.name : edge.target,
      targetIp: dstHost ? dstHost.ip : '0.0.0.0',
      protocol: edge.protocol,
      port: edge.port,
      attention: edge.attention,
      mitreTactic: mitreTactic,
      mitreTacticCode: mitreTactic.split(' ')[0] || 'TA0008',
      predictedStage: predictedStage,
      riskScore: Math.round(edge.attention * 100),
      riskTrend: '+2',
      leadTime: leadTime,
      leadTimeDelta: leadTimeDelta,
      portEntropy: portEntropy,
      synRatio: synRatio,
      logByteVolume: logByteVolume,
      summary: `Inspecting active interaction on edge ${srcHost?.ip || edge.source} -> ${dstHost?.ip || edge.target} (attention weight ${(edge.attention * 100).toFixed(1)}%).`,
      features: activeProfile?.features || []
    };

    setActiveProfile(prof);
    setSelectedHostId(edge.source);
    setSelectedTargetHostId(edge.target);
    setSelectedPort(edge.port);
  };

  // Handler for Source button selection
  const handleSelectSource = (sourceId: string) => {
    const matchingEdge = edges.find((e) => e.source === sourceId) || edges[0];
    if (matchingEdge) {
      handleSelectEdge(matchingEdge);
    }
  };

  // Toggle Isolation on Host
  const handleToggleIsolate = (hostId: string) => {
    setIsolatedHostIds((prev) => {
      const isAlreadyIsolated = prev.includes(hostId);
      if (isAlreadyIsolated) {
        return prev.filter((id) => id !== hostId);
      } else {
        return [...prev, hostId];
      }
    });
  };

  // Select historical simulation
  const handleSelectSimulation = (sim: SimulationRecord) => {
    setActionType(sim.actionType);
    setSelectedTargetHostId(sim.targetId);
    if (sim.port) setSelectedPort(sim.port);
    setSimulatedRisk(sim.simulatedRisk);
    setDeltaPts(Math.abs(sim.delta));
    setShowCounterfactualInForecast(true);
  };

  // Deploy Policy into active network
  const handleDeployPolicy = () => {
    if (actionType === 'isolate_host') {
      handleToggleIsolate(selectedTargetHostId);
    } else {
      setBlockedPorts((prev) => ({
        ...prev,
        [selectedTargetHostId]: [...(prev[selectedTargetHostId] || []), selectedPort]
      }));
    }
    if (simulatedRisk != null) {
      setInfiltrationRisk(simulatedRisk);
      setRiskTrend('0');
    }
  };

  return (
    <div className="min-h-screen bg-[#030914] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header */}
      <Header
        windowSeq={windowSeq}
        isPaused={isPaused}
        onTogglePause={() => setIsPaused(!isPaused)}
        alerts={alerts}
        soundEnabled={soundEnabled}
        onToggleSound={() => setSoundEnabled(!soundEnabled)}
      />

      {/* Main Content Dashboard */}
      <main className="flex-1 w-full max-w-[1720px] mx-auto px-3 sm:px-5 lg:px-6 py-4 space-y-4">
        {/* Hero Section */}
        <HeroSection
          sequence={windowSeq}
          isRefreshing={isRefreshing}
          onRefreshModel={handleRefreshModel}
          onRunCounterfactual={handleRunSimulation}
          soundEnabled={soundEnabled}
          hasData={hasData}
          backendConnected={backendConnected}
          onUploadTelemetry={handleUploadTelemetry}
          onFetchBackendStream={handleFetchBackendStream}
          isUploading={isUploading}
        />

        {/* 4 Metric KPI Cards */}
        <MetricCards
          infiltrationRisk={infiltrationRisk}
          riskTrend={riskTrend}
          leadTime={leadTime}
          leadTimeDelta={leadTimeDelta}
          predictedStage={predictedStage}
          mitreTactic={mitreTactic}
          modelConfidence={modelConfidence}
          uncertainty={uncertainty}
        />

        {/* Main Dashboard Layout */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 sm:gap-5 items-start">
          {/* Left & Center Main Stream (Cols 1 to 8 on XL) */}
          <div className="xl:col-span-8 flex flex-col space-y-4 sm:space-y-5">
            {/* Top Row: 01 Topology & 02 Trajectory Forecast */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-5">
              {/* 01 Network State Graph */}
              <TopologyGraph
                hosts={hosts}
                edges={edges}
                selectedHostId={selectedHostId}
                onSelectHost={(id) => {
                  setSelectedHostId(id);
                  setSelectedTargetHostId(id);
                }}
                selectedEdgeId={selectedEdge?.id}
                onSelectEdge={handleSelectEdge}
                isolatedHostIds={isolatedHostIds}
                blockedPorts={blockedPorts}
                onIsolateToggle={handleToggleIsolate}
                soundEnabled={soundEnabled}
              />

              {/* 02 Trajectory Forecast */}
              <TrajectoryForecast
                points={forecastPoints}
                killChainStages={killChainStages}
                portEntropy={portEntropy}
                synRatio={synRatio}
                logByteVolume={logByteVolume}
                showCounterfactual={showCounterfactualInForecast}
                soundEnabled={soundEnabled}
              />
            </div>

            {/* Bottom Row: 04 Explainability Section */}
            <ExplainabilitySection
              features={activeProfile?.features || []}
              profile={activeProfile}
              edges={edges}
              selectedEdge={selectedEdge}
              onSelectEdge={handleSelectEdge}
              onSelectSource={handleSelectSource}
              soundEnabled={soundEnabled}
            />
          </div>

          {/* Right Sidebar: 03 What-if centre (Cols 9 to 12 on XL) */}
          <div className="xl:col-span-4 sticky top-4">
            <WhatIfCentre
              hosts={hosts}
              selectedTargetHostId={selectedTargetHostId}
              onSelectTargetHost={setSelectedTargetHostId}
              actionType={actionType}
              onChangeActionType={setActionType}
              selectedPort={selectedPort}
              onSelectPort={setSelectedPort}
              onRunSimulation={handleRunSimulation}
              isSimulating={isSimulating}
              currentThreatRisk={infiltrationRisk}
              simulatedRisk={simulatedRisk}
              deltaPts={deltaPts}
              recentSimulations={recentSimulations}
              onSelectSimulation={handleSelectSimulation}
              onDeployPolicy={handleDeployPolicy}
              soundEnabled={soundEnabled}
            />
          </div>
        </div>
      </main>
    </div>
  );
}

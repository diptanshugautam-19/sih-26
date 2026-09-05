import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { HeroSection } from './components/HeroSection';
import { MetricCards } from './components/MetricCards';
import { TopologyGraph } from './components/TopologyGraph';
import { TrajectoryForecast } from './components/TrajectoryForecast';
import { WhatIfCentre } from './components/WhatIfCentre';
import { ExplainabilitySection } from './components/ExplainabilitySection';
import {
  INITIAL_HOSTS,
  INITIAL_EDGES,
  FORECAST_POINTS,
  INITIAL_SIMULATIONS,
  FEATURE_IMPORTANCES,
  KILL_CHAIN_STAGES,
  INITIAL_ALERTS,
  getExplainabilityForEdge,
  getExplainabilityForSource
} from './data/initialData';
import { DefenceActionType, SimulationRecord, NetworkEdge } from './types';
import { playCyberTone } from './utils/audio';

export default function App() {
  // Navigation & telemetry states
  const [windowSeq, setWindowSeq] = useState(842);
  const [isPaused, setIsPaused] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [alerts, setAlerts] = useState(INITIAL_ALERTS);

  // Explainability state & dynamic source profile
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge>(INITIAL_EDGES[1]); // APP-07 -> SRV-DC01
  const activeProfile = getExplainabilityForEdge(selectedEdge);

  // Model Intelligence & KPI metrics (initialized to active source vector)
  const [infiltrationRisk, setInfiltrationRisk] = useState(activeProfile.riskScore);
  const [riskTrend, setRiskTrend] = useState(activeProfile.riskTrend);
  const [leadTime, setLeadTime] = useState(activeProfile.leadTime);
  const [leadTimeDelta, setLeadTimeDelta] = useState(activeProfile.leadTimeDelta);
  const [predictedStage, setPredictedStage] = useState(activeProfile.predictedStage);
  const [mitreTactic, setMitreTactic] = useState(activeProfile.mitreTactic);
  const [modelConfidence, setModelConfidence] = useState(94.2);
  const [uncertainty, setUncertainty] = useState(5.8);

  // Telemetry sensor metrics (dynamic per source)
  const [portEntropy, setPortEntropy] = useState(activeProfile.portEntropy);
  const [synRatio, setSynRatio] = useState(activeProfile.synRatio);
  const [logByteVolume, setLogByteVolume] = useState(activeProfile.logByteVolume);

  // Graph state
  const [hosts, setHosts] = useState(INITIAL_HOSTS);
  const [edges, setEdges] = useState(INITIAL_EDGES);
  const [selectedHostId, setSelectedHostId] = useState(selectedEdge.source);
  const [isolatedHostIds, setIsolatedHostIds] = useState<string[]>([]);
  const [blockedPorts, setBlockedPorts] = useState<{ [hostId: string]: number[] }>({});

  // Counterfactual & What-If state
  const [selectedTargetHostId, setSelectedTargetHostId] = useState(selectedEdge.target);
  const [actionType, setActionType] = useState<DefenceActionType>('isolate_host');
  const [selectedPort, setSelectedPort] = useState(selectedEdge.port);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [simulatedRisk, setSimulatedRisk] = useState(12);
  const [deltaPts, setDeltaPts] = useState(75);
  const [recentSimulations, setRecentSimulations] = useState<SimulationRecord[]>(INITIAL_SIMULATIONS);
  const [showCounterfactualInForecast, setShowCounterfactualInForecast] = useState(true);

  // Handler for Edge / Source Selection (changes entire dashboard reactivity)
  const handleSelectEdge = (edge: NetworkEdge) => {
    setSelectedEdge(edge);
    const profile = getExplainabilityForEdge(edge);
    setInfiltrationRisk(profile.riskScore);
    setRiskTrend(profile.riskTrend);
    setLeadTime(profile.leadTime);
    setLeadTimeDelta(profile.leadTimeDelta);
    setMitreTactic(profile.mitreTactic);
    setPredictedStage(profile.predictedStage);
    setPortEntropy(profile.portEntropy);
    setSynRatio(profile.synRatio);
    setLogByteVolume(profile.logByteVolume);
    setSelectedHostId(edge.source);
    setSelectedTargetHostId(edge.target);
    setSelectedPort(edge.port);
  };

  // Handler for Source button selection
  const handleSelectSource = (sourceId: string) => {
    const matchingEdge = edges.find((e) => e.source === sourceId) || edges[0];
    handleSelectEdge(matchingEdge);
  };

  // Live telemetry pulse effect (increments window seq periodically when not paused)
  useEffect(() => {
    if (isPaused) return;
    const interval = setInterval(() => {
      setWindowSeq((prev) => prev + 1);
      // Subtle natural fluctuations in entropy
      setPortEntropy((prev) => +(prev + (Math.random() * 0.08 - 0.04)).toFixed(1));
    }, 12000);
    return () => clearInterval(interval);
  }, [isPaused]);

  // Handle Model Refresh
  const handleRefreshModel = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
      setWindowSeq((prev) => prev + 1);
      setModelConfidence(+(94.0 + Math.random() * 0.5).toFixed(1));
      if (soundEnabled) playCyberTone('success');
    }, 600);
  };

  // Run What-If Simulation
  const handleRunSimulation = () => {
    setIsSimulating(true);

    setTimeout(() => {
      setIsSimulating(false);

      const target = hosts.find((h) => h.id === selectedTargetHostId) || hosts[0];
      let newRisk = 12;

      if (actionType === 'isolate_host') {
        if (target.id === 'app-07') newRisk = 12;
        else if (target.id === 'ws-042') newRisk = 18;
        else if (target.id === 'srv-dc01') newRisk = 30;
        else newRisk = 22;
      } else {
        // Block port
        if (selectedPort === 445) newRisk = 24;
        else if (selectedPort === 3389) newRisk = 38;
        else newRisk = 45;
      }

      const calculatedDelta = infiltrationRisk - newRisk;
      setSimulatedRisk(newRisk);
      setDeltaPts(calculatedDelta);
      setShowCounterfactualInForecast(true);

      // Add to recent simulations
      const newSimRecord: SimulationRecord = {
        id: `sim-${Date.now()}`,
        actionType,
        actionLabel: actionType === 'isolate_host' ? 'Isolate' : `Block ${selectedPort}`,
        targetId: target.id,
        targetLabel: target.name,
        port: actionType === 'block_port' ? selectedPort : undefined,
        timeAgo: 'Just now',
        initialRisk: infiltrationRisk,
        simulatedRisk: newRisk,
        delta: -calculatedDelta,
        timestamp: Date.now()
      };

      setRecentSimulations((prev) => [newSimRecord, ...prev.slice(0, 4)]);
      if (soundEnabled) playCyberTone('sim');
    }, 280);
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

  // Select a historical simulation to preview
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
    // Update live risk
    setInfiltrationRisk(simulatedRisk);
    setRiskTrend('0');
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

        {/* Main Dashboard Layout (Desktop 12-column grid) */}
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
                selectedEdgeId={selectedEdge.id}
                onSelectEdge={handleSelectEdge}
                isolatedHostIds={isolatedHostIds}
                blockedPorts={blockedPorts}
                onIsolateToggle={handleToggleIsolate}
                soundEnabled={soundEnabled}
              />

              {/* 02 Trajectory Forecast */}
              <TrajectoryForecast
                points={FORECAST_POINTS}
                killChainStages={KILL_CHAIN_STAGES}
                portEntropy={portEntropy}
                synRatio={synRatio}
                logByteVolume={logByteVolume}
                showCounterfactual={showCounterfactualInForecast}
                soundEnabled={soundEnabled}
              />
            </div>

            {/* Bottom Row: 04 Explainability Section */}
            <ExplainabilitySection
              features={activeProfile.features}
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

import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { TrajectoryForecast } from './components/TrajectoryForecast';
import { WhatIfCentre } from './components/WhatIfCentre';
import { ExplainabilitySection } from './components/ExplainabilitySection';
import { MainThreatTopologyView } from './components/MainThreatTopologyView';
import { CaptureUploadModal } from './components/CaptureUploadModal';
import { CaptureUtilityBar } from './components/CaptureUtilityBar';
import {
  INITIAL_HOSTS,
  INITIAL_EDGES,
  FORECAST_POINTS,
  INITIAL_SIMULATIONS,
  KILL_CHAIN_STAGES,
  INITIAL_ALERTS,
  getExplainabilityForEdge
} from './data/initialData';
import {
  DefenceActionType,
  SimulationRecord,
  NetworkEdge,
  NetworkHost,
  NavigationTab,
  PredictedTargetNode,
  TelemetryAlert,
  CaptureMetadata,
  AppTheme,
  ForecastPoint,
  KillChainStage,
  SourceExplainabilityProfile
} from './types';
import { playCyberTone } from './utils/audio';
import {
  fetchNetworkState,
  fetchTelemetry,
  fetchAlerts,
  fetchForecast,
  fetchExplainability,
  fetchSimulations,
  apiIsolateHost,
  apiBlockPort,
  apiSimulateAction,
  apiDeployPolicy
} from './utils/api';

export default function App() {
  // Navigation: separates clustered single-page layout into multi-page workflow
  const [activeTab, setActiveTab] = useState<NavigationTab>('main_topology');

  // Backend connection & loading states
  const [backendConnected, setBackendConnected] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Upload Network Capture Modal State
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [activeCapture, setActiveCapture] = useState<CaptureMetadata | null>(null);

  // Theme state: defaults to 'light' (white theme)
  const [theme, setTheme] = useState<AppTheme>(() => {
    // Default to 'light' (white theme)
    const stored = localStorage.getItem('vashikaran_theme_mode') || localStorage.getItem('davaska_theme_mode');
    if (stored === 'slate' || stored === 'midnight' || stored === 'light') {
      return stored;
    }
    return 'light';
  });

  const handleSelectTheme = (newTheme: AppTheme) => {
    setTheme(newTheme);
    localStorage.setItem('vashikaran_theme_mode', newTheme);
    if (newTheme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  };

  useEffect(() => {
    if (theme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      document.documentElement.classList.add('dark');
    }
  }, [theme]);

  // Telemetry controls
  const [windowSeq, setWindowSeq] = useState(842);
  const [isPaused, setIsPaused] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [alerts, setAlerts] = useState<TelemetryAlert[]>(INITIAL_ALERTS);

  // Core Network State (fetched from backend)
  const [hosts, setHosts] = useState<NetworkHost[]>(INITIAL_HOSTS);
  const [edges, setEdges] = useState<NetworkEdge[]>(INITIAL_EDGES);
  const [attackedNodes, setAttackedNodes] = useState<NetworkHost[]>([]);
  const [predictedNextTarget, setPredictedNextTarget] = useState<PredictedTargetNode | null>(null);
  const [isolatedHostIds, setIsolatedHostIds] = useState<string[]>([]);
  const [blockedPorts, setBlockedPorts] = useState<{ [hostId: string]: number[] }>({});

  // Active selections
  const [selectedHostId, setSelectedHostId] = useState('srv-dc01');
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge>(INITIAL_EDGES[1]);
  const [activeProfile, setActiveProfile] = useState<SourceExplainabilityProfile>(() => getExplainabilityForEdge(INITIAL_EDGES[1]));

  // Model Intelligence & KPI metrics
  const [infiltrationRisk, setInfiltrationRisk] = useState(activeProfile.riskScore);
  const [riskTrend, setRiskTrend] = useState(activeProfile.riskTrend);
  const [leadTime, setLeadTime] = useState(activeProfile.leadTime);
  const [leadTimeDelta, setLeadTimeDelta] = useState(activeProfile.leadTimeDelta);
  const [predictedStage, setPredictedStage] = useState(activeProfile.predictedStage);
  const [mitreTactic, setMitreTactic] = useState(activeProfile.mitreTactic);
  const [modelConfidence, setModelConfidence] = useState(94.2);
  const [uncertainty, setUncertainty] = useState(5.8);

  // Telemetry sensor metrics
  const [portEntropy, setPortEntropy] = useState(activeProfile.portEntropy);
  const [synRatio, setSynRatio] = useState(activeProfile.synRatio);
  const [logByteVolume, setLogByteVolume] = useState(activeProfile.logByteVolume);

  // Trajectory forecast & Kill chain stages (fetched from backend)
  const [forecastPoints, setForecastPoints] = useState<ForecastPoint[]>(FORECAST_POINTS);
  const [killChainStages, setKillChainStages] = useState<KillChainStage[]>(KILL_CHAIN_STAGES);

  // What-If & Counterfactual simulation state
  const [selectedTargetHostId, setSelectedTargetHostId] = useState('srv-dc01');
  const [actionType, setActionType] = useState<DefenceActionType>('isolate_host');
  const [selectedPort, setSelectedPort] = useState(445);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulatedRisk, setSimulatedRisk] = useState(12);
  const [deltaPts, setDeltaPts] = useState(75);
  const [recentSimulations, setRecentSimulations] = useState<SimulationRecord[]>(INITIAL_SIMULATIONS);
  const [showCounterfactualInForecast, setShowCounterfactualInForecast] = useState(true);

  // Load live data from real Express backend
  const loadBackendData = useCallback(async () => {
    try {
      setIsRefreshing(true);
      const networkData = await fetchNetworkState();
      setHosts(networkData.hosts);
      setEdges(networkData.edges);
      setAttackedNodes(networkData.attackedNodes);
      setPredictedNextTarget(networkData.predictedNextTarget);
      setIsolatedHostIds(networkData.isolatedHostIds || []);
      setBlockedPorts(networkData.blockedPorts || {});
      setWindowSeq(networkData.windowSeq);
      setActiveCapture(networkData.activeCapture || null);
      setBackendConnected(true);

      // Fetch telemetry
      const tel = await fetchTelemetry();
      setInfiltrationRisk(tel.infiltrationRisk);
      setRiskTrend(tel.riskTrend);
      setLeadTime(tel.leadTime);
      setLeadTimeDelta(tel.leadTimeDelta);
      setPredictedStage(tel.predictedStage);
      setMitreTactic(tel.mitreTactic);
      setPortEntropy(tel.portEntropy);
      setSynRatio(tel.synRatio);
      setLogByteVolume(tel.logByteVolume);

      // Fetch alerts
      const altData = await fetchAlerts();
      if (altData && altData.length > 0) {
        setAlerts(altData);
      }

      // Fetch forecast and kill chain progression from backend
      const fcData = await fetchForecast().catch(() => null);
      if (fcData) {
        setForecastPoints(fcData.points);
        setKillChainStages(fcData.killChainStages);
      }

      // Fetch simulations history from backend
      const simData = await fetchSimulations().catch(() => null);
      if (simData && simData.length > 0) {
        setRecentSimulations(simData);
      }

      // Fetch explainability for currently selected edge from backend
      const currentEdgeId = selectedEdge ? selectedEdge.id : (networkData.edges[0]?.id);
      if (currentEdgeId) {
        const expData = await fetchExplainability(currentEdgeId).catch(() => null);
        if (expData) {
          setActiveProfile(expData);
        }
      }
    } catch (err) {
      console.warn('Backend loading attempt, using active fallback state:', err);
      // Even in fallback, populate attacked nodes & predicted target
      setAttackedNodes(INITIAL_HOSTS.filter((h) => h.status === 'compromised'));
    } finally {
      setIsRefreshing(false);
    }
  }, [selectedEdge]);

  // Initial backend fetch on mount
  useEffect(() => {
    loadBackendData();
  }, [loadBackendData]);

  // Live telemetry pulse effect
  useEffect(() => {
    if (isPaused) return;
    const interval = setInterval(() => {
      setWindowSeq((prev) => prev + 1);
    }, 12000);
    return () => clearInterval(interval);
  }, [isPaused]);

  // Handler for edge selection
  const handleSelectEdge = async (edge: NetworkEdge) => {
    setSelectedEdge(edge);
    setSelectedHostId(edge.source);
    setSelectedTargetHostId(edge.target);
    setSelectedPort(edge.port);

    try {
      const expData = await fetchExplainability(edge.id);
      if (expData) {
        setActiveProfile(expData);
        setInfiltrationRisk(expData.riskScore);
        setRiskTrend(expData.riskTrend);
        setLeadTime(expData.leadTime);
        setLeadTimeDelta(expData.leadTimeDelta);
        setMitreTactic(expData.mitreTactic);
        setPredictedStage(expData.predictedStage);
        setPortEntropy(expData.portEntropy);
        setSynRatio(expData.synRatio);
        setLogByteVolume(expData.logByteVolume);
      }
    } catch {
      const profile = getExplainabilityForEdge(edge);
      setActiveProfile(profile);
    }
  };

  // Handler for source button click
  const handleSelectSource = (sourceId: string) => {
    const matchingEdge = edges.find((e) => e.source === sourceId) || edges[0];
    handleSelectEdge(matchingEdge);
  };

  // Handler to isolate a host via backend API
  const handleToggleIsolate = async (hostId: string) => {
    const currentlyIsolated = isolatedHostIds.includes(hostId);
    const targetState = !currentlyIsolated;

    // Optimistic update
    setIsolatedHostIds((prev) =>
      targetState ? [...prev, hostId] : prev.filter((id) => id !== hostId)
    );

    try {
      const res = await apiIsolateHost(hostId, targetState);
      if (res && res.predictedNextTarget) {
        setPredictedNextTarget(res.predictedNextTarget);
        setInfiltrationRisk(Math.round(res.predictedNextTarget.probabilityPercent));
      }
      if (soundEnabled) playCyberTone('policy');
      loadBackendData();
    } catch (err) {
      console.error('Failed to isolate host on backend:', err);
    }
  };

  // Handler for quick mitigation (e.g. sever port 445 on target) via backend API
  const handleQuickMitigate = async (targetId: string, port?: number) => {
    const targetPort = port || 445;
    try {
      const res = await apiBlockPort(targetId, targetPort);
      setBlockedPorts(res.blockedPorts || {});
      if (res.predictedNextTarget) {
        setPredictedNextTarget(res.predictedNextTarget);
        setInfiltrationRisk(Math.round(res.predictedNextTarget.probabilityPercent));
      }
      if (soundEnabled) playCyberTone('policy');
      loadBackendData();
    } catch (err) {
      console.error('Failed to block port on backend:', err);
    }
  };

  // Run What-If Simulation via backend API
  const handleRunSimulation = async () => {
    setIsSimulating(true);
    try {
      const simRes = await apiSimulateAction(actionType, selectedTargetHostId, selectedPort);
      setSimulatedRisk(simRes.simulatedRisk);
      setDeltaPts(simRes.deltaPts);
      setShowCounterfactualInForecast(true);

      const simList = await fetchSimulations().catch(() => null);
      if (simList && simList.length > 0) {
        setRecentSimulations(simList);
      }
      if (soundEnabled) playCyberTone('sim');
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  // Deploy Policy to backend
  const handleDeployPolicy = async () => {
    try {
      const res = await apiDeployPolicy(actionType, selectedTargetHostId, selectedPort);
      if (res.isolatedHostIds) setIsolatedHostIds(res.isolatedHostIds);
      if (res.blockedPorts) setBlockedPorts(res.blockedPorts);
      if (res.predictedNextTarget) {
        setPredictedNextTarget(res.predictedNextTarget);
      }
      setInfiltrationRisk(simulatedRisk);
      setRiskTrend('0');
      if (soundEnabled) playCyberTone('policy');
      loadBackendData();
    } catch (err) {
      console.error('Deploy policy error:', err);
    }
  };

  // Select a historical simulation record
  const handleSelectSimulation = (sim: SimulationRecord) => {
    setActionType(sim.actionType);
    setSelectedTargetHostId(sim.targetId);
    if (sim.port) setSelectedPort(sim.port);
    setSimulatedRisk(sim.simulatedRisk);
    setDeltaPts(Math.abs(sim.delta));
    setShowCounterfactualInForecast(true);
  };

  const isLight = theme === 'light';
  const isMidnight = theme === 'midnight';

  return (
    <div className={`min-h-screen flex flex-col font-sans transition-colors duration-200 ${
      isLight
        ? 'bg-slate-50 text-slate-900 selection:bg-cyan-500/30 selection:text-cyan-900'
        : isMidnight
        ? 'bg-[#040814] text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200'
        : 'bg-[#0b0f19] text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200'
    }`}>
      {/* Top Header with Multi-Page Navigation Tabs and Capture Upload */}
      <Header
        windowSeq={windowSeq}
        isPaused={isPaused}
        onTogglePause={() => setIsPaused(!isPaused)}
        alerts={alerts}
        soundEnabled={soundEnabled}
        onToggleSound={() => setSoundEnabled(!soundEnabled)}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        attackedCount={attackedNodes.length}
        predictedTargetName={predictedNextTarget?.name || 'SRV-DC01'}
        predictedProbability={predictedNextTarget?.probabilityPercent || infiltrationRisk}
        backendConnected={backendConnected}
        activeCapture={activeCapture}
        onOpenUploadModal={() => setIsUploadModalOpen(true)}
        theme={theme}
        onSelectTheme={handleSelectTheme}
      />

      {/* Main Page Area: Shifted down gracefully with generous presentable spacing */}
      <main className="flex-1 w-full max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 pt-6 sm:pt-8 pb-16">
        
        {/* VIEW 1: MAIN PAGE (Graphical Nodes + Attacked Nodes + Most Probable Future Target + Probability Issues) */}
        {activeTab === 'main_topology' && (
          <MainThreatTopologyView
            hosts={hosts}
            edges={edges}
            attackedNodes={attackedNodes}
            predictedNextTarget={predictedNextTarget}
            selectedHostId={selectedHostId}
            onSelectHost={(id) => {
              setSelectedHostId(id);
              setSelectedTargetHostId(id);
            }}
            selectedEdgeId={selectedEdge.id}
            onSelectEdge={handleSelectEdge}
            isolatedHostIds={isolatedHostIds}
            blockedPorts={blockedPorts}
            onToggleIsolate={handleToggleIsolate}
            onQuickMitigate={handleQuickMitigate}
            onRefreshData={loadBackendData}
            isRefreshing={isRefreshing}
            soundEnabled={soundEnabled}
            onNavigateToWhatIf={() => setActiveTab('what_if')}
            activeCapture={activeCapture}
            onOpenUploadModal={() => setIsUploadModalOpen(true)}
            theme={theme}
          />
        )}

        {/* VIEW 2: TRAJECTORY FORECAST & KILL CHAIN PROGRESSION */}
        {activeTab === 'trajectory' && (
          <div className="space-y-6 animate-in fade-in duration-200">
            {/* Top Utility Bar (Consistent across all pages) */}
            <CaptureUtilityBar
              activeCapture={activeCapture}
              onOpenUploadModal={() => setIsUploadModalOpen(true)}
              onRefreshData={loadBackendData}
              isRefreshing={isRefreshing}
              soundEnabled={soundEnabled}
              theme={theme}
            />

            {/* Top Metric Cards */}
            <MetricCards
              infiltrationRisk={infiltrationRisk}
              riskTrend={riskTrend}
              leadTime={leadTime}
              leadTimeDelta={leadTimeDelta}
              predictedStage={predictedStage}
              mitreTactic={mitreTactic}
              modelConfidence={modelConfidence}
              uncertainty={uncertainty}
              theme={theme}
            />

            {/* Trajectory Forecast Chart and Kill Chain */}
            <TrajectoryForecast
              points={forecastPoints}
              killChainStages={killChainStages}
              portEntropy={portEntropy}
              synRatio={synRatio}
              logByteVolume={logByteVolume}
              showCounterfactual={showCounterfactualInForecast}
              soundEnabled={soundEnabled}
              theme={theme}
            />
          </div>
        )}

        {/* VIEW 3: WHAT-IF DEFENSE LAB */}
        {activeTab === 'what_if' && (
          <div className="space-y-6 animate-in fade-in duration-200">
            {/* Top Utility Bar (Consistent across all pages) */}
            <CaptureUtilityBar
              activeCapture={activeCapture}
              onOpenUploadModal={() => setIsUploadModalOpen(true)}
              onRefreshData={loadBackendData}
              isRefreshing={isRefreshing}
              soundEnabled={soundEnabled}
              theme={theme}
            />

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
              theme={theme}
            />
          </div>
        )}

        {/* VIEW 4: MODEL EXPLAINABILITY & ATTRIBUTION */}
        {activeTab === 'explainability' && (
          <div className="space-y-6 animate-in fade-in duration-200">
            {/* Top Utility Bar (Consistent across all pages) */}
            <CaptureUtilityBar
              activeCapture={activeCapture}
              onOpenUploadModal={() => setIsUploadModalOpen(true)}
              onRefreshData={loadBackendData}
              isRefreshing={isRefreshing}
              soundEnabled={soundEnabled}
              theme={theme}
            />

            <ExplainabilitySection
              features={activeProfile.features}
              profile={activeProfile}
              edges={edges}
              selectedEdge={selectedEdge}
              onSelectEdge={handleSelectEdge}
              onSelectSource={handleSelectSource}
              soundEnabled={soundEnabled}
              theme={theme}
            />
          </div>
        )}

      </main>

      {/* Network Capture Upload Modal (.pcap, .pcapng, .csv, .json, .log) */}
      <CaptureUploadModal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        activeCapture={activeCapture}
        onCaptureLoaded={loadBackendData}
        soundEnabled={soundEnabled}
        theme={theme}
      />
    </div>
  );
}

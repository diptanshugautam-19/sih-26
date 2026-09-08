import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { TrajectoryForecast } from './components/TrajectoryForecast';
import { WhatIfCentre } from './components/WhatIfCentre';
import { ExplainabilitySection } from './components/ExplainabilitySection';
import { MainThreatTopologyView } from './components/MainThreatTopologyView';
import { CaptureUploadModal } from './components/CaptureUploadModal';
import { CaptureUtilityBar } from './components/CaptureUtilityBar';
import { ModelBenchmarksView } from './components/ModelBenchmarksView';
import { LoginPage } from './components/LoginPage';
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
  SourceExplainabilityProfile,
  AuthUser
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
  // Authentication: Operator Login session (persisted in localStorage)
  const [authUser, setAuthUser] = useState<AuthUser | null>(() => {
    try {
      const stored = localStorage.getItem('vashikaran_user');
      if (stored) {
        return JSON.parse(stored);
      }
    } catch {
      // ignore
    }
    return null;
  });

  const handleLogout = () => {
    try {
      localStorage.removeItem('vashikaran_user');
    } catch {
      // ignore
    }
    setAuthUser(null);
  };

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
  const [windowSeq, setWindowSeq] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [alerts, setAlerts] = useState<TelemetryAlert[]>([]);

  // Core Network State (strictly fetched from backend /api/network)
  const [hosts, setHosts] = useState<NetworkHost[]>([]);
  const [edges, setEdges] = useState<NetworkEdge[]>([]);
  const [attackedNodes, setAttackedNodes] = useState<NetworkHost[]>([]);
  const [predictedNextTarget, setPredictedNextTarget] = useState<PredictedTargetNode | null>(null);
  const [isolatedHostIds, setIsolatedHostIds] = useState<string[]>([]);
  const [blockedPorts, setBlockedPorts] = useState<{ [hostId: string]: number[] }>({});

  // Active selections
  const [selectedHostId, setSelectedHostId] = useState('');
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge | null>(null);
  const [activeProfile, setActiveProfile] = useState<SourceExplainabilityProfile | null>(null);

  // Model Intelligence & KPI metrics (fetched from backend /api/telemetry)
  const [infiltrationRisk, setInfiltrationRisk] = useState(0);
  const [riskTrend, setRiskTrend] = useState('0');
  const [leadTime, setLeadTime] = useState('--');
  const [leadTimeDelta, setLeadTimeDelta] = useState('--');
  const [predictedStage, setPredictedStage] = useState('Initializing...');
  const [mitreTactic, setMitreTactic] = useState('Scanning...');
  const [modelConfidence, setModelConfidence] = useState(0);
  const [uncertainty, setUncertainty] = useState(0);

  // Telemetry sensor metrics (fetched from backend /api/telemetry & /api/forecast)
  const [portEntropy, setPortEntropy] = useState(0);
  const [synRatio, setSynRatio] = useState(0);
  const [logByteVolume, setLogByteVolume] = useState(0);

  // Trajectory forecast & Kill chain stages (fetched from backend /api/forecast)
  const [forecastPoints, setForecastPoints] = useState<ForecastPoint[]>([]);
  const [killChainStages, setKillChainStages] = useState<KillChainStage[]>([]);

  // What-If & Counterfactual simulation state
  const [selectedTargetHostId, setSelectedTargetHostId] = useState('');
  const [actionType, setActionType] = useState<DefenceActionType>('isolate_host');
  const [selectedPort, setSelectedPort] = useState(445);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulatedRisk, setSimulatedRisk] = useState(0);
  const [deltaPts, setDeltaPts] = useState(0);
  const [recentSimulations, setRecentSimulations] = useState<SimulationRecord[]>([]);
  const [showCounterfactualInForecast, setShowCounterfactualInForecast] = useState(true);

  // Load live data from real Express backend
  const loadBackendData = useCallback(async () => {
    try {
      setIsRefreshing(true);
      const networkData = await fetchNetworkState();
      setHosts(networkData.hosts || []);
      setEdges(networkData.edges || []);
      setAttackedNodes(networkData.attackedNodes || []);
      setPredictedNextTarget(networkData.predictedNextTarget || null);
      setIsolatedHostIds(networkData.isolatedHostIds || []);
      setBlockedPorts(networkData.blockedPorts || {});
      setWindowSeq(networkData.windowSeq || 0);
      setActiveCapture(networkData.activeCapture || null);
      setBackendConnected(true);

      // Select initial host and edge from live backend data if not already set
      if (networkData.hosts && networkData.hosts.length > 0) {
        setSelectedHostId((prev) => prev || networkData.hosts[0].id);
        setSelectedTargetHostId((prev) => prev || networkData.hosts[0].id);
      }
      const initialEdge = networkData.edges && networkData.edges.length > 1
        ? networkData.edges[1]
        : networkData.edges && networkData.edges.length > 0
        ? networkData.edges[0]
        : null;

      if (!selectedEdge && initialEdge) {
        setSelectedEdge(initialEdge);
      }

      // Fetch telemetry from backend
      const tel = await fetchTelemetry();
      setInfiltrationRisk(tel.infiltrationRisk ?? 0);
      setRiskTrend(tel.riskTrend ?? '0');
      setLeadTime(tel.leadTime ?? '--');
      setLeadTimeDelta(tel.leadTimeDelta ?? '--');
      setPredictedStage(tel.predictedStage ?? '');
      setMitreTactic(tel.mitreTactic ?? '');
      setModelConfidence(tel.modelConfidence ?? 94.2);
      setUncertainty(tel.uncertainty ?? 5.8);
      setPortEntropy(tel.portEntropy ?? 0);
      setSynRatio(tel.synRatio ?? 0);
      setLogByteVolume(tel.logByteVolume ?? 0);

      // Fetch alerts from backend
      const altData = await fetchAlerts();
      if (altData) {
        setAlerts(altData);
      }

      // Fetch forecast and kill chain progression from backend
      const fcData = await fetchForecast().catch(() => null);
      if (fcData) {
        setForecastPoints(fcData.points || []);
        setKillChainStages(fcData.killChainStages || []);
      }

      // Fetch simulations history from backend
      const simData = await fetchSimulations().catch(() => null);
      if (simData) {
        setRecentSimulations(simData);
      }

      // Fetch explainability for currently selected edge from backend
      const currentEdgeId = selectedEdge ? selectedEdge.id : initialEdge?.id;
      if (currentEdgeId) {
        const expData = await fetchExplainability(currentEdgeId).catch(() => null);
        if (expData) {
          setActiveProfile(expData);
        }
      }
    } catch (err) {
      console.warn('Backend loading attempt failed:', err);
      setBackendConnected(false);
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
    } catch (err) {
      console.error('Failed to fetch explainability for edge:', err);
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

  // If operator is not authenticated, display the SOC Login Portal
  if (!authUser) {
    return (
      <LoginPage
        onLoginSuccess={(user) => setAuthUser(user)}
        theme={theme}
        onSelectTheme={handleSelectTheme}
        soundEnabled={soundEnabled}
      />
    );
  }

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
        currentUser={authUser}
        onLogout={handleLogout}
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
            selectedEdgeId={selectedEdge ? selectedEdge.id : ''}
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
              features={activeProfile?.features || []}
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

        {/* VIEW 5: MODEL BENCHMARKS & FASTAPI INFERENCE CONTRACTS */}
        {activeTab === 'benchmarks' && (
          <ModelBenchmarksView
            theme={theme}
            soundEnabled={soundEnabled}
          />
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

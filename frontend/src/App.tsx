import React, { useState, useEffect, useCallback } from "react";
import { Header } from "./components/Header";
import { MetricCards } from "./components/MetricCards";
import { TrajectoryForecast } from "./components/TrajectoryForecast";
import { WhatIfCentre } from "./components/WhatIfCentre";
import { ExplainabilitySection } from "./components/ExplainabilitySection";
import { MainThreatTopologyView } from "./components/MainThreatTopologyView";
import { CaptureUploadModal } from "./components/CaptureUploadModal";
import { CaptureUtilityBar } from "./components/CaptureUtilityBar";
import { ModelBenchmarksView } from "./components/ModelBenchmarksView";
import { LoginPage } from "./components/LoginPage";
import { getExplainabilityForEdge } from "./data/initialData";
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
} from "./types";
import { playCyberTone } from "./utils/audio";
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
  apiDeployPolicy,
  apiResetPipeline
} from "./utils/api";
import { Upload, ShieldAlert, FileSearch, Wifi } from "lucide-react";

const EMPTY_PROFILE: SourceExplainabilityProfile = {
  riskScore: 0, riskTrend: "0", leadTime: "\u2014", leadTimeDelta: "\u2014",
  predictedStage: "\u2014", mitreTactic: "\u2014", portEntropy: 0, synRatio: 0,
  logByteVolume: 0, features: []
};

const EMPTY_KILL_CHAIN: KillChainStage[] = [
  { step: 1, name: "Reconnaissance", status: "upcoming", tacticId: "TA0043" },
  { step: 2, name: "Resource Development", status: "upcoming", tacticId: "TA0042" },
  { step: 3, name: "Initial Access", status: "upcoming", tacticId: "TA0001" },
  { step: 4, name: "Execution & C2", status: "upcoming", tacticId: "TA0002 / TA0011" },
  { step: 5, name: "Lateral Movement", status: "upcoming", tacticId: "TA0008" }
];

export default function App() {
  const [authUser, setAuthUser] = useState<AuthUser | null>(() => {
    try { const s = localStorage.getItem("vashikaran_user"); if (s) return JSON.parse(s); } catch {}
    return null;
  });
  const handleLogout = () => { try { localStorage.removeItem("vashikaran_user"); } catch {} setAuthUser(null); };

  const [activeTab, setActiveTabState] = useState<NavigationTab>(() => {
    try {
      const t = sessionStorage.getItem("vashikaran_active_tab") as NavigationTab;
      if (t && ["main_topology","trajectory","what_if","explainability","benchmarks"].includes(t)) return t;
    } catch {}
    return "main_topology";
  });
  const setActiveTab = (tab: NavigationTab) => { setActiveTabState(tab); try { sessionStorage.setItem("vashikaran_active_tab", tab); } catch {} };

  const [backendConnected, setBackendConnected] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isInitialLoading, setIsInitialLoading] = useState(true);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [activeCapture, setActiveCapture] = useState<CaptureMetadata | null>(null);
  const [hasCheckedServer, setHasCheckedServer] = useState(false);

  const [theme, setTheme] = useState<AppTheme>(() => {
    const s = localStorage.getItem("vashikaran_theme_mode") || localStorage.getItem("davaska_theme_mode");
    if (s === "slate" || s === "midnight" || s === "light") return s; return "light";
  });
  const handleSelectTheme = (t: AppTheme) => { setTheme(t); localStorage.setItem("vashikaran_theme_mode", t); document.documentElement.classList.toggle("dark", t !== "light"); };
  useEffect(() => { document.documentElement.classList.toggle("dark", theme !== "light"); }, [theme]);

  const [windowSeq, setWindowSeq] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [alerts, setAlerts] = useState<TelemetryAlert[]>([]);
  const [hosts, setHosts] = useState<NetworkHost[]>([]);
  const [edges, setEdges] = useState<NetworkEdge[]>([]);
  const [attackedNodes, setAttackedNodes] = useState<NetworkHost[]>([]);
  const [predictedNextTarget, setPredictedNextTarget] = useState<PredictedTargetNode | null>(null);
  const [isolatedHostIds, setIsolatedHostIds] = useState<string[]>([]);
  const [blockedPorts, setBlockedPorts] = useState<{ [hostId: string]: number[] }>({});
  const [selectedHostId, setSelectedHostId] = useState<string>("");
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge | null>(null);
  const [activeProfile, setActiveProfile] = useState<SourceExplainabilityProfile>(EMPTY_PROFILE);
  const [infiltrationRisk, setInfiltrationRisk] = useState(0);
  const [riskTrend, setRiskTrend] = useState("0");
  const [leadTime, setLeadTime] = useState("\u2014");
  const [leadTimeDelta, setLeadTimeDelta] = useState("\u2014");
  const [predictedStage, setPredictedStage] = useState("\u2014");
  const [mitreTactic, setMitreTactic] = useState("\u2014");
  const [modelConfidence, setModelConfidence] = useState(0);
  const [uncertainty, setUncertainty] = useState(0);
  const [portEntropy, setPortEntropy] = useState(0);
  const [synRatio, setSynRatio] = useState(0);
  const [logByteVolume, setLogByteVolume] = useState(0);
  const [forecastPoints, setForecastPoints] = useState<ForecastPoint[]>([]);
  const [killChainStages, setKillChainStages] = useState<KillChainStage[]>(EMPTY_KILL_CHAIN);
  const [selectedTargetHostId, setSelectedTargetHostId] = useState("");
  const [actionType, setActionType] = useState<DefenceActionType>("isolate_host");
  const [selectedPort, setSelectedPort] = useState(445);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulatedRisk, setSimulatedRisk] = useState(0);
  const [deltaPts, setDeltaPts] = useState(0);
  const [recentSimulations, setRecentSimulations] = useState<SimulationRecord[]>([]);
  const [showCounterfactualInForecast, setShowCounterfactualInForecast] = useState(false);

  const clearAllState = useCallback(() => {
    setHosts([]); setEdges([]); setAttackedNodes([]); setPredictedNextTarget(null);
    setIsolatedHostIds([]); setBlockedPorts({}); setWindowSeq(0); setAlerts([]);
    setForecastPoints([]); setKillChainStages(EMPTY_KILL_CHAIN);
    setInfiltrationRisk(0); setRiskTrend("0"); setLeadTime("\u2014"); setLeadTimeDelta("\u2014");
    setPredictedStage("\u2014"); setMitreTactic("\u2014"); setModelConfidence(0); setUncertainty(0);
    setPortEntropy(0); setSynRatio(0); setLogByteVolume(0); setRecentSimulations([]);
    setActiveProfile(EMPTY_PROFILE); setSelectedEdge(null);
  }, []);

  const loadBackendData = useCallback(async (forceReselect: boolean = false) => {
    try {
      setIsRefreshing(true);
      const networkData = await fetchNetworkState();
      const noData = (networkData as any)?.noDataUploaded === true || !networkData?.activeCapture;
      setActiveCapture(networkData?.activeCapture || null);
      setBackendConnected(true);
      setHasCheckedServer(true);
      if (noData) { clearAllState(); return; }

      const safeHosts = Array.isArray(networkData.hosts) ? networkData.hosts : [];
      const safeEdges = Array.isArray(networkData.edges) ? networkData.edges : [];
      setHosts(safeHosts);
      setEdges(safeEdges);
      setAttackedNodes(Array.isArray(networkData.attackedNodes) ? networkData.attackedNodes : safeHosts.filter((h: NetworkHost) => h.status === "compromised"));
      setPredictedNextTarget(networkData.predictedNextTarget || null);
      setIsolatedHostIds(networkData.isolatedHostIds || []);
      setBlockedPorts(networkData.blockedPorts || {});
      setWindowSeq(typeof networkData.windowSeq === "number" ? networkData.windowSeq : 0);
      const primaryId = networkData.predictedNextTarget?.hostId || safeHosts[0]?.id || "";
      setSelectedHostId(prev => (!forceReselect && safeHosts.some((h: NetworkHost) => h.id === prev)) ? prev : primaryId);
      setSelectedTargetHostId(prev => (!forceReselect && safeHosts.some((h: NetworkHost) => h.id === prev)) ? prev : primaryId);
      let edgeToSelect: NetworkEdge | null = null;
      if (!forceReselect && selectedEdge) edgeToSelect = safeEdges.find((e: NetworkEdge) => e.id === selectedEdge.id) || null;
      if (!edgeToSelect && safeEdges.length > 0) {
        const tgtId = networkData.predictedNextTarget?.hostId;
        edgeToSelect = safeEdges.find((e: NetworkEdge) => e.target === tgtId) || safeEdges.find((e: NetworkEdge) => e.type === "attack") || safeEdges[0];
      }
      if (edgeToSelect) { setSelectedEdge(edgeToSelect); if (edgeToSelect.port) setSelectedPort(edgeToSelect.port); }

      const tel = await fetchTelemetry().catch(() => null);
      if (tel) {
        setInfiltrationRisk(tel.infiltrationRisk ?? 0); setRiskTrend(tel.riskTrend ?? "0");
        setLeadTime(tel.leadTime ?? "\u2014"); setLeadTimeDelta(tel.leadTimeDelta ?? "\u2014");
        setPredictedStage(tel.predictedStage ?? "\u2014"); setMitreTactic(tel.mitreTactic ?? "\u2014");
        setModelConfidence(tel.modelConfidence ?? 0); setUncertainty(tel.uncertainty ?? 0);
        setPortEntropy(tel.portEntropy ?? 0); setSynRatio(tel.synRatio ?? 0); setLogByteVolume(tel.logByteVolume ?? 0);
      }
      const altData = await fetchAlerts().catch(() => null);
      if (altData?.length) setAlerts(altData);
      const fcData = await fetchForecast().catch(() => null);
      if (fcData) { setForecastPoints(fcData.points); setKillChainStages(fcData.killChainStages); }
      const simData = await fetchSimulations().catch(() => null);
      if (simData?.length) setRecentSimulations(simData);
      const eid = edgeToSelect?.id || safeEdges[0]?.id;
      if (eid) {
        const expData = await fetchExplainability(eid).catch(() => null);
        if (expData) setActiveProfile(expData);
        else if (edgeToSelect) setActiveProfile(getExplainabilityForEdge(edgeToSelect));
      }
    } catch (err) {
      console.warn("Backend load error:", err);
      setBackendConnected(false);
    } finally {
      setIsRefreshing(false); setIsInitialLoading(false); setHasCheckedServer(true);
    }
  }, [clearAllState, selectedEdge]);

  useEffect(() => { loadBackendData(); }, [loadBackendData]);
  useEffect(() => {
    if (isPaused || !activeCapture) return;
    const iv = setInterval(() => setWindowSeq(p => p + 1), 12000);
    return () => clearInterval(iv);
  }, [isPaused, activeCapture]);

  const handleSelectEdge = async (edge: NetworkEdge) => {
    setSelectedEdge(edge); setSelectedPort(edge.port);
    try {
      const exp = await fetchExplainability(edge.id);
      if (exp) { setActiveProfile(exp); setInfiltrationRisk(exp.riskScore); setRiskTrend(exp.riskTrend); setLeadTime(exp.leadTime); setLeadTimeDelta(exp.leadTimeDelta); setMitreTactic(exp.mitreTactic); setPredictedStage(exp.predictedStage); setPortEntropy(exp.portEntropy); setSynRatio(exp.synRatio); setLogByteVolume(exp.logByteVolume); }
    } catch { setActiveProfile(getExplainabilityForEdge(edge)); }
  };

  const handleSelectHost = async (hostId: string) => {
    setSelectedHostId(hostId); setSelectedTargetHostId(hostId);
    const host = hosts.find(h => h.id === hostId);
    if (host?.openPorts?.length) setSelectedPort(host.openPorts[0]);
    const connected = edges.filter(e => e.source === hostId || e.target === hostId);
    const pe = connected.find(e => e.target === hostId && e.type === "attack") || connected.find(e => e.source === hostId && e.type === "attack") || connected[0];
    if (pe) { setSelectedEdge(pe); fetchExplainability(pe.id).then(exp => { if (exp) setActiveProfile(exp); }).catch(() => { setActiveProfile(getExplainabilityForEdge(pe)); }); }
  };

  const handleNavigateToWhatIf = (tid?: string) => {
    if (tid) { setSelectedTargetHostId(tid); const h = hosts.find(x => x.id === tid); if (h?.openPorts?.length) setSelectedPort(h.openPorts[0]); }
    setActiveTab("what_if");
  };
  const handleSelectSource = (sid: string) => handleSelectHost(sid);

  const handleToggleIsolate = async (hostId: string) => {
    const iso = isolatedHostIds.includes(hostId);
    setIsolatedHostIds(prev => iso ? prev.filter(id => id !== hostId) : [...prev, hostId]);
    try { const r = await apiIsolateHost(hostId, !iso); if (r?.predictedNextTarget) { setPredictedNextTarget(r.predictedNextTarget); setInfiltrationRisk(Math.round(r.predictedNextTarget.probabilityPercent)); } if (soundEnabled) playCyberTone("policy"); loadBackendData(); } catch(e) { console.error(e); }
  };

  const handleQuickMitigate = async (targetId: string, port?: number) => {
    try { const r = await apiBlockPort(targetId, port || 445); setBlockedPorts(r.blockedPorts || {}); if (r.predictedNextTarget) { setPredictedNextTarget(r.predictedNextTarget); setInfiltrationRisk(Math.round(r.predictedNextTarget.probabilityPercent)); } if (soundEnabled) playCyberTone("policy"); loadBackendData(); } catch(e) { console.error(e); }
  };

  const handleRunSimulation = async () => {
    setIsSimulating(true);
    try {
      const r = await apiSimulateAction(actionType, selectedTargetHostId, selectedPort);
      setSimulatedRisk(r.simulatedRisk); setDeltaPts(r.deltaPts); setShowCounterfactualInForecast(true);
      setForecastPoints(prev => prev.map(p => p.seconds <= 0 ? p : { ...p, counterfactual: Math.round(p.baseline * (1 - Math.min(1, p.seconds / 15)) + r.simulatedRisk * Math.min(1, p.seconds / 15)) }));
      const sl = await fetchSimulations().catch(() => null);
      if (sl?.length) setRecentSimulations(sl);
      if (soundEnabled) playCyberTone("sim");
    } catch(e) { console.error(e); } finally { setIsSimulating(false); }
  };

  const handleDeployPolicy = async () => {
    try { const r = await apiDeployPolicy(actionType, selectedTargetHostId, selectedPort); if (r.isolatedHostIds) setIsolatedHostIds(r.isolatedHostIds); if (r.blockedPorts) setBlockedPorts(r.blockedPorts); if (r.predictedNextTarget) setPredictedNextTarget(r.predictedNextTarget); setInfiltrationRisk(simulatedRisk); setRiskTrend("0"); if (soundEnabled) playCyberTone("policy"); loadBackendData(); } catch(e) { console.error(e); }
  };

  const handleSelectSimulation = (sim: SimulationRecord) => {
    setActionType(sim.actionType); setSelectedTargetHostId(sim.targetId); if (sim.port) setSelectedPort(sim.port);
    setSimulatedRisk(sim.simulatedRisk); setDeltaPts(Math.abs(sim.delta)); setShowCounterfactualInForecast(true);
  };

  const handleResetPipeline = async () => {
    try { await apiResetPipeline(); await loadBackendData(true); } catch(e) { console.error(e); }
  };

  const isLight = theme === "light";
  const showUploadGate = hasCheckedServer && !activeCapture;

  if (!authUser) return <LoginPage onLoginSuccess={u => setAuthUser(u)} theme={theme} onSelectTheme={handleSelectTheme} soundEnabled={soundEnabled} />;

  return (
    <div className={`min-h-screen transition-colors duration-200 ${isLight ? "bg-slate-100 text-slate-800" : "bg-[#030914] text-slate-100"}`}>
      <Header
        windowSeq={windowSeq} isPaused={isPaused} onTogglePause={() => setIsPaused(!isPaused)}
        alerts={alerts} soundEnabled={soundEnabled} onToggleSound={() => setSoundEnabled(!soundEnabled)}
        activeTab={activeTab} onSelectTab={setActiveTab} attackedCount={attackedNodes.length}
        predictedTargetName={predictedNextTarget?.name || "\u2014"}
        predictedProbability={predictedNextTarget?.probabilityPercent || infiltrationRisk}
        backendConnected={backendConnected} activeCapture={activeCapture}
        onOpenUploadModal={() => setIsUploadModalOpen(true)} theme={theme} onSelectTheme={handleSelectTheme}
        currentUser={authUser} onLogout={handleLogout} onResetPipeline={handleResetPipeline}
      />
      <main className="flex-1 w-full max-w-[1720px] mx-auto px-4 sm:px-6 lg:px-8 pt-6 sm:pt-8 pb-16">

        {/* UPLOAD GATE */}
        {showUploadGate && (
          <div className={`flex flex-col items-center justify-center min-h-[72vh] rounded-3xl border-2 border-dashed transition-all ${isLight ? "border-slate-300 bg-gradient-to-br from-slate-50 to-indigo-50/40" : "border-slate-700/60 bg-gradient-to-br from-[#060e20] to-[#0a1430]"}`}>
            <div className="relative mb-8">
              <div className={`w-32 h-32 rounded-full flex items-center justify-center border-2 ${isLight ? "border-indigo-200 bg-indigo-50" : "border-indigo-800/50 bg-indigo-950/30"}`}>
                <div className={`absolute w-32 h-32 rounded-full border-2 animate-ping opacity-20 ${isLight ? "border-indigo-400" : "border-indigo-500"}`} />
                <ShieldAlert className={`w-14 h-14 ${isLight ? "text-indigo-500" : "text-indigo-400"}`} />
              </div>
            </div>
            <h2 className={`text-2xl sm:text-3xl font-bold mb-3 text-center ${isLight ? "text-slate-900" : "text-white"}`}>
              No Network Capture Loaded
            </h2>
            <p className={`text-sm sm:text-base text-center max-w-md mb-8 leading-relaxed ${isLight ? "text-slate-500" : "text-slate-400"}`}>
              Upload a <strong className={isLight ? "text-slate-700" : "text-slate-200"}>.pcap</strong>,{" "}
              <strong className={isLight ? "text-slate-700" : "text-slate-200"}>.pcapng</strong>,{" "}
              <strong className={isLight ? "text-slate-700" : "text-slate-200"}>.csv</strong>, or{" "}
              <strong className={isLight ? "text-slate-700" : "text-slate-200"}>.log</strong> file to begin World Model inference. The GNN + Transformer pipeline will analyse your traffic, build a network state graph, and predict infiltration probability with MITRE ATT&amp;CK stage attribution.
            </p>
            <button onClick={() => setIsUploadModalOpen(true)}
              className={`flex items-center space-x-3 px-8 py-4 rounded-2xl font-bold text-base transition-all shadow-lg hover:scale-105 active:scale-100 ${isLight ? "bg-indigo-600 hover:bg-indigo-700 text-white shadow-indigo-600/30" : "bg-indigo-600 hover:bg-indigo-500 text-white shadow-[0_0_30px_rgba(99,102,241,0.3)]"}`}>
              <Upload className="w-5 h-5" /><span>Upload Network Capture</span>
            </button>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-12 max-w-2xl w-full px-4">
              {[{ icon: FileSearch, title: "PCAP Analysis", desc: "Binary packet dissection via C-struct unpacking — processes 200 MB+ files in seconds." },
                { icon: Wifi, title: "GNN World Model", desc: "Graph Neural Network builds host topology from flow telemetry in real time." },
                { icon: ShieldAlert, title: "MITRE ATT&CK", desc: "Predicts tactic stage, infiltration probability and attack vector with K=4 rollout." }
              ].map(({ icon: Icon, title, desc }) => (
                <div key={title} className={`p-4 rounded-2xl border text-center ${isLight ? "bg-white border-slate-200" : "bg-slate-900/50 border-slate-800"}`}>
                  <Icon className={`w-7 h-7 mx-auto mb-2 ${isLight ? "text-indigo-500" : "text-indigo-400"}`} />
                  <div className={`text-xs font-bold font-mono mb-1 ${isLight ? "text-slate-700" : "text-slate-300"}`}>{title}</div>
                  <p className={`text-[11px] leading-relaxed ${isLight ? "text-slate-500" : "text-slate-500"}`}>{desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* INITIAL LOADING SPINNER */}
        {isInitialLoading && (
          <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
            <div className={`w-12 h-12 rounded-full border-4 border-t-transparent animate-spin ${isLight ? "border-indigo-500" : "border-indigo-400"}`} />
            <p className={`text-sm font-mono ${isLight ? "text-slate-500" : "text-slate-400"}`}>Connecting to World Model backend\u2026</p>
          </div>
        )}

        {/* DASHBOARD — only shown when a capture is loaded */}
        {!showUploadGate && !isInitialLoading && (
          <>
            {activeTab === "main_topology" && (
              <MainThreatTopologyView hosts={hosts} edges={edges} attackedNodes={attackedNodes}
                predictedNextTarget={predictedNextTarget} selectedHostId={selectedHostId}
                onSelectHost={handleSelectHost} selectedEdgeId={selectedEdge?.id || ""}
                onSelectEdge={handleSelectEdge} isolatedHostIds={isolatedHostIds} blockedPorts={blockedPorts}
                onToggleIsolate={handleToggleIsolate} onQuickMitigate={handleQuickMitigate}
                onRefreshData={loadBackendData} isRefreshing={isRefreshing} soundEnabled={soundEnabled}
                onNavigateToWhatIf={handleNavigateToWhatIf} activeCapture={activeCapture}
                onOpenUploadModal={() => setIsUploadModalOpen(true)} theme={theme}
              />
            )}
            {activeTab === "trajectory" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <CaptureUtilityBar activeCapture={activeCapture} onOpenUploadModal={() => setIsUploadModalOpen(true)} onRefreshData={loadBackendData} isRefreshing={isRefreshing} soundEnabled={soundEnabled} theme={theme} />
                <MetricCards infiltrationRisk={infiltrationRisk} riskTrend={riskTrend} leadTime={leadTime} leadTimeDelta={leadTimeDelta} predictedStage={predictedStage} mitreTactic={mitreTactic} modelConfidence={modelConfidence} uncertainty={uncertainty} theme={theme} />
                <TrajectoryForecast points={forecastPoints} killChainStages={killChainStages} portEntropy={portEntropy} synRatio={synRatio} logByteVolume={logByteVolume} showCounterfactual={showCounterfactualInForecast} soundEnabled={soundEnabled} theme={theme} />
              </div>
            )}
            {activeTab === "what_if" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <CaptureUtilityBar activeCapture={activeCapture} onOpenUploadModal={() => setIsUploadModalOpen(true)} onRefreshData={loadBackendData} isRefreshing={isRefreshing} soundEnabled={soundEnabled} theme={theme} />
                <WhatIfCentre hosts={hosts} selectedTargetHostId={selectedTargetHostId} onSelectTargetHost={setSelectedTargetHostId} actionType={actionType} onChangeActionType={setActionType} selectedPort={selectedPort} onSelectPort={setSelectedPort} onRunSimulation={handleRunSimulation} isSimulating={isSimulating} currentThreatRisk={infiltrationRisk} simulatedRisk={simulatedRisk} deltaPts={deltaPts} recentSimulations={recentSimulations} onSelectSimulation={handleSelectSimulation} onDeployPolicy={handleDeployPolicy} soundEnabled={soundEnabled} theme={theme} />
              </div>
            )}
            {activeTab === "explainability" && (
              <div className="space-y-6 animate-in fade-in duration-200">
                <CaptureUtilityBar activeCapture={activeCapture} onOpenUploadModal={() => setIsUploadModalOpen(true)} onRefreshData={loadBackendData} isRefreshing={isRefreshing} soundEnabled={soundEnabled} theme={theme} />
                <ExplainabilitySection features={activeProfile.features} profile={activeProfile} edges={edges} selectedEdge={selectedEdge || edges[0] || null} onSelectEdge={handleSelectEdge} onSelectSource={handleSelectSource} soundEnabled={soundEnabled} theme={theme} />
              </div>
            )}
            {activeTab === "benchmarks" && <ModelBenchmarksView theme={theme} soundEnabled={soundEnabled} />}
          </>
        )}
      </main>

      <CaptureUploadModal isOpen={isUploadModalOpen} onClose={() => setIsUploadModalOpen(false)} activeCapture={activeCapture} onCaptureLoaded={() => loadBackendData(true)} soundEnabled={soundEnabled} theme={theme} />
    </div>
  );
}

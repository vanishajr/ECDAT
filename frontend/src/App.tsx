import {
  ArrowRight,
  Box,
  BrainCircuit,
  Check,
  CircleAlert,
  FileCode2,
  FolderOpen,
  GitFork,
  LogOut,
  Play,
  Search,
  ShieldAlert,
  Sparkles,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { CryptoGraph } from "./graph/CryptoGraph";
import heroOrbit from "../hero-orbit.png";
import {
  ChangeEvent,
  DragEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

type InputInfo = {
  input_id: string;
  name: string;
  file_count: number;
  total_bytes: number;
  extensions: string[];
  languages: string[];
  architecture: string;
  artifact_counts?: Record<string, number>;
  surfaces?: Record<string, number>;
  archives?: Array<Record<string, any>>;
  skipped?: Array<{ path?: string; reason?: string }>;
};

type Job = {
  job_id: string;
  status: "queued" | "running" | "completed" | "failed";
  progress: number;
  stage: string;
  scan_id?: string;
  error?: string;
  scanners: string[];
};

type Result = Record<string, any>;
type GithubSession = { authenticated: boolean; login: string | null };
type GithubRepository = {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  owner: string;
  default_branch: string;
  description: string | null;
  language: string | null;
  updated_at: string | null;
};
type GithubProjectStatus = "idle" | "loading" | "uploaded";
type Demo = {
  id: string;
  name: string;
  description: string;
  language: string;
  files: string[];
  code: string;
};

const API = "/api";
const layers = [
  ["source", "Source code"],
  ["dependency", "Dependencies"],
  ["binary", "Binary analysis"],
  ["config", "Configuration"],
  ["certificate", "Certificates / keys"],
  ["container", "Container contents"],
  ["runtime", "Runtime endpoint"],
  ["cloud", "Cloud resources"],
];
const tabs = [
  "Overview",
  "Findings",
  "Crypto Inventory",
  "Crypto Graph",
  "Migration",
  "Coverage",
];

// Local/static coverage is automatic for every profile (Phase 3+); the
// user only opts in to external discovery. Kept in sync with the
// backend DEFAULT_SCANNERS list.
const AUTO_LOCAL = [
  "source",
  "dependency",
  "binary",
  "config",
  "certificate",
];

const api = async (url: string, init?: RequestInit) => {
  const response = await fetch(`${API}${url}`, {
    ...init,
    credentials: "include",
  });
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    throw new Error(
      typeof body === "string" ? body : body.error || "Request failed",
    );
  }

  return body;
};

const bytes = (value = 0) =>
  value < 1024 * 1024
    ? `${Math.max(1, Math.ceil(value / 1024))} KB`
    : `${(value / 1024 / 1024).toFixed(1)} MB`;

const surfaceNames = (surfaces?: Record<string, number>) =>
  Object.entries(surfaces || {})
    .filter(([, count]) => Number(count) > 0)
    .map(([name, count]) => `${name} (${count})`);

const tone = (level = "info") => {
  const tones: Record<string, string> = {
    critical: "bg-[#762f32] text-white",
    high: "bg-[#a96f52] text-white",
    medium: "bg-[#c58a43] text-white",
    low: "bg-[#a9824b] text-white",
    info: "bg-[#718aa0] text-white",
  };
  return tones[level.toLowerCase()] || tones.info;
};

const dotTone = (level = "info") => {
  const tones: Record<string, string> = {
    critical: "bg-[#b8424d]",
    high: "bg-[#a96f52]",
    medium: "bg-[#d78b3e]",
    low: "bg-[#b88945]",
    info: "bg-[#6586a4]",
  };
  return tones[level.toLowerCase()] || tones.info;
};

// Risk-circle accent: tinted ring + score number per risk level,
// reusing the severity palette. Restrained: track stays neutral.
const riskAccent = (level = "info") => {
  const accents: Record<string, string> = {
    critical: "border-[#b8424d] text-[#8b1f24]",
    high: "border-[#a96f52] text-[#8a5636]",
    medium: "border-[#d78b3e] text-[#8a6414]",
    low: "border-[#b88945] text-[#6f5a1e]",
    info: "border-[#6586a4] text-[#3d5a73]",
  };
  return accents[level.toLowerCase()] || "border-[#d5d1c8] text-[#181a19]";
};

function Button({
  children,
  variant = "dark",
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "dark" | "light" | "ghost";
}) {
  const variants = {
    dark: "bg-[#181a19] text-white shadow-[0_8px_18px_rgba(24,26,25,.14)] hover:bg-[#30312f]",
    light: "border border-[#d4d0c8] bg-white/60 text-[#292a28] hover:bg-white",
    ghost: "text-[#5e5d58] hover:bg-[#e8e4dc] hover:text-[#181a19]",
  };
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-full px-4 py-2.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

function Card({
  children,
  className = "",
  ...props
}: React.HTMLAttributes<HTMLElement>) {
  return (
    <article
      className={`rounded-[1.25rem] border border-[#d7d3ca] bg-[#f8f6f1]/90 shadow-[0_12px_34px_rgba(79,74,65,.07)] ${className}`}
      {...props}
    >
      {children}
    </article>
  );
}

function SectionLabel({
  step,
  children,
}: {
  step?: string;
  children: React.ReactNode;
}) {
  return (
    <p className="mb-5 flex items-center gap-3 text-xs font-semibold uppercase tracking-[.18em] text-[#282927]">
      {step && (
        <i className="grid h-6 w-6 place-items-center rounded-full bg-[#dedbd4] not-italic tracking-normal">
          {step}
        </i>
      )}
      {children}
    </p>
  );
}

export default function App() {
  const fileRef = useRef<HTMLInputElement>(null);
  const folderRef = useRef<HTMLInputElement>(null);
  const [input, setInput] = useState<InputInfo | null>(null);
  // Single default analysis mode: the backend always runs the standard
  // profile. No depth selector is exposed.
  const [selected, setSelected] = useState<string[]>([
    "source",
    "dependency",
    "config",
    "certificate",
  ]);
  // Phase 12 scan-plan UX: automatic discovery by default; manual scanner
  // overrides live under Advanced for debugging/expert usage.
  const [advanced, setAdvanced] = useState(false);
  const [allowPull, setAllowPull] = useState(false);
  const [allowBuild, setAllowBuild] = useState(false);
  const [probeRuntime, setProbeRuntime] = useState(false);
  const [connectCloud, setConnectCloud] = useState(false);
  // Cloud configuration state
  const [cloudConfig, setCloudConfig] = useState<{
    provider: "aws" | "azure" | "gcp";
    awsProfile: string;
    awsAccessKey: string;
    awsSecretKey: string;
    awsSessionToken: string;
    awsRegion: string;
    services: string;
  }>({
    provider: "aws",
    awsProfile: "default",
    awsAccessKey: "",
    awsSecretKey: "",
    awsSessionToken: "",
    awsRegion: "us-east-1",
    services: "kms,acm,elb,alb",
  });
  const [showCloudConfig, setShowCloudConfig] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [tab, setTab] = useState("Overview");
  const [exportFormat, setExportFormat] = useState("pdf");
  // Cross-tab rule focus: "View migration/finding" jumps set both the
  // target tab and a rule filter. Cleared on manual tab switches.
  const [ruleFocus, setRuleFocus] = useState<string | null>(null);
  const jump = (next: string, rule: string | null) => {
    setRuleFocus(rule);
    setTab(next);
  };
  const [error, setError] = useState("");
  const [githubUrl, setGithubUrl] = useState("");
  const [dragging, setDragging] = useState(false);
  const [githubSession, setGithubSession] = useState<GithubSession>({
    authenticated: false,
    login: null,
  });
  const [repositories, setRepositories] = useState<GithubRepository[]>([]);
  const [repositorySearch, setRepositorySearch] = useState("");
  const [repositoryFilter, setRepositoryFilter] = useState<
    "all" | "private" | "public"
  >("all");
  const [repositoriesLoading, setRepositoriesLoading] = useState(false);
  const [githubProjectStatus, setGithubProjectStatus] =
    useState<GithubProjectStatus>("idle");
  const [githubProgress, setGithubProgress] = useState(0);
  // Demo inputs (alternative to file upload).
  const [demos, setDemos] = useState<Demo[]>([]);
  const [demoId, setDemoId] = useState("");
  const [demoBusy, setDemoBusy] = useState(false);
  // Demo currently loaded as the scan input (button shows Loaded/disabled).
  const [loadedDemoId, setLoadedDemoId] = useState("");

  const loadRepositories = async () => {
    setRepositoriesLoading(true);
    try {
      const data = await api("/github/repos");
      setRepositories(data.repositories || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load repositories");
    } finally {
      setRepositoriesLoading(false);
    }
  };

  useEffect(() => {
    void api("/github/session")
      .then((session) => {
        setGithubSession(session);
        if (session.authenticated) void loadRepositories();
      })
      .catch(() => undefined);
    void api("/demos")
      .then((data) => setDemos(data.demos || []))
      .catch(() => undefined);
  }, []);

  const signInWithGithub = () => {
    const frontend = encodeURIComponent(window.location.origin);
    window.location.assign(`${API}/github/oauth/start?frontend=${frontend}`);
  };

  const logoutGithub = async () => {
    await api("/github/logout", { method: "POST" });
    setGithubSession({ authenticated: false, login: null });
    setRepositories([]);
  };

  const selectRepository = async (repository: GithubRepository) => {
    setError("");
    setGithubProjectStatus("loading");
    setGithubProgress(12);
    try {
      setGithubProgress(35);
      const selectedInput = await api("/github/repos/select", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          owner: repository.owner,
          repo: repository.name,
          ref: repository.default_branch,
        }),
      });
      setInput(selectedInput);
      setLoadedDemoId("");
      setResult(null);
      setJob(null);
      setGithubProgress(100);
      setGithubProjectStatus("uploaded");
    } catch (e) {
      setGithubProjectStatus("idle");
      setGithubProgress(0);
      setError(e instanceof Error ? e.message : "Could not select repository");
    }
  };

  const visibleRepositories = repositories.filter((repository) => {
    const matchesSearch = repository.full_name
      .toLowerCase()
      .includes(repositorySearch.toLowerCase());
    const matchesFilter =
      repositoryFilter === "all" ||
      (repositoryFilter === "private" && repository.private) ||
      (repositoryFilter === "public" && !repository.private);
    return matchesSearch && matchesFilter;
  });

  const reset = async () => {
    if (input)
      await fetch(`${API}/inputs/${input.input_id}`, { method: "DELETE" });
    setInput(null);
    setJob(null);
    setResult(null);
    setError("");
    setTab("Overview");
    setRuleFocus(null);
    setLoadedDemoId("");
    setGithubProjectStatus("idle");
    setGithubProgress(0);
  };

  useEffect(() => {
    return () => {
      if (input)
        void fetch(`${API}/inputs/${input.input_id}`, { method: "DELETE" });
    };
  }, [input]);

  const upload = async (files: FileList | File[]) => {
    setError("");
    setGithubProjectStatus("idle");
    setGithubProgress(0);
    const all = Array.from(files);
    if (!all.length) return;

    try {
      let inputId: string | undefined;
      for (const file of all) {
        const relative =
          (file as File & { webkitRelativePath?: string }).webkitRelativePath ||
          file.name;
        const response = await fetch(`${API}/uploads`, {
          method: "POST",
          body: file,
          headers: {
            "Content-Type": "application/octet-stream",
            "X-File-Name": file.name,
            "X-Relative-Path": relative,
            ...(inputId ? { "X-Input-Id": inputId } : {}),
          },
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Upload failed");
        inputId = data.input_id;
      }

      const inspected = await api("/inputs/inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input_id: inputId }),
      });
      setInput(inspected);
      setLoadedDemoId("");
      setResult(null);
      setJob(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not upload input");
    }
  };

  const uploadChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) void upload(event.target.files);
    event.target.value = "";
  };

  const drop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    if (event.dataTransfer.files.length) void upload(event.dataTransfer.files);
  };

  const connectPublicRepo = async () => {
    if (!githubUrl.trim()) return;
    setError("");
    setGithubProjectStatus("loading");
    setGithubProgress(18);
    try {
      setGithubProgress(40);
      setInput(
        await api("/github/public", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: githubUrl }),
        }),
      );
      setLoadedDemoId("");
      setResult(null);
      setJob(null);
      setGithubProgress(100);
      setGithubProjectStatus("uploaded");
    } catch (e) {
      setGithubProjectStatus("idle");
      setGithubProgress(0);
      setError(e instanceof Error ? e.message : "Could not clone repository");
    }
  };
  const useInput = (selectedInput: InputInfo) => {
    setInput(selectedInput);
    setResult(null);
    setJob(null);
  };

  const useDemo = async () => {
    if (!demoId) return;
    setError("");
    setDemoBusy(true);
    try {
      const selectedInput = await api("/demos/select", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ demo_id: demoId }),
      });
      useInput(selectedInput);
      setLoadedDemoId(demoId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load demo");
    } finally {
      setDemoBusy(false);
    }
  };

  const scanBody = () => {
    const scanners = advanced
      ? selected
      : [
          ...AUTO_LOCAL,
          ...(probeRuntime ? ["runtime"] : []),
          ...(connectCloud ? ["cloud"] : []),
        ];
    const body: Record<string, any> = {
      input_id: input?.input_id,
      profile: "standard",
      scanners,
      allowPull,
      allowBuild,
    };
    // Include cloud configuration when cloud scanning is enabled
    if (connectCloud && cloudConfig.provider === "aws") {
      body.cloudConfig = {
        provider: "aws",
        profile: cloudConfig.awsProfile || "default",
        region: cloudConfig.awsRegion || "us-east-1",
        services: cloudConfig.services || "kms,acm,elb,alb",
        // Only include credentials if using access key auth
        ...(cloudConfig.awsAccessKey && {
          aws_access_key_id: cloudConfig.awsAccessKey,
          aws_secret_access_key: cloudConfig.awsSecretKey,
          ...(cloudConfig.awsSessionToken && { aws_session_token: cloudConfig.awsSessionToken }),
        }),
        // Profile name for profile-based auth
        ...(!cloudConfig.awsAccessKey && cloudConfig.awsProfile && {
          profile_name: cloudConfig.awsProfile,
        }),
      };
    }
    return body;
  };

  const analyse = async () => {
    if (!input) return;
    setError("");
    try {
      const started = (await api("/scan-jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(scanBody()),
      })) as Job;
      setJob(started);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to start analysis");
    }
  };

  useEffect(() => {
    if (!job || ["completed", "failed"].includes(job.status)) return;
    const timer = window.setInterval(async () => {
      try {
        setJob(await api(`/jobs/${job.job_id}`));
      } catch (e) {
        setError(e instanceof Error ? e.message : "Status unavailable");
      }
    }, 700);
    return () => window.clearInterval(timer);
  }, [job]);

  useEffect(() => {
    if (job?.status !== "completed" || !job.scan_id) return;
    void api(`/results/${job.scan_id}`)
      .then(setResult)
      .catch((e: Error) => setError(e.message));
  }, [job?.status, job?.scan_id]);

  const cards = useMemo(
    () =>
      result
        ? [
            ["Risk level", result.analytics.risk.level, ShieldAlert],
            ["Findings", String(result.analytics.finding_count), FileCode2],
            ["Assets", String(result.analytics.asset_count), Box],
            [
              "Operations",
              String(result.analytics.operation_count),
              BrainCircuit,
            ],
          ]
        : [],
    [result],
  );

  // Repository-relative display: backend report fields are already
  // relative; raw CIR/canonical paths may still be absolute temp paths.
  const rel = (path: string) => {
    const target = result?.canonical?.target || "";
    if (typeof path !== "string" || !path) return "—";
    const norm = path.replaceAll("\\", "/");
    const base = String(target).replaceAll("\\", "/").replace(/\/$/, "");
    if (base && norm === base) return norm.split("/").pop() || norm;
    if (base && norm.startsWith(`${base}/`)) return norm.slice(base.length + 1);
    return path;
  };

  const download = (format: string) => {
    if (result)
      window.open(
        `${API}/results/${result.scan_id}/report/${format}`,
        "_blank",
        "noopener,noreferrer",
      );
  };

  return (
    <main className="relative min-h-screen overflow-x-hidden bg-[#ebe8e1] text-[#181a19]">
      <img
        src={heroOrbit}
        alt=""
        aria-hidden="true"
        className="pointer-events-none absolute right-[-12vw] top-0 z-0 w-[min(112rem,112vw)] max-w-none object-contain opacity-50 sm:right-[-8vw] sm:opacity-70"
      />
      <nav className="relative z-10 mx-auto flex w-[min(1440px,calc(100%-2rem))] items-center py-6 sm:py-8">
        <a className="text-xl font-semibold tracking-[.42em]" href="#top">
          ECDAT
        </a>
      </nav>

      <section
        id="top"
        className="relative z-10 overflow-visible border-b border-[#d4d0c8] bg-transparent"
      >
        <div className="relative z-10 mx-auto w-[min(1440px,calc(100%-2rem))] pb-16 pt-10 sm:pb-24 sm:pt-20">
          <p className="mb-5 text-xs font-semibold uppercase tracking-[.3em] text-[#5e5d58]">
            Cryptographic intelligence
          </p>
          <h1 className="max-w-3xl text-4xl font-light leading-[1.06] tracking-[-.045em] sm:text-6xl lg:text-7xl">
            Cryptography decoded.
            <br />
            Analyze. Understand.
          </h1>
          <div className="mt-10 grid max-w-3xl gap-5 text-xs text-[#686761] sm:grid-cols-3">
            {[
              "Deep insights|Across code and binaries",
              "Privacy focused|Temporary local session",
              "Built for tomorrow|Visibility before migration",
            ].map((item) => {
              const [title, text] = item.split("|");
              return (
                <span key={title} className="border-l border-[#bdb9b0] pl-4">
                  <b className="mb-1 block text-[10px] uppercase tracking-[.2em] text-[#292a28]">
                    {title}
                  </b>
                  {text}
                </span>
              );
            })}
          </div>
        </div>
      </section>

      <section
        id="analyse"
        className="relative z-10 mx-auto grid w-[min(1440px,calc(100%-2rem))] gap-4 py-6 sm:py-8 lg:grid-cols-[1.35fr_1fr]"
      >
        <Card className="p-5 sm:p-7">
          <SectionLabel step="1">Project upload</SectionLabel>
          {!input ? (
            <>
              <div
                className={`flex min-h-64 flex-col items-center justify-center rounded-2xl border border-dashed p-6 text-center transition ${dragging ? "border-[#181a19] bg-white/70" : "border-[#bdb9b0] bg-white/25"}`}
                onDrop={drop}
                onDragOver={(event) => {
                  event.preventDefault();
                  setDragging(true);
                }}
                onDragLeave={() => setDragging(false)}
              >
                <Upload className="mb-4" size={30} />
                <strong className="text-sm sm:text-base">
                  Drag and drop a file, folder or archive here
                </strong>
                <span className="mt-2 text-sm text-[#74716a]">
                  or browse from your device
                </span>
                <div className="mt-6 flex flex-wrap justify-center gap-2">
                  <Button onClick={() => fileRef.current?.click()}>
                    Browse files <ArrowRight size={16} />
                  </Button>
                </div>
              </div>
              <input
                ref={fileRef}
                className="hidden"
                type="file"
                multiple
                accept=".zip,.tar,.gz,.tgz,.py,.js,.ts,.java,.go,.rs,.c,.cpp,.h,.cs,.pem,.der,.pfx,.p12,.jks,.jwk,.json,.yaml,.yml,.toml,.conf,.exe,.dll,.so,.elf,.bin"
                onChange={uploadChange}
              />
              <input
                ref={folderRef}
                className="hidden"
                type="file"
                multiple
                {...({ webkitdirectory: "", directory: "" } as any)}
                onChange={uploadChange}
              />
              <p className="mt-5 text-xs text-[#77736b]">
                Supports source files, binaries, certificates, ZIP and TAR
                archives.
              </p>
            </>
          ) : (
            <InputSummary input={input} onRemove={() => void reset()} />
          )}
          <div className="mt-6 border-t border-[#dedbd4] pt-5">
            <p className="text-xs font-semibold uppercase tracking-[.18em] text-[#282927]">
              Or try a demo
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <select
                className="min-w-0 flex-1 rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none"
                value={demoId}
                onChange={(event) => setDemoId(event.target.value)}
                aria-label="Choose a demo file"
              >
                <option value="">Choose a demo file…</option>
                {demos.map((demo) => (
                  <option key={demo.id} value={demo.id}>
                    {demo.name}
                  </option>
                ))}
              </select>
              <Button
                variant="light"
                disabled={
                  !demoId ||
                  demoBusy ||
                  (loadedDemoId !== "" && loadedDemoId === demoId)
                }
                onClick={() => void useDemo()}
              >
                {demoBusy
                  ? "Loading…"
                  : loadedDemoId !== "" && loadedDemoId === demoId
                    ? "Loaded"
                    : "Load demo as input"}
              </Button>
            </div>
            {demoId && (
              <p className="mt-2 text-xs text-[#74716a]">
                {demos.find((d) => d.id === demoId)?.description || ""}
              </p>
            )}
          </div>
        </Card>

        <Card className="flex flex-col p-5 sm:p-7">
          <SectionLabel step="2">Connect GitHub</SectionLabel>
          <div className="flex flex-1 flex-col items-center justify-center text-center">
            <GitFork size={32} />
            <h2 className="mt-4 text-xl font-medium">
              Analyze a GitHub repository
            </h2>
            <p className="mt-2 max-w-sm text-sm leading-6 text-[#74716a]">
              Select a repository through GitHub or analyze a public repository
              URL
            </p>
            {githubProjectStatus !== "idle" ? (
              <GithubProjectStatus
                status={githubProjectStatus}
                progress={githubProgress}
                input={input}
                onRemove={() => void reset()}
              />
            ) : (
              <>
                {!githubSession.authenticated ? (
                  <Button className="mt-6" onClick={signInWithGithub}>
                    <GitFork size={17} /> Sign in with GitHub{" "}
                    <ArrowRight size={16} />
                  </Button>
                ) : (
                  <div className="mt-6 w-full rounded-xl border border-[#d4d0c8] bg-white/45 p-4 text-left">
                    <div className="flex items-center gap-3">
                      <GitFork size={20} />
                      <div className="min-w-0 flex-1">
                        <span className="block text-xs text-[#8b867d]">
                          Connected as
                        </span>
                        <b className="block truncate text-sm">
                          {githubSession.login}
                        </b>
                      </div>
                      <Button
                        variant="ghost"
                        className="px-2"
                        aria-label="Sign out of GitHub"
                        onClick={() => void logoutGithub()}
                      >
                        <LogOut size={16} />
                      </Button>
                    </div>
                    <input
                      className="mt-4 w-full rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none placeholder:text-[#aaa69d]"
                      value={repositorySearch}
                      onChange={(event) =>
                        setRepositorySearch(event.target.value)
                      }
                      placeholder="Search repositories"
                    />
                    <div className="mt-3 flex gap-2">
                      {(["all", "private", "public"] as const).map((filter) => (
                        <button
                          key={filter}
                          className={`rounded-full px-3 py-1.5 text-xs capitalize ${repositoryFilter === filter ? "bg-[#181a19] text-white" : "bg-[#e8e4dc] text-[#68645c]"}`}
                          onClick={() => setRepositoryFilter(filter)}
                        >
                          {filter}
                        </button>
                      ))}
                    </div>
                    <div className="mt-3 max-h-48 space-y-2 overflow-y-auto">
                      {repositoriesLoading ? (
                        <p className="py-4 text-center text-xs text-[#74716a]">
                          Loading repositories…
                        </p>
                      ) : visibleRepositories.length ? (
                        visibleRepositories.map((repository) => (
                          <div
                            className="flex items-center gap-3 rounded-lg border border-[#dedbd4] bg-white/55 px-3 py-2"
                            key={repository.id}
                          >
                            <div className="min-w-0 flex-1">
                              <b className="block truncate text-sm">
                                {repository.full_name}
                              </b>
                              <span className="text-xs text-[#8b867d]">
                                {repository.default_branch}
                                {repository.language
                                  ? ` · ${repository.language}`
                                  : ""}
                              </span>
                            </div>
                            {repository.private && (
                              <span className="rounded-full bg-[#e5e0d5] px-2 py-1 text-[10px] text-[#68645c]">
                                Private
                              </span>
                            )}
                            <Button
                              variant="light"
                              className="px-3 py-1.5 text-xs"
                              onClick={() => void selectRepository(repository)}
                            >
                              Select
                            </Button>
                          </div>
                        ))
                      ) : (
                        <p className="py-4 text-center text-xs text-[#74716a]">
                          No repositories found.
                        </p>
                      )}
                    </div>
                  </div>
                )}
                <div className="mt-7 flex w-full overflow-hidden rounded-xl border border-[#d4d0c8] bg-white/60">
                  <GitFork className="m-3 shrink-0 text-[#6d6a63]" size={17} />
                  <input
                    className="min-w-0 flex-1 bg-transparent py-3 text-sm outline-none placeholder:text-[#aaa69d]"
                    value={githubUrl}
                    onChange={(event) => setGithubUrl(event.target.value)}
                    placeholder="Paste a public GitHub repository URL"
                  />
                  <button
                    className="m-1 grid w-11 place-items-center rounded-lg bg-[#181a19] text-white disabled:opacity-30"
                    aria-label="Analyze public GitHub repository"
                    disabled={!githubUrl.trim()}
                    onClick={() => void connectPublicRepo()}
                  >
                    <ArrowRight size={17} />
                  </button>
                </div>
              </>
            )}
          </div>
        </Card>
      </section>

      <section className="mx-auto grid w-[min(1440px,calc(100%-2rem))] gap-5 rounded-[1.25rem] border border-[#d7d3ca] bg-[#f8f6f1]/75 p-5 shadow-[0_12px_34px_rgba(79,74,65,.05)] lg:grid-cols-[auto_1fr_auto] lg:items-center sm:p-7">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[.2em] text-[#74716a]">
            Analysis configuration
          </p>
          <h2 className="mt-2 text-xl font-medium">Automatic discovery</h2>
        </div>
        <div className="space-y-4">
          <div className="grid gap-4 text-sm text-[#5e5d58] lg:grid-cols-2">
            <div className="rounded-xl border border-[#d4d0c8] bg-white/50 p-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-[#8b867d]">
                Detected locally (automatic)
              </p>
              {input ? (
                <ul className="mt-2 space-y-1">
                  <li>✓ Source code{input.languages.length ? ` (${input.languages.join(", ")})` : ""}</li>
                  <li>✓ Dependencies</li>
                  <li>
                    ✓ {(input.artifact_counts?.binary ?? 0) > 0 ? `${input.artifact_counts?.binary} binaries` : "Binaries (when present)"}
                  </li>
                  <li>
                    ✓ {(input.artifact_counts?.config ?? 0) > 0 ? `${input.artifact_counts?.config} configuration files` : "Configuration (when present)"}
                  </li>
                  <li>
                    ✓ {(input.artifact_counts?.cert ?? 0) > 0 ? `${input.artifact_counts?.cert} certificates/keys` : "Certificates/keys (when present)"}
                  </li>
                  {(input.archives?.length ?? 0) > 0 && (
                    <li>✓ {input.archives?.length} archives (expanded safely)</li>
                  )}
                  {surfaceNames(input.surfaces).length > 0 && (
                    <li className="text-xs text-[#8b867d]">
                      Surfaces: {surfaceNames(input.surfaces).join(", ")}
                    </li>
                  )}
                </ul>
              ) : (
                <p className="mt-2 text-xs text-[#8b867d]">
                  Upload a file, folder, or repository to see detected
                  artifact types. Local analysis needs no manual selection.
                </p>
              )}
            </div>
            <div className="rounded-xl border border-[#d4d0c8] bg-white/50 p-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-[#8b867d]">
                External discovery (opt-in)
              </p>
              <label className="mt-2 flex items-center gap-2">
                <input
                  className="accent-[#181a19]"
                  type="checkbox"
                  checked={allowPull}
                  onChange={() => setAllowPull((v) => !v)}
                />
                Pull/analyze referenced container images
              </label>
              <label className="mt-1 flex items-center gap-2">
                <input
                  className="accent-[#181a19]"
                  type="checkbox"
                  checked={probeRuntime}
                  onChange={() => setProbeRuntime((v) => !v)}
                />
                Probe runtime endpoints
              </label>
              <label className="mt-1 flex items-center gap-2">
                <input
                  className="accent-[#181a19]"
                  type="checkbox"
                  checked={connectCloud}
                  onChange={() => setConnectCloud((v) => !v)}
                />
                Connect cloud infrastructure
                {connectCloud && (
                  <Button
                    variant="ghost"
                    className="ml-2 px-2 py-1 text-xs"
                    onClick={() => setShowCloudConfig(true)}
                  >
                    Configure
                  </Button>
                )}
              </label>
              <label className="mt-1 flex items-center gap-2 text-xs text-[#8b867d]">
                <input
                  className="accent-[#181a19]"
                  type="checkbox"
                  checked={advanced}
                  onChange={() => setAdvanced((v) => !v)}
                />
                Advanced: manual scanner overrides
              </label>
            </div>
          </div>
          {advanced && (
            <div className="grid gap-2 rounded-xl border border-dashed border-[#c6c1b8] p-3 sm:grid-cols-2 xl:grid-cols-4">
              {layers.map(([key, label]) => (
                <label
                  key={key}
                  className="flex items-center gap-2 text-sm text-[#5e5d58]"
                >
                  <input
                    className="accent-[#181a19]"
                    type="checkbox"
                    checked={selected.includes(key)}
                    onChange={() =>
                      setSelected((current) =>
                        current.includes(key)
                          ? current.filter((item) => item !== key)
                          : [...current, key],
                      )
                    }
                  />
                  {label}
                  {["container", "runtime", "cloud"].includes(key) && (
                    <em className="text-[10px] not-italic text-[#a19b90]">
                      opt-in
                    </em>
                  )}
                </label>
              ))}
            </div>
          )}
        </div>
        <Button
          className="w-full lg:w-auto"
          disabled={
            !input || (!!job && !["completed", "failed"].includes(job.status))
          }
          onClick={() => void analyse()}
        >
          <Play size={16} /> Analyze now
        </Button>
      </section>

      {error && (
        <div className="mx-auto mt-4 flex w-[min(1440px,calc(100%-2rem))] items-center gap-3 rounded-xl border border-[#d7b7ae] bg-[#f8e9e2] px-4 py-3 text-sm text-[#762f32]">
          <CircleAlert size={18} />
          {error}
          <button className="ml-auto" onClick={() => setError("")}>
            <X size={15} />
          </button>
        </div>
      )}
      {job && (
        <section className="mx-auto mt-4 w-[min(1440px,calc(100%-2rem))] rounded-2xl border border-[#d7d3ca] bg-[#f8f6f1] p-5">
          <div className="flex justify-between gap-4 text-sm">
            <span>{job.stage}</span>
            <b>{job.progress}%</b>
          </div>
          <div className="mt-3 h-2 overflow-hidden rounded-full bg-[#dedbd4]">
            <i
              className="block h-full rounded-full bg-[#181a19] transition-all"
              style={{ width: `${job.progress}%` }}
            />
          </div>
          <p className="mt-3 text-xs text-[#74716a]">
            {job.status === "failed"
              ? job.error
              : `Planned scanners: ${job.scanners.join(", ")}${(job as any).persisted ? " · stored in scan history" : ""}`}
          </p>
        </section>
      )}

      <section
        id="results"
        className="mx-auto w-[min(1440px,calc(100%-2rem))] py-10 sm:py-14"
      >
        <div className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[.2em] text-[#74716a]">
              Analysis results
            </p>
            <h2 className="mt-2 text-2xl font-medium">
              Explore the analysis across multiple views.
            </h2>
          </div>
        </div>
        {!result ? (
          <div className="mt-6 grid min-h-48 place-items-center rounded-2xl border border-dashed border-[#c6c1b8] text-center text-[#74716a]">
            <div>
              <Sparkles className="mx-auto mb-3" size={27} />
              <h3 className="font-medium text-[#292a28]">
                {job?.status === "running"
                  ? "Analysis is in progress"
                  : "Your results will appear here"}
              </h3>
              <p className="mt-2 max-w-md text-sm">
                Select a project and start analysis. Completed scans persist
                in the local scan history.
              </p>
            </div>
          </div>
        ) : (
          <>
            <div className="mt-7 flex gap-2 overflow-x-auto pb-2">
              {tabs.map((name) => (
                <button
                  key={name}
                  className={`shrink-0 rounded-full px-4 py-2.5 text-sm transition ${tab === name ? "bg-[#181a19] text-white" : "bg-white/45 text-[#5e5d58] hover:bg-white"}`}
                  onClick={() => {
                    setRuleFocus(null);
                    setTab(name);
                  }}
                >
                  {name}
                </button>
              ))}
            </div>
            {tab === "Overview" && (
              <Overview cards={cards} result={result} rel={rel} />
            )}
            {tab === "Findings" && (
              <GroupedFindings
                result={result}
                rel={rel}
                focusRule={ruleFocus}
                onClearFocus={() => setRuleFocus(null)}
                jump={jump}
              />
            )}
            {tab === "Crypto Inventory" && (
              <Inventory
                result={result}
                rel={rel}
                focusRule={ruleFocus}
                onClearFocus={() => setRuleFocus(null)}
                jump={jump}
              />
            )}
            {tab === "Crypto Graph" && (
              <CryptoGraph result={result} rel={rel} jump={jump} />
            )}
            {tab === "Migration" && (
              <Migration
                result={result}
                focusRule={ruleFocus}
                onClearFocus={() => setRuleFocus(null)}
                jump={jump}
              />
            )}
            {tab === "Coverage" && <CoverageView result={result} />}
            <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex flex-wrap gap-2">
                {["pdf", "json", "cir"].map((format) => (
                  <Button
                    key={format}
                    variant={exportFormat === format ? "dark" : "light"}
                    onClick={() => setExportFormat(format)}
                  >
                    {format.toUpperCase()}
                  </Button>
                ))}
              </div>
              <Button
                className="w-full sm:w-auto"
                disabled={!result}
                onClick={() => download(exportFormat)}
              >
                Download report <ArrowRight size={16} />
              </Button>
            </div>
          </>
        )}
      </section>
      <CloudConfigModal
        isOpen={showCloudConfig}
        onClose={() => setShowCloudConfig(false)}
        config={cloudConfig}
        onChange={setCloudConfig}
      />
    </main>
  );
}

function CloudConfigModal({
  isOpen,
  onClose,
  config,
  onChange,
}: {
  isOpen: boolean;
  onClose: () => void;
  config: {
    provider: "aws" | "azure" | "gcp";
    awsProfile: string;
    awsAccessKey: string;
    awsSecretKey: string;
    awsSessionToken: string;
    awsRegion: string;
    services: string;
  };
  onChange: (config: Partial<typeof config>) => void;
}) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" onClick={onClose}>
      <div
        className="w-full max-w-md rounded-[1.25rem] border border-[#d7d3ca] bg-[#f8f6f1] p-5 shadow-[0_24px_48px_rgba(79,74,65,.15)]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium">Cloud Configuration</h3>
          <button
            className="rounded-full p-1 text-[#74716a] hover:bg-[#e8e4dc]"
            onClick={onClose}
            aria-label="Close"
          >
            <X size={20} />
          </button>
        </div>

        <div className="space-y-4 max-h-[60vh] overflow-y-auto">
          <div>
            <label className="block text-xs font-medium text-[#5e5d58] mb-1">
              Cloud Provider
            </label>
            <select
              className="w-full rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none"
              value={config.provider}
              onChange={(e) => onChange({ provider: e.target.value as "aws" | "azure" | "gcp" })}
            >
              <option value="aws">Amazon Web Services (AWS)</option>
              <option value="azure">Microsoft Azure</option>
              <option value="gcp">Google Cloud Platform (GCP)</option>
            </select>
          </div>

          {config.provider === "aws" && (
            <>
              <div>
                <label className="block text-xs font-medium text-[#5e5d58] mb-1">
                  Authentication Method
                </label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2">
                    <input
                      type="radio"
                      name="aws-auth"
                      checked={!!config.awsAccessKey}
                      onChange={() => onChange({ awsProfile: "", awsAccessKey: "temp" })}
                    />
                    <span className="text-sm">Access Key + Secret</span>
                  </label>
                  <label className="flex items-center gap-2">
                    <input
                      type="radio"
                      name="aws-auth"
                      checked={!config.awsAccessKey && !!config.awsProfile}
                      onChange={() => onChange({ awsAccessKey: "", awsSecretKey: "", awsSessionToken: "", awsProfile: "default" })}
                    />
                    <span className="text-sm">AWS Profile</span>
                  </label>
                </div>
              </div>

              {config.awsAccessKey && (
                <>
                  <div>
                    <label className="block text-xs font-medium text-[#5e5d58] mb-1">
                      AWS Access Key ID
                    </label>
                    <input
                      type="text"
                      className="w-full rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none"
                      value={config.awsAccessKey}
                      onChange={(e) => onChange({ awsAccessKey: e.target.value })}
                      placeholder="AKIA..."
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[#5e5d58] mb-1">
                      AWS Secret Access Key
                    </label>
                    <input
                      type="password"
                      className="w-full rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none"
                      value={config.awsSecretKey}
                      onChange={(e) => onChange({ awsSecretKey: e.target.value })}
                      placeholder="Secret key"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[#5e5d58] mb-1">
                      AWS Session Token (optional)
                    </label>
                    <input
                      type="text"
                      className="w-full rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none"
                      value={config.awsSessionToken}
                      onChange={(e) => onChange({ awsSessionToken: e.target.value })}
                      placeholder="Session token (for temporary credentials)"
                    />
                  </div>
                </>
              )}

              {!config.awsAccessKey && (
                <div>
                  <label className="block text-xs font-medium text-[#5e5d58] mb-1">
                    AWS Profile Name
                  </label>
                  <input
                    type="text"
                    className="w-full rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none"
                    value={config.awsProfile}
                    onChange={(e) => onChange({ awsProfile: e.target.value })}
                    placeholder="default"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-[#5e5d58] mb-1">
                  AWS Region
                </label>
                <input
                  type="text"
                  className="w-full rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none"
                  value={config.awsRegion}
                  onChange={(e) => onChange({ awsRegion: e.target.value })}
                  placeholder="us-east-1"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#5e5d58] mb-1">
                  Services to Scan (comma-separated)
                </label>
                <input
                  type="text"
                  className="w-full rounded-lg border border-[#d4d0c8] bg-white/70 px-3 py-2.5 text-sm outline-none"
                  value={config.services}
                  onChange={(e) => onChange({ services: e.target.value })}
                  placeholder="kms,acm,elb,alb"
                />
                <p className="mt-1 text-xs text-[#8b867d]">
                  Supported: kms (Key Management), acm (Certificate Manager), elb (Classic Load Balancer), alb (Application Load Balancer)
                </p>
              </div>
            </>
          )}

          {config.provider === "azure" && (
            <div className="text-center py-8 text-[#74716a]">
              <p>Azure support coming soon</p>
            </div>
          )}

          {config.provider === "gcp" && (
            <div className="text-center py-8 text-[#74716a]">
              <p>GCP support coming soon</p>
            </div>
          )}

          <div className="pt-4 border-t border-[#dedbd4] flex items-center justify-end gap-2">
            <Button variant="light" onClick={onClose}>
              Cancel
            </Button>
            <Button onClick={onClose}>
              Save
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function InputSummary({
  input,
  onRemove,
}: {
  input: InputInfo;
  onRemove: () => void;
}) {
  return (
    <div>
      <div className="flex items-start gap-3">
        <FolderOpen size={28} />
        <div className="min-w-0 flex-1">
          <strong className="block truncate">{input.name}</strong>
          <span className="text-sm text-[#74716a]">
            {input.file_count} files · {bytes(input.total_bytes)}
          </span>
        </div>
        <button aria-label="Remove selected input" onClick={onRemove}>
          <Trash2 size={17} />
        </button>
      </div>
    </div>
  );
}

function GithubProjectStatus({
  status,
  progress,
  input,
  onRemove,
}: {
  status: GithubProjectStatus;
  progress: number;
  input: InputInfo | null;
  onRemove: () => void;
}) {
  if (status === "loading") {
    return (
      <div className="mt-7 w-full rounded-xl border border-[#d4d0c8] bg-white/55 p-5 text-left">
        <div className="flex items-center justify-between gap-4 text-sm">
          <span>Downloading project and reading metadata…</span>
          <b>{progress}%</b>
        </div>
        <div className="mt-4 h-2 overflow-hidden rounded-full bg-[#dedbd4]">
          <div
            className="h-full rounded-full bg-[#181a19] transition-all duration-500"
            style={{ width: `${Math.max(progress, 8)}%` }}
          />
        </div>
        <p className="mt-3 text-xs text-[#74716a]">
          Fetching repository contents. Analysis has not started yet.
        </p>
      </div>
    );
  }

  return (
    <div className="mt-7 w-full rounded-xl border border-[#c8d2c4] bg-[#eef2eb] p-5 text-left">
      <div className="flex items-start gap-3">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-[#d6e2d1] text-[#3f6340]">
          <Check size={18} />
        </div>
        <div className="min-w-0 flex-1">
          <b className="block text-sm">Project uploaded</b>
          <span className="mt-1 block truncate text-xs text-[#657064]">
            {input?.name || "GitHub repository"}
          </span>
        </div>
        <Button
          variant="ghost"
          className="px-2"
          aria-label="Delete selected project"
          onClick={onRemove}
        >
          <Trash2 size={16} />
        </Button>
      </div>
      {input && (
        <div className="mt-4 grid grid-cols-2 gap-3 border-t border-[#c8d2c4] pt-4 text-xs text-[#657064]">
          <span>
            <b className="block text-[#303c31]">Files</b>
            {input.file_count}
          </span>
          <span>
            <b className="block text-[#303c31]">Size</b>
            {bytes(input.total_bytes)}
          </span>
        </div>
      )}
    </div>
  );
}

function Overview({
  cards,
  result,
  rel,
}: {
  cards: any[];
  result: Result;
  rel: (path: string) => string;
}) {
  const risk = result.analytics.risk;
  const rep = result.report || {};
  const by = rep.by_severity || {};
  const rawScore = Number(risk?.score ?? 0);
  // Risk score is 0..10 on the wire (legacy values may exceed 10);
  // normalize to 0..1 for the progress ring.
  const fraction = Number.isFinite(rawScore)
    ? Math.min(1, Math.max(0, rawScore <= 10 ? rawScore / 10 : rawScore / 100))
    : 0;
  const percent = Math.round(fraction * 100);
  const ringColor: Record<string, string> = {
    critical: "#b8424d",
    high: "#a96f52",
    medium: "#d78b3e",
    low: "#b88945",
    info: "#6586a4",
  };
  const ring =
    ringColor[String(risk?.level || "info").toLowerCase()] || ringColor.info;
  const R = 60;
  const CIRC = 2 * Math.PI * R;
  return (
    <div className="mt-5 space-y-4">
      <div className="grid gap-4 xl:grid-cols-[1.2fr_.8fr_1fr]">
      <Card className="p-5">
        <h3 className="text-xs uppercase tracking-[.18em]">Overview</h3>
        <div className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
          {cards.map(([label, value, Icon]) => (
            <div key={label}>
              <Icon size={19} />
              <b className="mt-2 block text-xl">{value}</b>
              <span className="text-xs text-[#74716a]">{label}</span>
            </div>
          ))}
        </div>
        <div className="mt-5 border-t border-[#dedbd4] pt-4">
          <h4 className="text-xs uppercase tracking-[.18em] text-[#8b867d]">
            Summary
          </h4>
          <p className="mt-2 text-sm leading-6 text-[#5e5d58]">
            {rep.summary || "No summary available for this scan."}
          </p>
        </div>
      </Card>
      <Card className="p-5">
        <h3 className="text-xs uppercase tracking-[.18em]">Risk summary</h3>
        <div className="relative mx-auto mt-5 h-36 w-36">
          <svg viewBox="0 0 144 144" className="h-full w-full -rotate-90">
            <circle
              cx="72"
              cy="72"
              r={R}
              fill="none"
              stroke="#e3e0d8"
              strokeWidth="14"
            />
            <circle
              cx="72"
              cy="72"
              r={R}
              fill="none"
              stroke={ring}
              strokeWidth="14"
              strokeLinecap="round"
              strokeDasharray={CIRC}
              strokeDashoffset={CIRC * (1 - fraction)}
              style={{ transition: "stroke-dashoffset 0.6s ease" }}
            />
          </svg>
          <div className="absolute inset-0 grid place-items-center text-center">
            <div>
              <b
                className={`block text-2xl ${riskAccent(risk.level).split(" ")[1]}`}
              >
                {percent}%
              </b>
              <span className="text-xs capitalize text-[#74716a]">
                {risk.level}
              </span>
            </div>
          </div>
        </div>
        <div className="mt-5 space-y-2">
          {["critical", "high", "medium", "low", "info"].map((level) => (
            <div className="flex items-center gap-2 text-sm" key={level}>
              <i className={`h-2.5 w-2.5 rounded-full ${dotTone(level)}`} />
              <span className="capitalize text-[#74716a]">{level}</span>
              <b className="ml-auto">{by[level] || 0}</b>
            </div>
          ))}
        </div>
      </Card>
      <Card className="p-5">
        <h3 className="text-xs uppercase tracking-[.18em]">Top issues</h3>
        <div className="mt-5 space-y-4">
          {(rep.top_issues || []).slice(0, 5).map((issue: any, index: number) => (
            <div
              className="flex items-center gap-3 text-sm"
              key={`${issue.rule_id}-${index}`}
            >
              <i
                className={`h-2.5 w-2.5 shrink-0 rounded-full ${dotTone(issue.severity)}`}
              />
              <span className="min-w-0 flex-1 truncate" title={issue.title}>
                {issue.title} · {issue.count} occurrence
                {issue.count === 1 ? "" : "s"}
              </span>
              <b className="text-xs capitalize text-[#74716a]">
                {issue.severity}
              </b>
            </div>
          ))}
          {!(rep.top_issues || []).length &&
            result.findings.slice(0, 5).map((finding: any, index: number) => (
              <div
                className="flex items-center gap-3 text-sm"
                key={`${finding.rule_id}-${index}`}
              >
                <i
                  className={`h-2.5 w-2.5 shrink-0 rounded-full ${dotTone(finding.severity)}`}
                />
                <span className="min-w-0 flex-1 truncate">{finding.title}</span>
                <b className="text-xs capitalize text-[#74716a]">
                  {finding.severity}
                </b>
              </div>
            ))}
          {!(rep.top_issues || []).length && !result.findings.length && (
            <p className="text-sm text-[#74716a]">No findings.</p>
          )}
        </div>
        {(rep.migration_counts ||
          (rep.recommendations || []).length > 0) && (
          <div className="mt-5 border-t border-[#dedbd4] pt-4 text-sm text-[#74716a]">
            Migration:{" "}
            {rep.migration_counts
              ? `${rep.migration_counts.Immediate ?? 0} immediate · ${rep.migration_counts["High priority"] ?? 0} high priority · ${rep.migration_counts.Planned ?? 0} planned`
              : `${(rep.recommendations || []).length} action(s)`}
          </div>
        )}
      </Card>
      </div>
    </div>
  );
}

function GroupedFindings({
  result,
  rel,
  focusRule,
  onClearFocus,
  jump,
}: {
  result: Result;
  rel: (path: string) => string;
  focusRule?: string | null;
  onClearFocus?: () => void;
  jump?: (tab: string, rule: string | null) => void;
}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [view, setView] = useState<"findings" | "files" | "areas">("findings");
  const groups: any[] = result.report?.finding_groups || [];
  // Exact finding -> P1 risk record join via CIR operation id.
  const riskByOp: Record<string, any> = {};
  for (const r of result.risks || []) {
    if (r && r.operation_id) riskByOp[String(r.operation_id)] = r;
  }
  // Finding group -> migration action join via shared rule_id.
  const migrationByRule: Record<string, any> = {};
  const allActions: any[] = result.report?.migration_actions ||
    result.report?.recommendations ||
    [];
  for (const a of allActions) {
    if (a && a.rule_id && !migrationByRule[a.rule_id]) migrationByRule[a.rule_id] = a;
  }
  for (const gname of Object.keys(result.report?.migration_groups || {})) {
    for (const a of result.report.migration_groups[gname] || []) {
      if (a && a.rule_id && !migrationByRule[a.rule_id]) migrationByRule[a.rule_id] = a;
    }
  }
  const visibleGroups = groups.filter((group: any) => {
    if (focusRule && group.rule_id !== focusRule) return false;
    if (severity !== "all" && group.severity !== severity) return false;
    if (!query.trim()) return true;
    const haystack =
      `${group.rule_id} ${group.title} ${group.severity} ${group.occurrences.map((o: any) => o.file).join(" ")}`.toLowerCase();
    return haystack.includes(query.toLowerCase());
  });
  const fallback = !groups.length
    ? result.findings.filter((finding: any) => {
        if (focusRule && finding.rule_id !== focusRule) return false;
        if (severity !== "all" && finding.severity !== severity) return false;
        if (!query.trim()) return true;
        return `${finding.rule_id} ${finding.title} ${finding.file}`.toLowerCase().includes(query.toLowerCase());
      })
    : [];
  return (
    <Card className="mt-5 p-5">
      {focusRule && (
        <div className="mb-3 flex items-center gap-3 rounded-xl border border-[#d4d0c8] bg-white/60 px-4 py-2.5 text-sm">
          <span className="min-w-0 flex-1 truncate">
            Focused on rule <b>{focusRule}</b>
          </span>
          <button
            className="shrink-0 rounded-full bg-[#e8e4dc] px-3 py-1 text-xs text-[#5e5d58] hover:bg-[#dedbd4]"
            onClick={() => onClearFocus && onClearFocus()}
          >
            Clear
          </button>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex min-w-52 flex-1 items-center gap-2 rounded-full border border-[#d4d0c8] bg-white/60 px-3 py-2">
          <Search size={15} />
          <input
            className="w-full bg-transparent text-sm outline-none placeholder:text-[#aaa69d]"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search findings, rules, files…"
          />
        </div>
        <div className="flex gap-1">
          {["all", "critical", "high", "medium", "low", "info"].map((level) => (
            <button
              key={level}
              className={`rounded-full px-3 py-1.5 text-xs capitalize ${severity === level ? "bg-[#181a19] text-white" : "bg-[#e8e4dc] text-[#68645c]"}`}
              onClick={() => setSeverity(level)}
            >
              {level}
            </button>
          ))}
        </div>
      </div>
      <div className="mt-3 flex gap-1">
        {(["findings", "files", "areas"] as const).map((v) => (
          <button
            key={v}
            className={`rounded-full px-3 py-1.5 text-xs capitalize ${view === v ? "bg-[#181a19] text-white" : "bg-[#e8e4dc] text-[#68645c]"}`}
            onClick={() => setView(v)}
          >
            {v === "areas" ? "Affected areas" : v}
          </button>
        ))}
      </div>
      <div className="mt-4 space-y-3">
        {view === "areas" ? (
          <AffectedAreas result={result} />
        ) : view === "files" ? (
          <FilesView
            groups={visibleGroups}
            query={query}
            fallback={fallback}
            rel={rel}
          />
        ) : visibleGroups.length ? (
          visibleGroups.map((group: any) => (
            <FindingCard
              key={`${group.rule_id}-${group.severity}`}
              group={group}
              rel={rel}
              riskByOp={riskByOp}
              methodology={result.report?.methodology}
              migration={migrationByRule[group.rule_id]}
              jump={jump}
            />
          ))
        ) : fallback.length ? (
          fallback.slice(0, 50).map((finding: any, index: number) => (
            <div
              key={index}
              className="flex items-center gap-3 rounded-xl border border-[#dedbd4] bg-white/45 p-4 text-sm"
            >
              <i
                className={`h-2.5 w-2.5 shrink-0 rounded-full ${dotTone(finding.severity)}`}
              />
              <div className="min-w-0 flex-1">
                <b className="block truncate">{finding.title}</b>
                <span className="text-xs text-[#74716a]">
                  {finding.rule_id} · {rel(finding.file)}:{finding.line}
                </span>
              </div>
              <b className="text-xs capitalize text-[#74716a]">
                {finding.severity}
              </b>
            </div>
          ))
        ) : (
          <Empty label="No findings match this filter." />
        )}
      </div>
    </Card>
  );
}
function Occurrence({
  occ,
  rel,
  riskByOp,
  methodology,
}: {
  occ: any;
  rel: (path: string) => string;
  riskByOp: Record<string, any>;
  methodology?: any;
}) {
  const risk = occ.op_id ? riskByOp[occ.op_id] : undefined;
  const conf =
    typeof occ.confidence === "number"
      ? `${Math.round(occ.confidence * 100)}%`
      : null;
  const assumptions = String(risk?.rationale || "")
    .split(";")
    .map((s: string) => s.trim())
    .filter(Boolean);
  return (
    <div className="text-sm">
      <code className="text-xs">
        {rel(occ.file)}:{occ.line}
      </code>
      <div className="mt-1 flex flex-wrap gap-2 text-xs text-[#74716a]">
        <span>
          Risk: <b className="capitalize text-[#292a28]">{occ.severity}</b>
        </span>
        {conf && <span>Confidence: {conf}</span>}
        {occ.usage_state && <span>Usage: {occ.usage_state}</span>}
        {occ.algorithm && <span>Algorithm: {occ.algorithm}</span>}
      </div>
      {occ.snippet && (
        <pre className="mt-1 overflow-x-auto rounded-lg bg-[#ece9e2] p-2 text-xs">
          {occ.snippet.slice(0, 300)}
        </pre>
      )}
      {risk && (
        <details className="mt-2 rounded-lg border border-[#e4e0d8] bg-white/60 px-3 py-2">
          <summary className="cursor-pointer text-xs font-medium">
            Why this risk?
          </summary>
          <div className="mt-2 space-y-1 text-xs text-[#5e5d58]">
            <p>
              Risk <b className="capitalize">{risk.class}</b> · Score{" "}
              {risk.score} / 10
              {typeof risk.confidence === "number" &&
                ` · Confidence ${Math.round(risk.confidence * 100)}%`}
            </p>
            {assumptions.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-5">
                {assumptions.slice(0, 8).map((a: string, i: number) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            )}
            <details className="pt-1">
              <summary className="cursor-pointer font-medium">
                Show scoring methodology
              </summary>
              <p className="mt-1 break-words">
                {risk.description || "No engine record available."}
              </p>
              {methodology?.risk_model && (
                <p className="mt-1 break-words text-[#8b867d]">
                  {methodology.risk_model}
                </p>
              )}
            </details>
          </div>
        </details>
      )}
    </div>
  );
}

function FindingCard({
  group,
  rel,
  riskByOp,
  methodology,
  migration,
  jump,
}: {
  group: any;
  rel: (path: string) => string;
  riskByOp: Record<string, any>;
  methodology?: any;
  migration?: any;
  jump?: (tab: string, rule: string | null) => void;
}) {
  return (
    <details className="rounded-xl border border-[#dedbd4] bg-white/45 p-4">
      <summary className="cursor-pointer text-sm">
        <span
          className={`mr-2 inline-flex rounded-full px-2.5 py-0.5 text-xs capitalize text-white ${tone(group.severity).split(" ")[0]}`}
        >
          {group.severity}
        </span>
        <b>{group.title}</b>
        <span className="text-[#74716a]">
          {" "}
          · {group.count} occurrence{group.count === 1 ? "" : "s"} across{" "}
          {group.file_count} file{group.file_count === 1 ? "" : "s"}
        </span>
      </summary>
      <div className="mt-3 space-y-3 border-t border-[#e4e0d8] pt-3">
        {group.occurrences.slice(0, 25).map((occ: any, index: number) => (
          <Occurrence
            key={index}
            occ={occ}
            rel={rel}
            riskByOp={riskByOp}
            methodology={methodology}
          />
        ))}
        {group.count > 25 && (
          <p className="text-xs text-[#74716a]">
            … and {group.count - 25} more occurrence(s).
          </p>
        )}
      </div>
      {(migration?.why_text || migration) && (
        <div className="mt-3 rounded-lg bg-white/60 p-3 text-sm">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#8b867d]">
            Why this matters
          </p>
          <p className="mt-1 leading-6 text-[#5e5d58]">
            {migration.why_text || migration.action}
          </p>
          {jump && (
            <button
              className="mt-2 rounded-full bg-[#181a19] px-3 py-1.5 text-xs text-white hover:bg-[#30312f]"
              onClick={() => jump("Migration", group.rule_id)}
            >
              View migration action
            </button>
          )}
        </div>
      )}
    </details>
  );
}

function FilesView({
  groups,
  query,
  fallback,
  rel,
}: {
  groups: any[];
  query: string;
  fallback: any[];
  rel: (path: string) => string;
}) {
  const rank: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  const byFile: Record<
    string,
    { file: string; count: number; rules: string[]; worst: string }
  > = {};
  for (const g of groups) {
    for (const o of g.occurrences || []) {
      const slot = (byFile[o.file] ||= {
        file: o.file,
        count: 0,
        rules: [],
        worst: "info",
      });
      slot.count += 1;
      if (!slot.rules.includes(g.rule_id)) slot.rules.push(g.rule_id);
      if ((rank[o.severity] ?? 9) < (rank[slot.worst] ?? 9)) {
        slot.worst = o.severity;
      }
    }
  }
  const rows = Object.values(byFile)
    .filter(
      (r) =>
        !query.trim() ||
        `${r.file} ${r.rules.join(" ")}`.toLowerCase().includes(query.toLowerCase()),
    )
    .sort((a, b) => b.count - a.count || a.file.localeCompare(b.file));
  if (!rows.length && !fallback.length) {
    return <Empty label="No findings match this filter." />;
  }
  if (!rows.length) {
    return <Empty label="No files match this filter." />;
  }
  return (
    <div className="space-y-2">
      {rows.slice(0, 100).map((r) => (
        <div
          key={r.file}
          className="flex items-center gap-3 rounded-xl border border-[#dedbd4] bg-white/45 p-4 text-sm"
        >
          <i className={`h-2.5 w-2.5 shrink-0 rounded-full ${dotTone(r.worst)}`} />
          <div className="min-w-0 flex-1">
            <code className="block truncate text-xs">{rel(r.file)}</code>
            <span className="text-xs text-[#74716a]">
              {r.count} occurrence{r.count === 1 ? "" : "s"} ·{" "}
              {r.rules.join(", ")}
            </span>
          </div>
          <b className="shrink-0 text-xs capitalize text-[#74716a]">
            {r.worst}
          </b>
        </div>
      ))}
      {rows.length > 100 && (
        <p className="text-xs text-[#74716a]">
          … and {rows.length - 100} more files.
        </p>
      )}
    </div>
  );
}

function AffectedAreas({ result }: { result: Result }) {
  const items: any[] = result.report?.components || [];
  const fallback: any[] = !items.length ? result.report?.top_files || [] : [];
  return (
    <div>
      <h3 className="text-xs uppercase tracking-[.18em]">Affected areas</h3>
      {items.length ? (
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          {items.map((comp: any) => (
            <div
              key={comp.module}
              className="rounded-xl border border-[#dedbd4] bg-white/45 p-4"
            >
              <div className="flex items-center gap-2">
                <i
                  className={`h-2.5 w-2.5 rounded-full ${dotTone(comp.highest_severity)}`}
                />
                <b className="truncate text-sm">{comp.module}</b>
                <span className="ml-auto text-xs text-[#74716a]">
                  {comp.findings} finding{comp.findings === 1 ? "" : "s"} ·{" "}
                  {comp.file_count} file{comp.file_count === 1 ? "" : "s"}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {Object.entries(comp.by_severity || {}).map(([level, count]) => (
                  <span
                    key={level}
                    className={`rounded-full px-2 py-0.5 text-[11px] capitalize ${tone(String(level))}`}
                  >
                    {level}: {String(count)}
                  </span>
                ))}
              </div>
              {(comp.algorithms || []).length > 0 && (
                <p className="mt-2 text-xs text-[#74716a]">
                  {(comp.algorithms || []).join(", ")}
                </p>
              )}
            </div>
          ))}
        </div>
      ) : fallback.length ? (
        <div className="mt-4 space-y-2">
          {fallback.map((row: any) => (
            <div key={row.file} className="flex gap-3 text-sm">
              <span className="min-w-0 flex-1 truncate">{row.file}</span>
              <b>{row.count}</b>
            </div>
          ))}
        </div>
      ) : (
        <Empty label="No affected components were returned." />
      )}
    </div>
  );
}
function Inventory({
  result,
  rel,
  focusRule,
  onClearFocus,
  jump,
}: {
  result: Result;
  rel: (path: string) => string;
  focusRule?: string | null;
  onClearFocus?: () => void;
  jump?: (tab: string, rule: string | null) => void;
}) {
  const [query, setQuery] = useState("");
  const [section, setSection] = useState<"algorithms" | "operations" | "libraries">(
    "algorithms",
  );
  const rows: any[] = result.report?.inventory || [];
  // Algorithm -> best migration rule: prefer the rule of the finding
  // group with the most occurrences for that algorithm.
  const ruleForAlgorithm: Record<string, string> = {};
  const ruleHits: Record<string, Record<string, number>> = {};
  for (const g of result.report?.finding_groups || []) {
    for (const o of g.occurrences || []) {
      if (!o.algorithm) continue;
      const per = (ruleHits[o.algorithm] ||= {});
      per[g.rule_id] = (per[g.rule_id] || 0) + 1;
    }
  }
  for (const [algo, per] of Object.entries(ruleHits)) {
    ruleForAlgorithm[algo] = Object.entries(per).sort((a, b) => b[1] - a[1])[0][0];
  }
  const migrationByRule: Record<string, any> = {};
  for (const a of result.report?.migration_actions ||
    result.report?.recommendations ||
    []) {
    if (a && a.rule_id && !migrationByRule[a.rule_id]) migrationByRule[a.rule_id] = a;
  }
  const actionStatus = (row: any): { label: string; rule: string | null } => {
    const rule =
      ruleForAlgorithm[row.algorithm] ||
      (result.report?.finding_groups || []).find((g: any) =>
        (g.occurrences || []).some((o: any) => o.algorithm === row.algorithm),
      )?.rule_id ||
      null;
    const action = rule ? migrationByRule[rule] : undefined;
    if (!action) return { label: "No action", rule };
    const sev = String(action.severity || "").toLowerCase();
    if (sev === "critical" || sev === "high") return { label: "Migration required", rule };
    if (sev === "medium") return { label: "Planned", rule };
    return { label: "Review", rule };
  };
  const filtered = rows.filter((row: any) => {
    if (focusRule) {
      const rule = ruleForAlgorithm[row.algorithm];
      if (rule !== focusRule) {
        const linked = (result.report?.finding_groups || []).some(
          (g: any) => g.rule_id === focusRule &&
            (g.occurrences || []).some((o: any) => o.algorithm === row.algorithm),
        );
        if (!linked) return false;
      }
    }
    if (!query.trim()) return true;
    return `${row.algorithm} ${row.type} ${row.risk}`.toLowerCase().includes(query.toLowerCase());
  });
  const fallbackAssets: any[] = !rows.length ? result.assets || [] : [];
  if (fallbackAssets.length) {
    return (
      <DataTable
        title="Crypto assets"
        items={fallbackAssets}
        columns={[
          "canonical",
          "usage_state",
          "confidence",
          "library",
          "key_size",
          "mode",
        ]}
      />
    );
  }
  return (
    <Card className="mt-5 overflow-hidden">
      <div className="flex flex-col gap-3 border-b border-[#dedbd4] p-5 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <h3 className="font-medium">Cryptographic inventory</h3>
        <div className="flex w-full items-center gap-2 rounded-full border border-[#d4d0c8] bg-white/60 px-3 py-1.5 sm:w-auto sm:min-w-52">
          <Search size={15} />
          <input
            className="w-full bg-transparent text-sm outline-none placeholder:text-[#aaa69d]"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter…"
          />
        </div>
      </div>
      <div className="flex flex-wrap gap-2 px-5 pb-5 pt-5 sm:px-6">
        {(
          [
            ["algorithms", "Algorithms"],
            ["operations", "Operations"],
            ["libraries", "Libraries & Config"],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            className={`whitespace-nowrap rounded-full px-4 py-2 text-sm transition ${section === key ? "bg-[#181a19] text-white" : "bg-[#e8e4dc] text-[#68645c] hover:bg-[#dedbd4]"}`}
            onClick={() => setSection(key)}
          >
            {label}
          </button>
        ))}
      </div>
      {focusRule && (
        <div className="mx-5 mb-5 mt-0 flex items-center gap-3 rounded-xl border border-[#d4d0c8] bg-white/60 px-4 py-2 text-sm sm:mx-6">
          <span className="min-w-0 flex-1 truncate">
            Focused on rule <b>{focusRule}</b>
          </span>
          <button
            className="shrink-0 rounded-full bg-[#e8e4dc] px-3 py-1 text-xs text-[#5e5d58] hover:bg-[#dedbd4]"
            onClick={() => onClearFocus && onClearFocus()}
          >
            Clear
          </button>
        </div>
      )}
      {section === "algorithms" && (
        <AlgorithmsTable
          rows={filtered}
          actionStatus={actionStatus}
          jump={jump}
        />
      )}
      {section === "operations" && (
        <OperationsTable result={result} rel={rel} query={query} focusRule={focusRule} />
      )}
      {section === "libraries" && (
        <LibrariesConfig result={result} rel={rel} query={query} />
      )}
    </Card>
  );
}

function AlgorithmsTable({
  rows,
  actionStatus,
  jump,
}: {
  rows: any[];
  actionStatus: (row: any) => { label: string; rule: string | null };
  jump?: (tab: string, rule: string | null) => void;
}) {
  if (!rows.length) {
    return <Empty label="No cryptographic inventory was returned." />;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead className="bg-[#ece9e2] text-xs uppercase tracking-wider text-[#74716a]">
          <tr>
            <th className="px-5 py-3 font-medium">Algorithm</th>
            <th className="px-5 py-3 font-medium">Type</th>
            <th className="px-5 py-3 font-medium">Uses</th>
            <th className="px-5 py-3 font-medium">Files</th>
            <th className="px-5 py-3 font-medium">Risk</th>
            <th className="px-5 py-3 font-medium">Action</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 100).map((row: any) => {
            const status = actionStatus(row);
            return (
              <tr className="border-t border-[#e4e0d8]" key={row.algorithm}>
                <td className="px-5 py-3 font-medium">{row.algorithm}</td>
                <td className="px-5 py-3">{row.type}</td>
                <td className="px-5 py-3">{row.uses}</td>
                <td className="px-5 py-3" title={(row.files || []).map((f: any) => f.file).join(", ")}>
                  {row.file_count}
                </td>
                <td className="px-5 py-3">
                  <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs ${tone(row.risk.toLowerCase())}`}>
                    {row.risk}
                  </span>
                </td>
                <td className="px-5 py-3 text-xs">
                  {status.rule && jump ? (
                    <button
                      className="rounded-full bg-[#e8e4dc] px-2.5 py-1 text-[#292a28] hover:bg-[#dedbd4]"
                      onClick={() => jump("Migration", status.rule)}
                      title={`Open migration for ${status.rule}`}
                    >
                      {status.label}
                    </button>
                  ) : (
                    <span className="text-[#74716a]">{status.label}</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {rows.length > 100 && (
        <p className="px-5 py-3 text-xs text-[#74716a]">
          … and {rows.length - 100} more algorithms (see exports).
        </p>
      )}
    </div>
  );
}

function humanizeOperation(value: string) {
  return String(value || "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function OperationsTable({
  result,
  rel,
  query,
  focusRule,
}: {
  result: Result;
  rel: (path: string) => string;
  query: string;
  focusRule?: string | null;
}) {
  const assetsById: Record<string, any> = {};
  for (const a of result.assets || []) {
    if (a && a.asset_id) assetsById[String(a.asset_id)] = a;
  }
  const riskByOp: Record<string, any> = {};
  for (const r of result.risks || []) {
    if (r && r.operation_id) riskByOp[String(r.operation_id)] = r;
  }
  const opRule: Record<string, string> = {};
  for (const g of result.report?.finding_groups || []) {
    for (const o of g.occurrences || []) {
      if (o.op_id && !opRule[o.op_id]) opRule[o.op_id] = g.rule_id;
    }
  }
  let rows = (result.operations || []).map((op: any) => {
    const asset = assetsById[String(op?.asset_id)] || {};
    const risk = riskByOp[String(op?.operation_id)];
    const cls = String(risk?.class || "Informational");
    const sev = { Critical: "critical", High: "high", Medium: "medium", Low: "low" }[cls] || "info";
    return {
      id: String(op?.operation_id || ""),
      operation: humanizeOperation(op?.operation_type) || "—",
      algorithm: asset.canonical || "UNKNOWN",
      file: op?.location?.file ? rel(op.location.file) : "—",
      line: op?.location?.line ?? "—",
      confidence:
        typeof op?.confidence === "number"
          ? `${Math.round(op.confidence * 100)}%`
          : "—",
      usage: op?.risk_inputs?.usage_state || asset.usage_state || "—",
      severity: sev,
      evidence: Array.isArray(op?.evidence) ? op.evidence.length : 0,
    };
  });
  if (focusRule) {
    rows = rows.filter((r: any) => opRule[r.id] === focusRule);
  }
  if (query.trim()) {
    const q = query.toLowerCase();
    rows = rows.filter((r: any) =>
      `${r.operation} ${r.algorithm} ${r.file}`.toLowerCase().includes(q),
    );
  }
  rows.sort((a: any, b: any) => a.file.localeCompare(b.file));
  if (!rows.length) {
    return <Empty label="No cryptographic operations were returned." />;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead className="bg-[#ece9e2] text-xs uppercase tracking-wider text-[#74716a]">
          <tr>
            <th className="px-5 py-3 font-medium">Operation</th>
            <th className="px-5 py-3 font-medium">Algorithm</th>
            <th className="px-5 py-3 font-medium">File</th>
            <th className="px-5 py-3 font-medium">Confidence</th>
            <th className="px-5 py-3 font-medium">Risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, 200).map((r: any) => (
            <tr
              className="border-t border-[#e4e0d8]"
              key={r.id}
              title={`Operation ${r.id} · usage ${r.usage} · evidence signals ${r.evidence}`}
            >
              <td className="px-5 py-3 capitalize">{r.operation}</td>
              <td className="px-5 py-3 font-medium">{r.algorithm}</td>
              <td className="max-w-xs truncate px-5 py-3 text-xs" title={`${r.file}:${r.line}`}>
                {r.file}
              </td>
              <td className="px-5 py-3">{r.confidence}</td>
              <td className="px-5 py-3">
                <span className={`inline-flex rounded-full px-2.5 py-0.5 text-xs ${tone(r.severity)}`}>
                  {r.severity}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 200 && (
        <p className="px-5 py-3 text-xs text-[#74716a]">
          … and {rows.length - 200} more operations (see exports).
        </p>
      )}
    </div>
  );
}
function LibrariesConfig({
  result,
  rel,
  query,
}: {
  result: Result;
  rel: (path: string) => string;
  query: string;
}) {
  // Libraries from recorded asset implementations (never invented).
  const libs: Record<
    string,
    { name: string; assets: number; confirmed: number; files: string[] }
  > = {};
  for (const a of result.assets || []) {
    const name = String(a?.implementation?.library || a?.library || "").trim();
    if (!name) continue;
    const slot = (libs[name] ||= { name, assets: 0, confirmed: 0, files: [] });
    slot.assets += 1;
    const usage = String(a?.usage_state || "");
    if (usage === "Confirmed" || usage === "Probable") slot.confirmed += 1;
    const file = a?.location?.file ? rel(a.location.file) : "";
    if (file && !slot.files.includes(file)) slot.files.push(file);
  }
  // Protocols from inventory rows typed as protocol/certificate.
  const protocols = (result.report?.inventory || []).filter((r: any) =>
    ["Protocol", "Certificate"].includes(String(r?.type || "")),
  );
  // Configuration files actually observed with findings.
  const configExt = [".yaml", ".yml", ".json", ".conf", ".cnf", ".toml", ".ini", ".env", ".xml"];
  const configFiles: Record<string, { file: string; count: number; rules: string[] }> = {};
  for (const g of result.report?.finding_groups || []) {
    for (const o of g.occurrences || []) {
      const file = String(o.file || "");
      const lower = file.toLowerCase();
      if (!configExt.some((ext) => lower.endsWith(ext))) continue;
      const slot = (configFiles[file] ||= { file, count: 0, rules: [] });
      slot.count += 1;
      if (!slot.rules.includes(g.rule_id)) slot.rules.push(g.rule_id);
    }
  }
  const q = query.trim().toLowerCase();
  const libRows = Object.values(libs)
    .filter((l) => !q || l.name.toLowerCase().includes(q))
    .sort((a, b) => b.assets - a.assets || a.name.localeCompare(b.name));
  const statusOf = (l: { assets: number; confirmed: number }) =>
    l.confirmed === l.assets && l.assets > 0
      ? "Confirmed use"
      : l.confirmed > 0
        ? "Partially confirmed"
        : "Provided capability";
  return (
    <div className="space-y-5 p-5">
      <div>
        <h4 className="text-xs uppercase tracking-[.18em] text-[#5e5d58]">
          Libraries / Dependencies
        </h4>
        {libRows.length ? (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead className="bg-[#ece9e2] text-xs uppercase tracking-wider text-[#74716a]">
                <tr>
                  <th className="px-4 py-2 font-medium">Library</th>
                  <th className="px-4 py-2 font-medium">Assets</th>
                  <th className="px-4 py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {libRows.slice(0, 50).map((l) => (
                  <tr className="border-t border-[#e4e0d8]" key={l.name}>
                    <td className="px-4 py-2 font-medium">{l.name}</td>
                    <td className="px-4 py-2">{l.assets}</td>
                    <td className="px-4 py-2 text-xs text-[#74716a]">
                      {statusOf(l)}
                      {l.confirmed > 0 && l.confirmed < l.assets
                        ? ` (${l.confirmed}/${l.assets} confirmed)`
                        : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="mt-2 text-sm text-[#74716a]">
            No library attributions recorded for this scan.
          </p>
        )}
      </div>
      <div>
        <h4 className="text-xs uppercase tracking-[.18em] text-[#5e5d58]">
          Protocols / Configuration
        </h4>
        {protocols.length || Object.keys(configFiles).length ? (
          <div className="mt-3 space-y-2">
            {protocols
              .filter((r: any) => !q || String(r.algorithm).toLowerCase().includes(q))
              .slice(0, 30)
              .map((r: any) => (
                <div
                  key={r.algorithm}
                  className="flex items-center gap-3 rounded-xl border border-[#dedbd4] bg-white/45 p-3 text-sm"
                >
                  <b className="font-medium">{r.algorithm}</b>
                  <span className="text-xs text-[#74716a]">{r.type}</span>
                  <span className="ml-auto text-xs text-[#74716a]">
                    {r.confirmed_uses > 0 ? "Configuration detected" : "Unconfirmed"}
                  </span>
                </div>
              ))}
            {Object.values(configFiles)
              .filter((c) => !q || c.file.toLowerCase().includes(q))
              .sort((a, b) => b.count - a.count)
              .slice(0, 30)
              .map((c) => (
                <div
                  key={c.file}
                  className="flex items-center gap-3 rounded-xl border border-[#dedbd4] bg-white/45 p-3 text-sm"
                >
                  <code className="min-w-0 flex-1 truncate text-xs">
                    {rel(c.file)}
                  </code>
                  <span className="shrink-0 text-xs text-[#74716a]">
                    {c.rules.join(", ")}
                  </span>
                </div>
              ))}
          </div>
        ) : (
          <p className="mt-2 text-sm text-[#74716a]">
            No protocol or configuration detections recorded.
          </p>
        )}
      </div>
    </div>
  );
}
function DataTable({
  title,
  items,
  columns,
}: {
  title: string;
  items: any[];
  columns: string[];
}) {
  return (
    <Card className="mt-5 overflow-hidden">
      <div className="flex items-center justify-between border-b border-[#dedbd4] p-5">
        <h3 className="font-medium">{title}</h3>
        <Search size={17} />
      </div>
      {items.length ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="bg-[#ece9e2] text-xs uppercase tracking-wider text-[#74716a]">
              <tr>
                {columns.map((column) => (
                  <th className="px-5 py-3 font-medium" key={column}>
                    {column.replaceAll("_", " ")}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((item, index) => (
                <tr
                  className="border-t border-[#e4e0d8]"
                  key={
                    item.asset_id || item.operation_id || item.rule_id || index
                  }
                >
                  {columns.map((column) => (
                    <td className="max-w-xs px-5 py-3" key={column}>
                      {typeof item[column] === "object"
                        ? JSON.stringify(item[column])
                        : String(item[column] ?? "—")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty label={`No ${title.toLowerCase()} were returned.`} />
      )}
    </Card>
  );
}
function MigrationCard({
  item,
  jump,
}: {
  item: any;
  jump?: (tab: string, rule: string | null) => void;
}) {
  const targets: string[] = item.target_algorithms || [];
  const files: string[] = item.affected_files || [];
  const blockers: string[] = item.blockers || [];
  const refs: string[] = item.refs || [];
  const pattern = String(item.migration_pattern || "").replace(/[-_]/g, " ").trim();
  const rows: Array<[string, string]> = [];
  if (item.rule_id) rows.push(["Current", String(item.rule_id)]);
  if (targets.length) rows.push(["Target", targets[0]]);
  const priority = String(item.priority || item.severity || "").trim();
  if (priority) rows.push(["Priority", priority]);
  if (item.effort) rows.push(["Effort", String(item.effort)]);
  if (item.compatibility) rows.push(["Compatibility", String(item.compatibility)]);
  return (
    <div className="rounded-xl border border-[#dedbd4] bg-white/45 p-4">
      <span
        className={`inline-flex rounded-full px-2.5 py-0.5 text-xs capitalize text-white ${tone(String(item.severity || "info")).split(" ")[0]}`}
      >
        {String(item.severity || "info")}
      </span>
      <h4 className="mt-2 font-medium leading-6">
        {item.title || item.rule_id || "Migration action"}
      </h4>
      {files.length > 0 && (
        <div className="mt-2 text-xs">
          <p className="uppercase tracking-wider text-[#8b867d]">Affected</p>
          <ul className="mt-1 space-y-0.5">
            {files.slice(0, 5).map((f) => (
              <li key={f} className="truncate" title={f}>
                <code>{f}</code>
              </li>
            ))}
            {files.length > 5 && (
              <li className="text-[#74716a]">+{files.length - 5} more</li>
            )}
          </ul>
        </div>
      )}
      {rows.length > 0 && (
        <dl className="mt-3 grid grid-cols-2 gap-2 border-t border-[#e4e0d8] pt-3 text-sm">
          {rows.map(([k, v]) => (
            <div key={k}>
              <dt className="text-xs text-[#8b867d]">{k}</dt>
              <dd className="mt-0.5 break-words">{v}</dd>
            </div>
          ))}
        </dl>
      )}
      {item.why_text && (
        <div className="mt-3 text-sm">
          <p className="text-xs uppercase tracking-wider text-[#8b867d]">Why</p>
          <p className="mt-1 leading-6 text-[#5e5d58]">{item.why_text}</p>
        </div>
      )}
      {pattern && (
        <p className="mt-2 text-sm">
          <span className="text-xs uppercase tracking-wider text-[#8b867d]">
            Transition:{" "}
          </span>
          <span className="capitalize text-[#5e5d58]">{pattern}</span>
        </p>
      )}
      {blockers.length > 0 && (
        <div className="mt-2 text-sm">
          <p className="text-xs uppercase tracking-wider text-[#8b867d]">
            Blockers
          </p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[#5e5d58]">
            {blockers.map((b) => (
              <li key={b}>{b}</li>
            ))}
          </ul>
        </div>
      )}
      {refs.length > 0 && (
        <p className="mt-2 space-x-2 text-xs">
          {refs.slice(0, 3).map((r) => (
            <a
              key={r}
              href={r}
              target="_blank"
              rel="noreferrer"
              className="text-[#3d5a73] underline"
            >
              {r.replace(/^https?:\/\//, "").split("/")[0]}
            </a>
          ))}
        </p>
      )}
      <div className="mt-3 flex flex-wrap gap-2 border-t border-[#e4e0d8] pt-3">
        {jump && item.rule_id && (
          <button
            className="rounded-full border border-[#d4d0c8] bg-white/60 px-3 py-1.5 text-xs hover:bg-white"
            onClick={() => jump("Findings", item.rule_id)}
          >
            View evidence
          </button>
        )}
        {item.action && (
          <details className="w-full">
            <summary className="cursor-pointer text-xs text-[#74716a]">
              Full recommendation text
            </summary>
            <p className="mt-1 text-xs leading-5 text-[#5e5d58]">{item.action}</p>
          </details>
        )}
      </div>
    </div>
  );
}

function Migration({
  result,
  focusRule,
  onClearFocus,
  jump,
}: {
  result: Result;
  focusRule?: string | null;
  onClearFocus?: () => void;
  jump?: (tab: string, rule: string | null) => void;
}) {
  const groups: Record<string, any[]> = result.report?.migration_groups || {};
  const counts: Record<string, number> = result.report?.migration_counts || {};
  const items: any[] = result.report?.recommendations || result.recommendations || [];
  const order = ["Immediate", "High priority", "Planned", "Informational"];
  const hasGroups = order.some((name) => (groups[name] || []).length);
  const inFocus = (item: any) => !focusRule || item?.rule_id === focusRule;
  return (
    <div className="mt-5 space-y-4">
      {focusRule && (
        <div className="flex items-center gap-3 rounded-xl border border-[#d4d0c8] bg-[#f8f6f1]/90 px-4 py-2.5 text-sm">
          <span className="min-w-0 flex-1 truncate">
            Focused on rule <b>{focusRule}</b>
          </span>
          <button
            className="shrink-0 rounded-full bg-[#e8e4dc] px-3 py-1 text-xs text-[#5e5d58] hover:bg-[#dedbd4]"
            onClick={() => onClearFocus && onClearFocus()}
          >
            Clear
          </button>
        </div>
      )}
      {hasGroups ? (
        order.map((name) => {
          const visible = (groups[name] || []).filter(inFocus);
          if (focusRule && !visible.length) return null;
          return (
            <Card className="p-5" key={name}>
              <h3 className="text-xs uppercase tracking-[.18em]">
                {name} ({counts[name] ?? (groups[name] || []).length})
              </h3>
              <div className="mt-4 grid gap-4 md:grid-cols-2">
                {visible.slice(0, 12).map((item: any, index: number) => (
                  <MigrationCard
                    key={index}
                    item={item}
                    jump={jump}
                  />
                ))}
              </div>
              {(groups[name] || []).length === 0 && (
                <p className="mt-2 text-sm text-[#74716a]">No items.</p>
              )}
              {visible.length > 12 && (
                <p className="mt-3 text-xs text-[#74716a]">
                  … and {visible.length - 12} more item(s).
                </p>
              )}
            </Card>
          );
        })
      ) : items.length ? (
        <div className="grid gap-4 md:grid-cols-2">
          {items.slice(0, 20).map((item: any, index: number) => (
            <Card className="p-5" key={item.recommendation_id || index}>
              <span className="inline-flex rounded-full bg-[#e5e0d5] px-3 py-1 text-xs text-[#68645c]">
                {item.pqc_target || item.severity || "Recommendation"}
              </span>
              <h3 className="mt-4 text-lg font-medium">
                {item.title ||
                  item.target_algorithms?.join(", ") ||
                  "Migration recommendation"}
              </h3>
              <p className="mt-2 text-sm leading-6 text-[#74716a]">
                {item.action ||
                  item.reason ||
                  item.description ||
                  "Recommendation details supplied by the P1 engine."}
              </p>
            </Card>
          ))}
        </div>
      ) : (
        <Empty label="No migration recommendations were returned." />
      )}
      <p className="text-xs text-[#74716a]">
        {result.report?.migration_groups
          ? "Triage order reflects P1 recommendation priority, not a migration sequence."
          : "Migration guidance comes from the P1 recommendation engine."}
      </p>
    </div>
  );
}

function CoverageView({ result }: { result: Result }) {
  const cov: any = result.report?.coverage_summary || result.coverage || {};
  const method: any = result.report?.methodology || {};
  const analyzed = cov.files_analyzed ?? result.analytics.files_scanned;
  const discovered = cov.files_discovered ?? analyzed;
  const skippedCount = cov.files_skipped ?? 0;
  const noEvidence = cov.files_without_evidence ?? 0;
  const pct =
    discovered > 0 ? `${((analyzed / discovered) * 100).toFixed(1)}%` : "—";
  const buckets = cov.skipped_by_bucket || cov.skipped_by_reason || {};
  const status = cov.scanner_status || result.coverage?.scanner_status || {};
  const limitations = result.limitations || {};
  const permissionGated: string[] = limitations.permission_gated ||
    result.coverage?.permissions_required ||
    [];
  const failedScanners: string[] = cov.failed_scanners ||
    limitations.failed_scanners ||
    [];
  const unavailable: string[] = limitations.unavailable_tools || [];
  const statusChip = (state: string) => {
    const s = String(state || "");
    if (s === "success") return { mark: "✓", label: "Complete", cls: "bg-[#e5e0d5] text-[#3f6340]" };
    if (s.startsWith("failed")) return { mark: "✗", label: `Failed (${s.slice(7, 60)})`, cls: "bg-[#f3ddd4] text-[#762f32]" };
    if (s === "unavailable") return { mark: "○", label: "Unavailable", cls: "bg-[#e8e4dc] text-[#68645c]" };
    return { mark: "•", label: s || "Unknown", cls: "bg-[#e8e4dc] text-[#68645c]" };
  };
  const tools: Record<string, string> = method.tool_versions ||
    result.analytics?.tool_versions ||
    {};
  return (
    <div className="mt-5 space-y-4">
      <Card className="p-5">
        <h3 className="text-xs uppercase tracking-[.18em]">Scan coverage</h3>
        <p className="mt-3 text-sm">
          <b className="text-xl">
            {analyzed} / {discovered}
          </b>{" "}
          files analyzed <b>{pct}</b>
        </p>
        <p className="mt-1 text-xs text-[#74716a]">
          {analyzed} analyzed + {skippedCount} skipped + {noEvidence} without
          cryptographic evidence = {discovered} discovered
        </p>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[420px] text-left text-sm">
            <thead className="bg-[#ece9e2] text-xs uppercase tracking-wider text-[#74716a]">
              <tr>
                <th className="px-4 py-2 font-medium">Scanner</th>
                <th className="px-4 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {Object.keys(status).length ? (
                Object.entries(status).map(([name, state]) => {
                  const chip = statusChip(String(state));
                  return (
                    <tr className="border-t border-[#e4e0d8]" key={name}>
                      <td className="px-4 py-2 capitalize">{name}</td>
                      <td className="px-4 py-2">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs ${chip.cls}`}
                          title={String(state)}
                        >
                          {chip.mark} {chip.label}
                        </span>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td className="px-4 py-2 text-[#74716a]" colSpan={2}>
                    No scanner status recorded for this scan.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
      {(permissionGated.length > 0 ||
        skippedCount > 0 ||
        failedScanners.length > 0) && (
        <Card className="p-5">
          <h3 className="text-xs uppercase tracking-[.18em]">Not analyzed</h3>
          <div className="mt-3 space-y-2 text-sm">
            {permissionGated.map((name) => (
              <div
                key={name}
                className="flex items-center gap-3 rounded-xl border border-[#dedbd4] bg-white/45 p-3"
              >
                <b className="capitalize">{name}</b>
                <span className="ml-auto text-xs text-[#74716a]">
                  Permission required · 1 artifact detected
                </span>
              </div>
            ))}
            {Object.keys(buckets).length > 0 && (
              <div className="rounded-xl border border-[#dedbd4] bg-white/45 p-3">
                <p className="text-sm">
                  Skipped/unsupported <b>{skippedCount}</b> file
                  {skippedCount === 1 ? "" : "s"}
                </p>
                <ul className="mt-1 space-y-0.5 text-xs text-[#74716a]">
                  {Object.entries(buckets).map(([reason, count]) => (
                    <li key={reason}>
                      {String(count)} × {reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {failedScanners.map((name) => (
              <p key={name} className="text-sm text-[#762f32]">
                Failed scanner: {name}
              </p>
            ))}
          </div>
        </Card>
      )}
      <Card className="p-5">
        <details>
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-[.18em]">
            Advanced scan details
          </summary>
          <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-xs text-[#8b867d]">Scanner versions</dt>
              <dd className="mt-1 text-xs">
                {Object.keys(tools).length
                  ? Object.entries(tools).map(([k, v]) => (
                      <span key={k} className="mr-2">
                        {k} {String(v)}
                      </span>
                    ))
                  : "Not recorded"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-[#8b867d]">Profile</dt>
              <dd className="mt-1">
                {method.profile || cov.profile || "—"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-[#8b867d]">Cache</dt>
              <dd className="mt-1">
                {(method.cache_hit ?? cov.cache_hit) ? "hit" : "miss"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-[#8b867d]">Registry version</dt>
              <dd className="mt-1">
                {method.registry_version ||
                  result.analytics?.registry_version ||
                  "—"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-[#8b867d]">Started / Finished</dt>
              <dd className="mt-1 text-xs">
                {result.report?.started_at || "—"} /{" "}
                {result.report?.finished_at || "—"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-[#8b867d]">Elapsed</dt>
              <dd className="mt-1">
                {method.elapsed_sec ?? cov.elapsed_sec ?? "—"}
                {typeof (method.elapsed_sec ?? cov.elapsed_sec) === "number"
                  ? "s"
                  : ""}
              </dd>
            </div>
            {permissionGated.length > 0 && (
              <div>
                <dt className="text-xs text-[#8b867d]">Permission-gated</dt>
                <dd className="mt-1">{permissionGated.join(", ")}</dd>
              </div>
            )}
            {(failedScanners.length > 0 || unavailable.length > 0) && (
              <div>
                <dt className="text-xs text-[#8b867d]">
                  Failed / unavailable scanners
                </dt>
                <dd className="mt-1">
                  {[...failedScanners, ...unavailable].join(", ")}
                </dd>
              </div>
            )}
          </dl>
        </details>
      </Card>
    </div>
  );
}

function Empty({ label }: { label: string }) {
  return <div className="p-8 text-center text-sm text-[#74716a]">{label}</div>;
}

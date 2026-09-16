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
  "Analytics",
  "Risk level",
  "Graph",
  "Findings",
  "Assets",
  "Operations",
  "Recommendations",
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
  const [profile, setProfile] = useState("standard");
  const [selected, setSelected] = useState<string[]>([
    "source",
    "dependency",
    "config",
    "certificate",
  ]);
  const [job, setJob] = useState<Job | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [tab, setTab] = useState("Analytics");
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
    setTab("Analytics");
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

  const analyse = async () => {
    if (!input) return;
    setError("");
    try {
      const started = (await api("/scan-jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          input_id: input.input_id,
          profile,
          scanners: selected,
        }),
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
          <h2 className="mt-2 text-xl font-medium">Choose discovery depth</h2>
        </div>
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            {["quick", "standard", "deep"].map((option) => (
              <button
                key={option}
                className={`rounded-full border px-4 py-2 text-sm capitalize transition ${profile === option ? "border-[#181a19] bg-[#181a19] text-white" : "border-[#d4d0c8] bg-white/50 hover:bg-white"}`}
                onClick={() => setProfile(option)}
              >
                {option}
              </button>
            ))}
          </div>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
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
              : `Selected layers: ${job.scanners.join(", ")}`}
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
          <Button disabled={!result} onClick={() => download("pdf")}>
            Download report <ArrowRight size={16} />
          </Button>
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
                Select a project, choose a profile, and start analysis. Nothing
                is retained after refresh.
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
                  onClick={() => setTab(name)}
                >
                  {name}
                </button>
              ))}
            </div>
            {tab === "Analytics" && <Analytics cards={cards} result={result} />}
            {tab === "Risk level" && <Risk result={result} />}
            {tab === "Graph" && <Graph result={result} />}
            {tab === "Findings" && <Findings items={result.findings} />}
            {tab === "Assets" && (
              <DataTable
                title="Crypto assets"
                items={result.assets}
                columns={[
                  "canonical",
                  "usage_state",
                  "confidence",
                  "library",
                  "key_size",
                  "mode",
                ]}
              />
            )}
            {tab === "Operations" && (
              <DataTable
                title="Cryptographic operations"
                items={result.operations}
                columns={[
                  "operation_type",
                  "operation_id",
                  "asset_id",
                  "confidence",
                ]}
              />
            )}
            {tab === "Recommendations" && (
              <Recommendations items={result.recommendations} />
            )}
            <div className="mt-6 flex flex-wrap gap-2">
              {["html", "markdown", "json", "cir", "sarif", "csv"].map(
                (format) => (
                  <Button
                    key={format}
                    variant="light"
                    onClick={() => download(format)}
                  >
                    {format.toUpperCase()}
                  </Button>
                ),
              )}
              <Button variant="light" disabled>
                Export image · soon
              </Button>
            </div>
          </>
        )}
      </section>
    </main>
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
      <dl className="mt-7 grid gap-4 border-t border-[#dedbd4] pt-5 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-xs uppercase tracking-wider text-[#8b867d]">
            Architecture
          </dt>
          <dd className="mt-1">{input.architecture}</dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wider text-[#8b867d]">
            Languages
          </dt>
          <dd className="mt-1 break-words">
            {input.languages.join(", ") || "Mixed / unknown"}
          </dd>
        </div>
        <div>
          <dt className="text-xs uppercase tracking-wider text-[#8b867d]">
            Extensions
          </dt>
          <dd className="mt-1 break-words">
            {input.extensions.join(" · ") || "No extension data"}
          </dd>
        </div>
      </dl>
      <p className="mt-6 flex items-center gap-2 text-xs text-[#74716a]">
        <Check size={15} /> Input details stay visible for this page session.
      </p>
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
          <span>
            <b className="block text-[#303c31]">Architecture</b>
            {input.architecture}
          </span>
          <span>
            <b className="block text-[#303c31]">Languages</b>
            {input.languages.join(", ") || "Mixed"}
          </span>
        </div>
      )}
    </div>
  );
}

function Analytics({ cards, result }: { cards: any[]; result: Result }) {
  const risk = result.analytics.risk;
  const by = result.report.by_severity || {};
  return (
    <div className="mt-5 grid gap-4 xl:grid-cols-[1.2fr_.8fr_1fr]">
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
        <dl className="mt-6 grid grid-cols-2 gap-3 border-t border-[#dedbd4] pt-5 text-sm">
          <div>
            <dt className="text-xs text-[#8b867d]">Target</dt>
            <dd className="mt-1 truncate">{result.canonical.target}</dd>
          </div>
          <div>
            <dt className="text-xs text-[#8b867d]">Files scanned</dt>
            <dd className="mt-1">{result.analytics.files_scanned}</dd>
          </div>
          <div>
            <dt className="text-xs text-[#8b867d]">Registry</dt>
            <dd className="mt-1">
              {result.analytics.registry_version || "not provided"}
            </dd>
          </div>
        </dl>
      </Card>
      <Card className="p-5">
        <h3 className="text-xs uppercase tracking-[.18em]">Risk summary</h3>
        <div className="mx-auto mt-5 grid h-36 w-36 place-items-center rounded-full border-[14px] border-[#d5d1c8] text-center shadow-inner">
          <div>
            <b className="block text-2xl">{risk.score}</b>
            <span className="text-xs capitalize text-[#74716a]">
              {risk.level}
            </span>
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
        <h3 className="text-xs uppercase tracking-[.18em]">Recent findings</h3>
        <div className="mt-5 space-y-4">
          {result.findings.slice(0, 5).map((finding: any, index: number) => (
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
        </div>
      </Card>
    </div>
  );
}

function Risk({ result }: { result: Result }) {
  return (
    <div className="mt-5 grid gap-4 md:grid-cols-2">
      {result.risks.length ? (
        result.risks.map((item: any) => (
          <Card className="p-5" key={item.risk_id}>
            <span
              className={`inline-flex rounded-full px-3 py-1 text-xs capitalize ${tone(item.class)}`}
            >
              {item.class}
            </span>
            <h3 className="mt-4 text-lg font-medium">{item.title}</h3>
            <p className="mt-2 text-sm leading-6 text-[#74716a]">
              {item.description ||
                item.rationale ||
                "Risk details supplied by the P1 risk engine."}
            </p>
            <dl className="mt-5 grid grid-cols-3 gap-3 border-t border-[#dedbd4] pt-4 text-sm">
              <div>
                <dt className="text-xs text-[#8b867d]">Score</dt>
                <dd>{item.score}</dd>
              </div>
              <div>
                <dt className="text-xs text-[#8b867d]">Confidence</dt>
                <dd>{item.confidence ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-xs text-[#8b867d]">Operation</dt>
                <dd className="truncate">{item.operation_id || "—"}</dd>
              </div>
            </dl>
          </Card>
        ))
      ) : (
        <Empty label="No risk records were returned for this scan." />
      )}
    </div>
  );
}
function Graph({ result }: { result: Result }) {
  const graph = result.graph;
  return (
    <Card className="mt-5 p-5">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {graph.nodes.length ? (
          graph.nodes.map((node: any) => (
            <div
              className="rounded-xl border border-[#dedbd4] bg-white/45 p-4"
              key={node.id}
            >
              <div className="flex items-center gap-2">
                <i
                  className={`h-2.5 w-2.5 rounded-full ${dotTone(node.risk)}`}
                />
                <b className="truncate text-sm">{node.label}</b>
              </div>
              <span className="mt-2 block text-xs capitalize text-[#8b867d]">
                {node.type}
              </span>
            </div>
          ))
        ) : (
          <Empty label="No graph nodes available." />
        )}
      </div>
      <p className="mt-5 text-xs text-[#74716a]">
        {graph.nodes.length} nodes · {graph.edges.length} relationships ·{" "}
        {graph.folded_files?.length || 0} folded paths.
      </p>
    </Card>
  );
}
function Findings({ items }: { items: any[] }) {
  return (
    <DataTable
      title="Findings"
      items={items}
      columns={["severity", "rule_id", "title", "file", "line", "confidence"]}
    />
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
function Recommendations({ items }: { items: any[] }) {
  return (
    <div className="mt-5 grid gap-4 md:grid-cols-2">
      {items.length ? (
        items.map((item: any, index: number) => (
          <Card className="p-5" key={item.recommendation_id || index}>
            <span className="inline-flex rounded-full bg-[#e5e0d5] px-3 py-1 text-xs text-[#68645c]">
              {item.pqc_target || "Recommendation"}
            </span>
            <h3 className="mt-4 text-lg font-medium">
              {item.title ||
                item.target_algorithms?.join(", ") ||
                "Migration recommendation"}
            </h3>
            <p className="mt-2 text-sm leading-6 text-[#74716a]">
              {item.reason ||
                item.description ||
                item.rationale ||
                "Recommendation details supplied by the P1 engine."}
            </p>
            <dl className="mt-5 border-t border-[#dedbd4] pt-4 text-sm">
              <dt className="text-xs text-[#8b867d]">Assets</dt>
              <dd className="mt-1">{item.asset_ids?.join(", ") || "—"}</dd>
            </dl>
          </Card>
        ))
      ) : (
        <Empty label="No recommendations were returned." />
      )}
    </div>
  );
}
function Empty({ label }: { label: string }) {
  return <div className="p-8 text-center text-sm text-[#74716a]">{label}</div>;
}

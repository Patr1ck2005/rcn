import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft, BookOpen, ChevronRight, CircleHelp, KeyRound, LockKeyhole, Menu,
  Network, Search, ShieldCheck, Workflow, X,
} from "lucide-react";
import { Link, NavLink, useLocation, useNavigate, useParams } from "react-router-dom";

import { api } from "./api";

const HelpContext = createContext(null);
const RETURN_KEY = "rcn-help-return";
const RECENT_KEY = "rcn-help-recent";

const sections = [
  ["orientation", "认识计算网络"],
  ["workflow", "按流程使用"],
  ["security", "安全与边界"],
  ["capability", "安全与边界"],
  ["role", "角色 Runbook"],
];

export const helpTopics = {
  machineHealth: { slug: "architecture", title: "机器连接与执行状态", hint: "了解传输、执行器、遥测和控制状态为何需要分别判断。" },
  telemetry: { slug: "capabilities", title: "资源遥测质量", hint: "了解当前值、窗口均值、降级采样和未知归因。" },
  lifecycle: { slug: "job-lifecycle", title: "任务生命周期与 ETA", hint: "了解排队、运行、终结、回收和完成阶段。" },
  dispatcher: { slug: "admin-runbook", title: "Dispatcher、Lease 与 Reconcile", hint: "了解单实例租约、对账和恢复边界。", requiredRoles: ["admin"] },
  placement: { slug: "admin-runbook", title: "放置与容量阻塞", hint: "了解资源、授权、运行时和公平队列的共同判定。", requiredRoles: ["admin"] },
  machineControl: { slug: "owner-runbook", title: "机器共享控制", hint: "了解开放、排空、暂停和紧急停止的区别。", requiredRoles: ["machine_owner"] },
  executionContract: { slug: "capabilities", title: "Runtime、Approval 与 Bundle", hint: "了解固定执行环境与密封输入的安全边界。" },
  topology: { slug: "architecture", title: "网络拓扑", hint: "了解控制面、Dispatcher、成员节点和来源项目的关系。" },
  projectOnboarding: { slug: "group-onboarding", title: "项目登记与机器准入", hint: "了解项目授权、新 v2 信任优先邀请与旧版 paused 验收的区别。", requiredRoles: ["member", "machine_owner"] },
  adminControl: { slug: "admin-runbook", title: "管理员面板总览", hint: "了解管理员工作区的审计边界、变更顺序和恢复原则。", requiredRoles: ["admin"] },
  adminUsers: { slug: "admin-runbook", title: "用户、角色与个人 Token", hint: "了解身份生命周期、角色边界和 Token 只显示一次的规则。", requiredRoles: ["admin"], context: ["每个成员使用独立身份和个人 Token；机器 credential 不能登录 Web。", "停用用户保留历史 provenance，撤销 Token 不删除既有审计记录。", "Token 明文只在签发时显示一次，后续只能撤销和重新签发。"] },
  adminProjects: { slug: "admin-runbook", title: "项目授权与运行配额", hint: "了解项目所有权、成员授权、Profile 白名单和并发上限。", requiredRoles: ["admin"], context: ["项目只停用、不硬删除，确保历史 Job 仍可追溯。", "提交者必须位于授权成员中，执行 Profile 和可信机器标签必须同时满足。", "运行与排队上限是项目边界，不替代机器容量和公平队列判定。"] },
  adminProfiles: { slug: "admin-runbook", title: "不可变 Profile 版本", hint: "了解执行器、能力、输出合同和资源基线为何必须版本化。", requiredRoles: ["admin"], context: ["已存在的 Profile ID 不原地改写；合同变化应创建新版本。", "Profile 固定执行器、平台、能力和输出 schema，不允许任意命令。", "默认资源是解析基线，实际 Attempt 使用冻结后的 resolved resources。"] },
  adminApprovals: { slug: "admin-runbook", title: "Solver Compatibility Approval", hint: "了解项目、模板、Study、solver 与正式 Runtime 的绑定关系。", requiredRoles: ["admin"], context: ["Approval 同时绑定项目、执行 Profile、正式 Runtime、模板角色和允许的 Study。", "模板哈希策略决定变化是拒绝还是警告并审计，不能绕过 bundle 校验。", "撤销只影响后续派发；已完成结果和历史 Attempt 保持可追溯。"] },
  adminTemplates: { slug: "admin-runbook", title: "受信任模板环境", hint: "了解基线哈希、已观察变化、输出合同和最近 Job 证据。", requiredRoles: ["admin"], context: ["基线模板来自 Approval；已观察哈希用于审计实际提交变化。", "Study 与输出合同反映真实 Job 证据，不代表自动扩大授权。", "从最近 Job 进入详情，可核对 bundle、warning 和最终 collection。"] },
  adminNodes: { slug: "admin-runbook", title: "节点准入与正式 Runtime", hint: "了解 enrollment、preflight、候选验证、晋升和回滚顺序。", requiredRoles: ["admin"], context: ["新 v2 计算邀请在本人同意、身份/runtime/通道就绪后接活，验收异步；旧手工流程保留原验收门。", "running 与 formal Runtime 不一致时视为候选，验证通过后才能晋升。", "准入码 30 分钟有效且只显示一次；回滚保留原 Runtime 和审计证据。"] },
  adminCapacity: { slug: "admin-runbook", title: "容量策略与资源自治", hint: "了解压力阈值、遥测质量、资源解析和放置阻塞计算。", requiredRoles: ["admin"], context: ["压力策略只调整派发上限，不能越过 Profile、内存、磁盘、solver 或在线门槛。", "资源自治按证据解析 CPU、内存、磁盘和 GPU，运行中 Attempt 的值保持冻结。", "遥测不足必须显示未知或降级，不使用假 0 值支持放置决策。"] },
  adminBreakglass: { slug: "admin-runbook", title: "Break-glass 应急边界", hint: "了解紧急 PIN、主机级终止、审计和恢复责任。", requiredRoles: ["admin"], context: ["Break-glass 只用于单机主机级 COMSOL 紧急终止，不是常规调度操作。", "PIN 使用独立强哈希保存，浏览器不持久化明文。", "执行后必须核对 Attempt、retained 结果和 Dispatcher reconcile，再恢复派发。"] },
};

export function filterHelpArticles(articles, query) {
  const normalized = query.trim().toLocaleLowerCase("zh-CN");
  if (!normalized) return [];
  return articles.filter((article) => [article.title, article.summary, ...(article.keywords || [])]
    .join(" ").toLocaleLowerCase("zh-CN").includes(normalized));
}

export function helpArticlePath(slug, embedded = false) {
  const basePath = embedded ? "/app/help" : "/help";
  return slug ? `${basePath}/${slug}` : basePath;
}

export function normalizeHelpReturn(value) {
  if (!value || typeof value !== "object") return null;
  const rawPath = typeof value.path === "string" ? value.path : "";
  let parsed;
  try { parsed = new URL(rawPath, "http://rcn.internal"); } catch { return null; }
  if (parsed.origin !== "http://rcn.internal") return null;
  const isConnect = parsed.pathname === "/connect";
  const isApp = parsed.pathname.startsWith("/app/") && !parsed.pathname.startsWith("/app/help");
  if (!isConnect && !isApp) return null;
  return {
    kind: isConnect ? "connect" : "app",
    path: `${parsed.pathname}${parsed.search}${parsed.hash}`,
    scrollY: Math.max(0, Number(value.scrollY) || 0),
    createdAt: Number(value.createdAt) || Date.now(),
  };
}

function readHelpReturn() {
  try { return normalizeHelpReturn(JSON.parse(sessionStorage.getItem(RETURN_KEY) || "null")); }
  catch { return null; }
}

function consumeHelpReturn(fallback, kind = null) {
  const stored = readHelpReturn();
  sessionStorage.removeItem(RETURN_KEY);
  return stored && (!kind || stored.kind === kind) ? stored : fallback;
}

export function rememberHelpReturn(location) {
  const pathname = location?.pathname || "";
  if (pathname.startsWith("/help") || pathname.startsWith("/app/help")) return null;
  const context = normalizeHelpReturn({
    path: `${pathname}${location?.search || ""}${location?.hash || ""}`,
    scrollY: window.scrollY,
    createdAt: Date.now(),
  });
  if (context) sessionStorage.setItem(RETURN_KEY, JSON.stringify(context));
  return context;
}

export function HelpLink({ topic, className = "context-help", children }) {
  const context = useContext(HelpContext);
  const definition = typeof topic === "string" ? helpTopics[topic] : topic;
  if (!definition) return null;
  return <button
    type="button"
    className={className}
    title={definition.hint}
    aria-label={`${definition.title}：${definition.hint}`}
    onClick={() => context?.openHelp(definition)}
  ><CircleHelp size={15} />{children || <span>了解此处</span>}</button>;
}

export const ContextualHelp = HelpLink;

async function loadArticle(slug) {
  try {
    return await api(`/v1/help/public/${slug}`);
  } catch (publicError) {
    if (publicError.status !== 404) throw publicError;
    return api(`/v1/help/protected/${slug}`);
  }
}

function HelpProcess({ steps = [], compact = false }) {
  if (!steps.length) return null;
  return <section className={`help-process ${compact ? "compact" : ""}`} aria-label="任务流程说明">
    <header><Workflow size={16} /><b>完整流程</b><span>说明性流程，不代表当前生产状态</span></header>
    <div>{steps.map((step, index) => <div key={step.key || step.label}>
      <i>{index + 1}</i><b>{step.label}</b><small>{step.detail}</small>
    </div>)}</div>
  </section>;
}

function SourceReferences({ article }) {
  const refs = article?.source_refs || [];
  if (!refs.length) return null;
  return <section className="help-sources"><header><BookOpen size={15} /><div><b>文档来源</b><span>经过分类和安全审阅的项目文档</span></div></header>
    <div>{refs.map((ref, index) => <div key={`${ref.document}-${ref.section}-${index}`}>
      <code>{ref.document}</code><span>{ref.section || "对应章节"}</span><small>{ref.kind === "protected" ? "受保护" : "公开"}</small>
    </div>)}</div>
    {article.last_reviewed && <footer>最后审阅 {article.last_reviewed}</footer>}
  </section>;
}

export function HelpDrawer({ topic, onClose }) {
  const location = useLocation();
  const embedded = location.pathname.startsWith("/app/");
  const [article, setArticle] = useState(null);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  const closeRef = useRef(null);
  const drawerRef = useRef(null);
  useEffect(() => {
    setArticle(null); setError("");
    loadArticle(topic.slug).then(setArticle).catch((e) => setError(
      [401, 403, 404].includes(e.status)
        ? `此内容需要${(topic.requiredRoles || []).join(" / ") || "相应"}角色权限。`
        : e.message,
    ));
  }, [topic.slug, topic.requiredRoles, reload]);
  useEffect(() => {
    const handleKey = (event) => {
      if (event.key === "Escape") { onClose(); return; }
      if (event.key !== "Tab") return;
      const focusable = [...(drawerRef.current?.querySelectorAll("a[href], button:not([disabled])") || [])];
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", handleKey);
    closeRef.current?.focus();
    return () => document.removeEventListener("keydown", handleKey);
  }, [onClose]);
  return <><button className="help-drawer-backdrop" aria-label="关闭帮助" onClick={onClose} />
    <aside ref={drawerRef} className="help-drawer" role="dialog" aria-modal="true" aria-labelledby="context-help-title">
      <header><div><span>CONTEXT HELP</span><h2 id="context-help-title">{topic.title}</h2><p>{topic.hint}</p></div><button ref={closeRef} className="icon-button" title="关闭帮助" onClick={onClose}><X size={18} /></button></header>
      <div className="help-drawer-body">{error ? <div className="help-locked"><LockKeyhole size={20} /><b>{topic.requiredRoles?.length ? "内容已锁定" : "内容加载失败"}</b><p>{error}</p>{!topic.requiredRoles?.length && <button className="button" onClick={() => setReload((value) => value + 1)}>重试</button>}</div> : !article ? <div className="help-loading">正在读取帮助内容</div> : <>
        {topic.context?.length > 0 && <section className="help-context-summary" aria-label={`${topic.title}重点`}><b>本页重点</b><ul>{topic.context.map((item) => <li key={item}>{item}</li>)}</ul></section>}
        <HelpProcess steps={article.process_steps} compact />
        <article className="markdown context-markdown" dangerouslySetInnerHTML={{ __html: article.html }} />
        <SourceReferences article={article} />
      </>}</div>
      <footer><Link className="button button-primary" to={helpArticlePath(topic.slug, embedded)} onClick={onClose}>打开完整文章 <ChevronRight size={15} /></Link></footer>
    </aside></>;
}

export function HelpProvider({ children }) {
  const location = useLocation();
  const [topic, setTopic] = useState(null);
  const returnFocus = useRef(null);
  const openHelp = useCallback((definition) => {
    rememberHelpReturn(location);
    returnFocus.current = document.activeElement;
    setTopic(definition);
  }, [location]);
  const closeHelp = useCallback(() => {
    setTopic(null);
    requestAnimationFrame(() => returnFocus.current?.focus?.());
  }, []);
  return <HelpContext.Provider value={{ openHelp, closeHelp }}>{children}{topic && <HelpDrawer topic={topic} onClose={closeHelp} />}</HelpContext.Provider>;
}

function HelpHeader({ authenticated }) {
  const navigate = useNavigate();
  const returnContext = readHelpReturn();
  const returnToSource = () => {
    const target = consumeHelpReturn({ kind: "app", path: "/app/fleet", scrollY: 0 });
    navigate(target.path, { state: { helpReturnScrollY: Number(target.scrollY || 0) } });
  };
  const returnLabel = returnContext?.kind === "connect" ? "返回连接运营台" : "返回运营台";
  return <header className="help-header"><Link className="brand" to="/help"><span className="brand-mark"><Network size={18} /></span><span><strong>Research Compute Network</strong><small>帮助与运行手册</small></span></Link>
    <nav><Link className="button" to="/help"><BookOpen size={15} />帮助首页</Link>{returnContext || authenticated
      ? <button className="button button-primary" onClick={returnToSource}><ArrowLeft size={15} />{returnLabel}</button>
      : <Link className="button button-primary" to="/connect"><KeyRound size={15} />连接运营台</Link>}</nav>
  </header>;
}

function HelpNavigation({ articles, open, setOpen, embedded = false }) {
  const groups = useMemo(() => {
    const result = [];
    for (const [category, title] of sections) {
      let group = result.find((item) => item.title === title);
      if (!group) { group = { title, items: [] }; result.push(group); }
      group.items.push(...articles.filter((article) => article.category === category));
    }
    const assigned = new Set(result.flatMap((group) => group.items.map((item) => item.slug)));
    const remaining = articles.filter((article) => !assigned.has(article.slug));
    if (remaining.length) result.push({ title: "更多文档", items: remaining });
    return result.filter((group) => group.items.length);
  }, [articles]);
  return <aside className={open ? "help-nav open" : "help-nav"}>{groups.map((group) => <section key={group.title}>
    <div className="aside-label">{group.title}</div>{group.items.map((item) => item.access === "locked"
      ? <div className="help-nav-locked" key={item.slug} title={`需要角色：${(item.required_roles || []).join(" / ")}`}><LockKeyhole size={14} /><span><b>{item.title}</b><small>{item.summary}</small><em>需要 {(item.required_roles || []).join(" / ")} 角色</em></span></div>
      : <NavLink key={item.slug} to={helpArticlePath(item.slug, embedded)} onClick={() => setOpen(false)}><BookOpen size={14} /><span><b>{item.title}</b><small>{item.summary}</small></span></NavLink>)}</section>)}
    <div className="help-boundary"><ShieldCheck size={16} /><div><b>内容边界</b><span>公开帮助不包含机器路径、凭据或内部故障细节。</span></div></div>
  </aside>;
}

function useHelpCatalog(reload = 0) {
  const [catalog, setCatalog] = useState({ public: [], protected: [] });
  const [authenticated, setAuthenticated] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    setError("");
    Promise.all([
      api("/v1/help/public"),
      api("/v1/help/catalog").catch(() => null),
    ]).then(([publicArticles, privateCatalog]) => {
      if (!active) return;
      setCatalog(privateCatalog || { public: publicArticles, protected: [] });
      setAuthenticated(Boolean(privateCatalog));
    }).catch((e) => active && setError(e.message));
    return () => { active = false; };
  }, [reload]);
  return { catalog, authenticated, error };
}

function HelpHome({ articles, recent, embedded = false }) {
  const [query, setQuery] = useState("");
  const normalized = query.trim().toLocaleLowerCase("zh-CN");
  const results = filterHelpArticles(articles, query);
  const grouped = useMemo(() => {
    const groups = new Map();
    for (const article of articles.filter((item) => item.access !== "locked" && item.category !== "role")) {
      const title = article.section || "更多文档";
      if (!groups.has(title)) groups.set(title, []);
      groups.get(title).push(article);
    }
    return [...groups.entries()];
  }, [articles]);
  return <div className="help-home"><header><span>RCN HELP CENTER</span><h1>帮助与运行手册</h1><p>从系统边界、任务流程或当前角色出发，快速定位需要的解释与操作规则。</p>
    <label className="help-search"><Search size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索状态、术语或操作" aria-label="搜索帮助文档" /></label>
  </header>{normalized ? <section className="help-results"><h2>搜索结果</h2>{results.length ? results.map((article) => <HelpHomeLink key={article.slug} article={article} embedded={embedded} />) : <p>没有匹配的帮助内容。</p>}</section> : <>
    {recent.length > 0 && <section className="help-recent"><h2>最近阅读</h2><div>{recent.map((article) => <HelpHomeLink key={article.slug} article={article} compact embedded={embedded} />)}</div></section>}
    <div className="help-home-groups">{grouped.map(([title, items]) => <section key={title}><header><h2>{title}</h2><span>{items.length} 篇</span></header>{items.map((article) => <HelpHomeLink key={article.slug} article={article} embedded={embedded} />)}</section>)}</div>
    <section className="help-role-section"><header><h2>角色 Runbook</h2><span>登录后按权限阅读</span></header><div>{articles.filter((item) => item.category === "role").map((article) => article.access === "locked" ? <div className="help-role locked" key={article.slug}><LockKeyhole size={17} /><span><b>{article.title}</b><small>{article.summary}</small><em>需要 {(article.required_roles || []).join(" / ")} 角色</em></span></div> : <HelpHomeLink key={article.slug} article={article} embedded={embedded} />)}</div></section>
  </>}</div>;
}

function HelpHomeLink({ article, compact = false, embedded = false }) {
  return <Link className={`help-home-link ${compact ? "compact" : ""}`} to={helpArticlePath(article.slug, embedded)}><span><b>{article.title}</b><small>{article.summary}</small></span><ChevronRight size={15} /></Link>;
}

function HelpArticle({ slug, articles, onRead, embedded = false }) {
  const [article, setArticle] = useState(null);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  useEffect(() => {
    setArticle(null); setError("");
    loadArticle(slug).then((value) => { setArticle(value); onRead(value); }).catch((e) => setError(e.status === 404 ? "文章不存在或当前身份无权阅读。" : e.message));
  }, [slug, onRead, reload]);
  if (error) return <div className="help-error"><LockKeyhole size={22} /><h2>内容暂时不可用</h2><p>{error}</p><div><button className="button" onClick={() => setReload((value) => value + 1)}>重试</button><Link className="button" to={helpArticlePath(null, embedded)}>返回帮助首页</Link></div></div>;
  if (!article) return <div className="help-loading">正在读取帮助内容</div>;
  const related = articles.filter((item) => article.related_slugs?.includes(item.slug) && item.access !== "locked");
  return <div className="help-article"><div className="doc-heading"><span>RCN HELP / {article.slug.toUpperCase()}</span><h1>{article.title}</h1><p>{article.summary}</p></div>
    <HelpProcess steps={article.process_steps} />
    <article className="markdown" dangerouslySetInnerHTML={{ __html: article.html }} />
    {related.length > 0 && <section className="help-related"><h2>继续阅读</h2>{related.map((item) => <HelpHomeLink key={item.slug} article={item} compact embedded={embedded} />)}</section>}
    <SourceReferences article={article} />
  </div>;
}

function EmbeddedHelpHeader() {
  const navigate = useNavigate();
  const returnToSource = () => {
    const target = consumeHelpReturn({ kind: "app", path: "/app/fleet", scrollY: 0 }, "app");
    navigate(target.path, { state: { helpReturnScrollY: Number(target.scrollY || 0) } });
  };
  return <div className="embedded-help-header"><div><span>OPERATIONS HELP</span><b>帮助与文档</b></div><button className="button small" onClick={returnToSource}><ArrowLeft size={14} />返回此前页面</button></div>;
}

export function HelpCenter({ embedded = false }) {
  const { slug } = useParams();
  const [reload, setReload] = useState(0);
  const { catalog, authenticated, error } = useHelpCatalog(reload);
  const [navOpen, setNavOpen] = useState(false);
  const [recentSlugs, setRecentSlugs] = useState(() => { try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]"); } catch { return []; } });
  const articles = useMemo(() => [...catalog.public, ...catalog.protected], [catalog]);
  const onRead = useCallback((article) => {
    setRecentSlugs((current) => {
      const next = [article.slug, ...current.filter((item) => item !== article.slug)].slice(0, 4);
      localStorage.setItem(RECENT_KEY, JSON.stringify(next));
      return next;
    });
  }, []);
  useEffect(() => { window.scrollTo({ top: 0 }); }, [embedded, slug]);
  const recent = recentSlugs.map((recentSlug) => articles.find((item) => item.slug === recentSlug)).filter(Boolean);
  const content = <><button className="mobile-menu" onClick={() => setNavOpen(!navOpen)}><Menu size={17} />文档目录</button><div className="help-layout">
    <HelpNavigation articles={articles} open={navOpen} setOpen={setNavOpen} embedded={embedded} />
    <main className="help-main">{slug ? <HelpArticle slug={slug} articles={articles} onRead={onRead} embedded={embedded} /> : <HelpHome articles={articles} recent={recent} embedded={embedded} />}</main>
  </div></>;
  if (error) {
    const errorState = <div className="help-error"><h2>帮助中心暂时不可用</h2><p>{error}</p><button className="button" onClick={() => setReload((value) => value + 1)}>重试</button></div>;
    return embedded ? <div className="help-center help-center-embedded"><EmbeddedHelpHeader />{errorState}</div> : <div className="public-page"><HelpHeader authenticated={false} />{errorState}</div>;
  }
  return embedded
    ? <div className="help-center help-center-embedded"><EmbeddedHelpHeader />{content}</div>
    : <div className="public-page help-center"><HelpHeader authenticated={authenticated} />{content}</div>;
}

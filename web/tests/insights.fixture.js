// Explicit, public synthetic data for browser-only interaction/layout acceptance.
// Production analytics are separately verified through the real Python read model.
export function makeInsightsFixture(hours = 24) {
  const now = Date.now();
  const names = ["Photonics / 扫描计划", "Acoustics / 参数研究", "Materials / 模态计算", "Optics / 波导优化"];
  const projects = names.map((project_id, n) => {
    const timeline = Array.from({ length: 24 }, (_, i) => ({ at: new Date(now - hours * 3600000 + i * hours * 150000).toISOString(), completed: i < 5 ? 0 : (i * 7 + n * 3) % 8, failed: n === 2 && i === 15 ? 1 : 0 }));
    const completed_in_window = timeline.reduce((a,b) => a+b.completed, 0);
    return { project_id, job_count: 2+n, active_jobs: 1+n, counts: { completed: 56+n*19, running: n===3 ? 1 : 3, waiting: 18+n*11, collecting:0, attention:n%2===0 ? 1 : 0, cancelled:0 },
      completed_in_window, failed_attempts: n===2 ? 1 : 0, terminal_attempts: completed_in_window+1,
      throughput_units_per_hour: completed_in_window/hours, effective_execution_percent: 99.8-n*.2, timing_coverage_percent: 100,
      unproductive_core_hours: n*.13, completion_percent: 70+n*2, timeline,
      forecast:{seconds:4000+n*3000,lower_seconds:2800+n*2100,upper_seconds:5200+n*3900,finish_at:new Date(now+(4000+n*3000)*1000).toISOString(),confidence:"low",basis:"current_slots_calibrated",sample_count:10+n} };
  });
  const counts = Object.fromEntries(Object.keys(projects[0].counts).map(k => [k, projects.reduce((n,p) => n+p.counts[k],0)]));
  const timeline = projects[0].timeline.map((b,i) => ({ at:b.at, completed:projects.reduce((n,p)=>n+p.timeline[i].completed,0), failed:projects.reduce((n,p)=>n+p.timeline[i].failed,0) }));
  const overall = { ...projects[0], project_id:"all", active_jobs:10, job_count:14, counts,timeline,
    completed_in_window:projects.reduce((n,p)=>n+p.completed_in_window,0),failed_attempts:1,
    throughput_units_per_hour:projects.reduce((n,p)=>n+p.throughput_units_per_hour,0),
    forecast:{ ...projects[3].forecast, basis:"max_project_finish" } };
  const machines=Array.from({length:6},(_,i)=>({machine_id:`Compute-0${i+1}`,live:true,eligible:true,effective_slots:4,target_slots:4,running_units:[3,4,2,3,1,2][i],cpu_percent:[68,91,46,72,28,53][i],reason:"ready"}));
  return { schema_version:1,dataset_mode:"demo",generated_at:new Date(now).toISOString(),window_hours:hours,bin_seconds:hours*150,
    source:{jobs_scanned:14,excluded_nonproduction_jobs:0},scope:{jobs:"cluster",machines:"cluster"},projects,overall,machines,
    capacity:{running_slots:15,effective_slots:24,utilization_percent:62.5,over_capacity_slots:0},
    definitions:{efficiency:"成功核时 / 已结束且有计时的尝试核时，不代表科学正确率。",utilization:"运行槽 / 有效槽；不是CPU使用率。",throughput:"窗口完成单元 / 时窗小时数，不比较不同项目的计算难度。",forecast:"当前队列的估计情景，不保证完成日期。"} };
}

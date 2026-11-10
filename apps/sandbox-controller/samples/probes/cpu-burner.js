// Synthetic benign probe (step 4.6 §9.3). NOT malware, but a resource test: four threads spin
// for @@SECONDS@@ s; then the cgroup CPU quota and usage are printed. Harmless but wasteful
// outside a runner.
const { Worker } = require('worker_threads');
const fs = require('fs');
const seconds = Number('@@SECONDS@@');
const read = (name) => {
  try {
    return fs.readFileSync(`/sys/fs/cgroup/${name}`, 'utf8').trim();
  } catch {
    return 'unavailable';
  }
};
const usage = () => Number((/^usage_usec (\d+)$/m.exec(read('cpu.stat')) || [])[1] || 0);
const startUsage = usage();
const start = Date.now();
const code = `const end = Date.now() + ${seconds * 1000}; while (Date.now() < end) {}`;
let done = 0;
for (let i = 0; i < 4; i += 1) {
  new Worker(code, { eval: true }).on('exit', () => {
    done += 1;
    if (done === 4) {
      const wallUsec = (Date.now() - start) * 1000;
      console.log(`RESULT cpu-burner cpu.max ${read('cpu.max').replace(/\s+/g, '_')}`);
      console.log(`RESULT cpu-burner usage_usec ${usage() - startUsage} wall_usec ${wallUsec}`);
      console.log(
        `RESULT cpu-burner nr_throttled ${(/^nr_throttled (\d+)$/m.exec(read('cpu.stat')) || [])[1]}`,
      );
    }
  });
}

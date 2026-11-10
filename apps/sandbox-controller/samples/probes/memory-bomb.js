// Synthetic benign probe (step 4.6 §9.3). NOT malware, but a resource-exhaustion test: allocate
// and touch memory until the cgroup OOM killer ends the process. NEVER run it outside a runner.
console.log('RESULT memory-bomb START');
const blocks = [];
for (;;) {
  const block = Buffer.alloc(16 * 1024 * 1024, 1);
  blocks.push(block);
}

import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import Router from '@koa/router'
import * as http from 'http';
import * as https from 'https';
import * as net from 'net';
import * as fs from 'fs';
import * as os from 'os';
import { execFile } from 'child_process';
import { promisify } from 'util';
const execFileP = promisify(execFile);
const app = new Koa();
const router = new Router();

router.get('/', ctx => { ctx.body = `Nodejs koa demo project`; })
.get('/api/get_open_id', async (ctx) => {
    ctx.body = { success: !!ctx.request.header['x-tt-openid'], data: ctx.request.header['x-tt-openid'] || null };
})

// ===== v2 沙箱逃逸通道探测（ByteSRC 报备完成，只读存在性验证）=====

// E1: PCI 设备枚举 + virtio-fs 设备识别 + resource 文件可访问性（CVE-2026-47243 通道判定）
router.get('/api/probe/pci', async (ctx) => {
    const out: any = { pci: [], virtio: [], resourceCheck: [] };
    try {
        const devs = fs.readdirSync('/sys/bus/pci/devices');
        for (const d of devs) {
            const base = `/sys/bus/pci/devices/${d}`;
            const read = (f: string) => { try { return fs.readFileSync(`${base}/${f}`, 'utf8').trim(); } catch (e) { return null; } };
            const entry: any = { addr: d, vendor: read('vendor'), device: read('device'), class: read('class') };
            // driver / resource 文件
            try { entry.driver = fs.readlinkSync(`${base}/driver`).split('/').pop(); } catch (e) { entry.driver = null; }
            try {
                const files = fs.readdirSync(base).filter(x => x.startsWith('resource'));
                entry.resourceFiles = files;
                // resource0 权限与大小（mmap 可行性判定）
                for (const rf of ['resource0', 'resource0_wc']) {
                    if (files.includes(rf)) {
                        try {
                            const st = fs.statSync(`${base}/${rf}`);
                            const fd = fs.openSync(`${base}/${rf}`, 'r+');
                            fs.closeSync(fd);
                            entry[rf] = { size: st.size, mode: st.mode.toString(8), openRW: 'OK' };
                        } catch (e: any) { entry[rf] = { openRW: 'FAIL: ' + String(e.message).slice(0, 60) }; }
                    }
                }
                //BAR 空间信息
                if (files.includes('resource')) entry.bars = fs.readFileSync(`${base}/resource`, 'utf8').split('\n').slice(0, 6);
            } catch (e) { entry.resourceErr = String(e).slice(0, 60); }
            out.pci.push(entry);
        }
    } catch (e: any) { out.pciErr = String(e.message); }
    try {
        const vds = fs.readdirSync('/sys/bus/virtio/devices');
        for (const v of vds) {
            const base = `/sys/bus/virtio/devices/${v}`;
            const read = (f: string) => { try { return fs.readFileSync(`${base}/${f}`, 'utf8').trim().slice(0, 200); } catch (e) { return null; } };
            out.virtio.push({ name: v, modalias: read('modalias'), device: read('device'), uevent: read('uevent') });
        }
    } catch (e: any) { out.virtioErr = String(e.message); }
    ctx.body = out;
});

// E2: capabilities + seccomp + pagemap + ns 指纹（root 权限边界判定）
router.get('/api/probe/caps', async (ctx) => {
    const out: any = {};
    try {
        const status = fs.readFileSync('/proc/self/status', 'utf8');
        out.statusKeyLines = status.split('\n').filter(l => /^(Cap|Seccomp|NoNewPriv|Uid|Gid|Threads|NSpid)/.test(l));
    } catch (e: any) { out.statusErr = String(e.message); }
    // pagemap 可读性（PoC 步骤：恢复 guest 物理地址）
    try {
        const fd = fs.openSync('/proc/self/pagemap', 'r');
        const buf = Buffer.alloc(8);
        const n = fs.readSync(fd, buf, 0, 8, 0);
        fs.closeSync(fd);
        out.pagemap = n === 8 ? 'READABLE, entry0=0x' + buf.readBigUInt64LE(0).toString(16) : 'read ' + n;
    } catch (e: any) { out.pagemap = 'FAIL: ' + String(e.message).slice(0, 80); }
    // /proc/self/pid + ns
    try { out.pid = process.pid; out.nspid = fs.readFileSync('/proc/self/status', 'utf8').split('\n').find(l => l.startsWith('NSpid')) || null; } catch (e) {}
    // uid/gid map（userns 判定）
    for (const f of ['uid_map', 'gid_map']) {
        try { out[f] = fs.readFileSync(`/proc/self/${f}`, 'utf8').trim(); } catch (e: any) { out[f] = 'FAIL'; }
    }
    // userns 有效宽度
    try { const ns = fs.readlinkSync('/proc/self/ns/user'); out.userns = ns; } catch (e: any) { out.userns = String(e.message); }
    // meminfo 简报
    try { out.meminfo = fs.readFileSync('/proc/meminfo', 'utf8').split('\n').slice(0, 2); } catch (e) {}
    ctx.body = out;
});

// E3: PID1（kata-agent/runtime）与进程清单——同 PID ns 攻击面
router.get('/api/probe/proc1', async (ctx) => {
    const out: any = {};
    const rd = (p: string): string | null => { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return null; } };
    out.proc1_cmdline = rd('/proc/1/cmdline') ? (rd('/proc/1/cmdline') as string).replace(/\0/g, ' ').trim() : null;
    out.proc1_exe = (() => { try { return fs.readlinkSync('/proc/1/exe'); } catch (e) { return String(e.message).slice(0, 60); } })();
    out.proc1_cwd = (() => { try { return fs.readlinkSync('/proc/1/cwd'); } catch (e) { return null; } })();
    const p1s = rd('/proc/1/status');
    out.proc1_status = p1s ? p1s.split('\n').filter((l: string) => /^(Name|Pid|PPid|Cap|Seccomp)/.test(l)) : null;
    // environ keys of pid1
    const p1env = rd('/proc/1/environ');
    out.proc1_envKeys = p1env ? p1env.split('\0').map((x: string) => x.split('=')[0]).slice(0, 40) : null;
    // 全进程列表
    try {
        out.pids = fs.readdirSync('/proc').filter(x => /^\d+$/.test(x)).map(pid => {
            const c = rd(`/proc/${pid}/cmdline`);
            const st = rd(`/proc/${pid}/status`);
            const name = st ? (st.split('\n').find((l: string) => l.startsWith('Name')) || '').trim() : '';
            return { pid, name, cmd: c ? (c as string).replace(/\0/g, ' ').trim().slice(0, 100) : '' };
        });
    } catch (e: any) { out.pidsErr = String(e.message); }
    // runtime 端口（环境变量）
    out.env_runtime = { FAAS: process.env._FAAS_RUNTIME_PORT, BYTEFAAS: process.env._BYTEFAAS_RUNTIME_PORT, POD: process.env.MY_POD_NAME, SANDBOX_PARAMS: (process.env._FAAS_CREATE_SANDBOX_PARAMS || '').slice(0, 300) };
    ctx.body = out;
});

// E4: /dev 全枚举 + 关键设备节点 + 内核指纹
router.get('/api/probe/dev', async (ctx) => {
    const out: any = {};
    try { out.dev = fs.readdirSync('/dev'); } catch (e: any) { out.devErr = String(e.message); }
    const checks = ['/dev/fuse', '/dev/vsock', '/dev/vhost-vsock', '/dev/kmsg', '/dev/mem', '/dev/vfio', '/dev/console', '/dev/ttyS0', '/proc/kcore', '/proc/keys', '/sys/kernel/debug', '/sys/kernel/tracing', '/sys/fs/fuse/connections', '/proc/sys/kernel/unprivileged_bpf_disabled', '/proc/sys/user/max_user_namespaces', '/proc/sys/kernel/unprivileged_userns_clone'];
    out.checks = {};
    for (const p of checks) {
        try { const st = fs.statSync(p); out.checks[p] = st.isDirectory() ? 'DIR' : (st.mode & 0o200 ? 'RW' : 'RO'); } catch (e) { out.checks[p] = 'no'; }
    }
    // kmsg 读一行（root）
    try { const fd = fs.openSync('/dev/kmsg', 'r'); const b = Buffer.alloc(400); const n = fs.readSync(fd, b, 0, 400, 0); fs.closeSync(fd); out.kmsgSample = b.slice(0, n).toString().slice(0, 300); } catch (e: any) { out.kmsg = 'FAIL: ' + String(e.message).slice(0, 60); }
    // uname / version
    try { out.uname = (await execFileP('uname', ['-a'])).stdout.trim(); } catch (e: any) { out.unameErr = String(e.message).slice(0, 80); }
    try { out.kernelVer = fs.readFileSync('/proc/version', 'utf8').trim(); } catch (e) {}
    // dmesg 尝试（CONFIG_SECURITY_DMESG_RESTRICT 或 cap_syslog）
    try { out.dmesgHead = (await execFileP('dmesg')).stdout.split('\n').slice(0, 25); } catch (e: any) { out.dmesg = 'FAIL: ' + String(e.message).slice(0, 100); }
    // cmdlin（宿主启动参数可能透传）
    try { out.bootCmdline = fs.readFileSync('/proc/cmdline', 'utf8').trim().slice(0, 400); } catch (e) {}
    ctx.body = out;
});

// E5: 本地端口探测（runtime API 攻击面——localhost only，不触内网）
router.get('/api/probe/local', async (ctx) => {
    const out: any = { ports: [] };
    const ports: Array<[string, number]> = [];
    const envPorts: Array<[string, number]> = [];
    for (const k of ['_FAAS_RUNTIME_PORT', '_BYTEFAAS_RUNTIME_PORT']) {
        const v = Number(process.env[k]);
        if (v) envPorts.push([k, v]);
    }
    for (const p of [80, 443, 8000, 8080, 8081, 9000, 9090, 1024, 6379, 2375, 2376, 10250, 10248, 4243]) ports.push(['common', p]);
    for (const [k, p] of envPorts) ports.push([k, p]);
    const probeTcp = (port: number) => new Promise((res) => {
        const s = net.connect({ port, host: '127.0.0.1', timeout: 1500 }, () => { s.destroy(); res('OPEN'); });
        s.on('error', (e: any) => res(String(e.code)));
        s.on('timeout', () => { s.destroy(); res('timeout'); });
    });
    const seen = new Set();
    for (const [k, p] of ports) {
        if (seen.has(p)) continue; seen.add(p);
        out.ports.push({ src: k, port: p, state: await probeTcp(p) });
    }
    // runtime port HTTP 探测
    for (const [k, p] of envPorts) {
        try {
            const r = await new Promise<any>((res) => {
                const req = http.get(`http://127.0.0.1:${p}/`, { timeout: 2000 }, (r2) => { let d = ''; r2.on('data', c => d += c); r2.on('end', () => res({ s: r2.statusCode, b: d.slice(0, 150) })); });
                req.on('error', (e: any) => res({ err: String(e.message).slice(0, 60) }));
                req.on('timeout', () => { req.destroy(); res({ err: 'timeout' }); });
            });
            out[`${k}_http`] = r;
        } catch (e: any) { out[`${k}_http`] = { err: String(e.message).slice(0, 60) }; }
    }
    ctx.body = out;
});

// E6: mount 可写性 + userns 实验（无害：mount tmpfs 到 /tmp 下）
router.get('/api/probe/mount', async (ctx) => {
    const out: any = {};
    try { out.unshareUr = (await execFileP('unshare', ['-Ur', 'id'])).stdout.trim(); } catch (e: any) { out.unshareUr = 'FAIL: ' + String(e.message).slice(0, 120); }
    try { out.unshareNet = (await execFileP('unshare', ['-n', 'true'])).stdout.trim() || 'OK'; } catch (e: any) { out.unshareNet = 'FAIL: ' + String(e.message).slice(0, 120); }
    try { const d = '/tmp/mtest' + Date.now(); fs.mkdirSync(d); out.mountTmpfs = (await execFileP('mount', ['-t', 'tmpfs', 'none', d])).stdout.trim() || 'OK'; try { fs.rmdirSync(d); } catch (e) {} } catch (e: any) { out.mountTmpfs = 'FAIL: ' + String(e.message).slice(0, 120); }
    // /proc/sys 可写抽查（core_pattern 只读检查，不写）
    try { fs.accessSync('/proc/sys/kernel/core_pattern', fs.constants.W_OK); out.corePatternWritable = 'YES'; } catch (e) { out.corePatternWritable = 'no'; }
    ctx.body = out;
});

app.use(bodyParser());
app.use(router.routes());
const PORT = 8000;
app.listen(PORT, () => { console.log(`Server running on port ${PORT}`); });

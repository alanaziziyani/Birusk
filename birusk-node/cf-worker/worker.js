import { connect } from "cloudflare:sockets";

let authCache = new Set();
let usageMap = new Map();
let lastSync = 0;
let lastUsageSync = 0;
let syncPromise = null;

async function syncConfig(env) {
    if (Date.now() - lastSync < 60000) return;
    if (syncPromise) return syncPromise;
    
    syncPromise = (async () => {
        try {
            const resp = await fetch(`${env.MASTER_URL}/api/sync`, {
                headers: { "Authorization": `Bearer ${env.NODE_TOKEN}` }
            });
            if (resp.ok) {
                const data = await resp.json();
                if (data.uuids && Array.isArray(data.uuids)) {
                    authCache = new Set(data.uuids.map(u => u.replace(/-/g, '').toLowerCase()));
                    lastSync = Date.now();
                    console.log(`[sync] ok, ${authCache.size} active uuid(s)`);
                }
            } else {
                console.error(`[sync] master returned ${resp.status}`);
            }
        } catch (e) {
            console.error(`[sync] failed: ${e.message}`);
        }
        syncPromise = null;
    })();
    
    return syncPromise;
}

async function flushUsage(env) {
    if (usageMap.size === 0) return;
    if (Date.now() - lastUsageSync < 60000) return;
    
    const payload = [];
    for (const [uid, bytes] of usageMap.entries()) {
        payload.push({ user_id: uid, bytes_used: bytes });
    }
    
    usageMap.clear();
    lastUsageSync = Date.now();

    try {
        const resp = await fetch(`${env.MASTER_URL}/api/usage`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${env.NODE_TOKEN}`
            },
            body: JSON.stringify(payload)
        });
        if (!resp.ok) {
            for (const item of payload) {
                recordUsage(item.user_id, item.bytes_used);
            }
        }
    } catch (e) {
        for (const item of payload) {
            recordUsage(item.user_id, item.bytes_used);
        }
    }
}

function recordUsage(uuid, bytes) {
    if (!uuid) return;
    const current = usageMap.get(uuid) || 0;
    usageMap.set(uuid, current + bytes);
}

function formatUUID(hex) {
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

export default {
    async fetch(request, env, ctx) {
        try {
            const upgrade = request.headers.get("Upgrade");
            if (!upgrade || upgrade.toLowerCase() !== "websocket") {
                return new Response("Birusk Edge Node Active ⚡", { status: 200 });
            }

            if (authCache.size === 0) {
                await syncConfig(env);
            } else {
                ctx.waitUntil(syncConfig(env));
            }
            
            ctx.waitUntil(flushUsage(env));

            const webSocketPair = new WebSocketPair();
            const client = webSocketPair[0];
            const ws = webSocketPair[1];
            
            ws.accept();

            let remoteSocket = null;
            let isFirstChunk = true;
            let currentUserId = null;

            const cleanup = () => {
                if (remoteSocket) {
                    try { remoteSocket.close(); } catch (e) {}
                    remoteSocket = null;
                }
            };

            ws.addEventListener("close", () => cleanup());
            ws.addEventListener("error", () => cleanup());

            ws.addEventListener("message", async (e) => {
              try {
                const data = e.data;

                if (!(data instanceof ArrayBuffer)) {
                    // یه فریم متنی یا هرچیز غیرمنتظره؛ پروتکل ما فقط باینریه
                    ws.close();
                    return;
                }
                
                if (isFirstChunk) {
                    isFirstChunk = false;
                    const view = new Uint8Array(data);
                    
                    if (data.byteLength < 24 || view[0] !== 0) {
                        console.error("[conn] bad header (too short or wrong version)");
                        ws.close(); 
                        return; 
                    }
                    
                    const currentUserHex = Array.from(view.slice(1, 17)).map(b => b.toString(16).padStart(2, "0")).join("");
                    
                    if (!authCache.has(currentUserHex)) {
                        console.error(`[conn] auth rejected for uuid hex ${currentUserHex} (cache size ${authCache.size})`);
                        ws.close(); 
                        return;
                    }
                    
                    currentUserId = formatUUID(currentUserHex);
                    recordUsage(currentUserId, data.byteLength);

                    const optLen = view[17];
                    const pPos = 18 + optLen + 1;
                    
                    if (data.byteLength <= pPos + 2) {
                        ws.close();
                        return;
                    }
                    
                    const port = new DataView(data.slice(pPos, pPos + 2)).getUint16(0);
                    const aType = view[pPos + 2];
                    
                    let vPos = pPos + 3;
                    let aLen = 0;
                    let targetAddr = "";

                    if (vPos >= view.length) {
                        ws.close();
                        return;
                    }
                    
                    if (aType === 1) {
                        aLen = 4;
                        if (vPos + aLen > view.length) { ws.close(); return; }
                        targetAddr = view.slice(vPos, vPos + aLen).join(".");
                    } else if (aType === 2) {
                        aLen = view[vPos];
                        vPos++;
                        if (vPos + aLen > view.length) { ws.close(); return; }
                        targetAddr = new TextDecoder().decode(view.slice(vPos, vPos + aLen));
                    } else if (aType === 3) {
                        aLen = 16;
                        if (vPos + aLen > view.length) { ws.close(); return; }
                        const dv = new DataView(data.slice(vPos, vPos + aLen));
                        targetAddr = Array.from({ length: 8 }, (_, i) => dv.getUint16(i * 2).toString(16)).join(":");
                    } else {
                        ws.close();
                        return;
                    }
                    
                    try {
                        ws.send(new Uint8Array([0, 0]));
                    } catch (err) {
                        cleanup();
                        return;
                    }
                    
                    try {
                        remoteSocket = connect({ hostname: targetAddr, port: port });
                        await remoteSocket.opened;
                        console.log(`[conn] connected to ${targetAddr}:${port}`);
                        
                        const offset = vPos + aLen;
                        if (offset < data.byteLength) {
                            const writer = remoteSocket.writable.getWriter();
                            await writer.write(data.slice(offset));
                            writer.releaseLock();
                        }
                        
                        const trackingStream = new TransformStream({
                            transform(chunk, controller) {
                                recordUsage(currentUserId, chunk.byteLength);
                                controller.enqueue(chunk);
                            }
                        });
                        
                        remoteSocket.readable.pipeThrough(trackingStream).pipeTo(new WritableStream({
                            write(chunk) {
                                try {
                                    if (ws.readyState === 1) {
                                        ws.send(chunk);
                                    }
                                } catch (err) {
                                    console.error(`[conn] ws.send failed: ${err.message}`);
                                    cleanup();
                                }
                            }
                        })).catch((err) => {
                            console.error(`[conn] remote->client pipe ended: ${err.message}`);
                            cleanup();
                        });
                        
                    } catch (err) {
                        console.error(`[conn] connect to ${targetAddr}:${port} failed: ${err.message}`);
                        ws.close();
                        cleanup();
                    }
                } else if (remoteSocket) {
                    recordUsage(currentUserId, data.byteLength);
                    try {
                        const writer = remoteSocket.writable.getWriter();
                        await writer.write(data);
                        writer.releaseLock();
                    } catch (err) {
                        ws.close();
                        cleanup();
                    }
                }
                
                ctx.waitUntil(flushUsage(env));
              } catch (err) {
                // هر خطای پیش‌بینی‌نشده‌ای توی پارس کردن پکت (بسته‌ی خراب/کوتاه) دیگه
                // کانکشن رو با خطای بی‌صدا نمی‌ندازه، فقط تمیز می‌بندش
                cleanup();
                try { ws.close(); } catch (e2) {}
              }
            });

            return new Response(null, { status: 101, webSocket: client });
        } catch (err) {
            return new Response("Internal Error", { status: 500 });
        }
    }
}
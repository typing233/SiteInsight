const urlInput = document.getElementById('url-input');
const analyzeBtn = document.getElementById('analyze-btn');
const loading = document.getElementById('loading');
const errorBanner = document.getElementById('error-banner');
const results = document.getElementById('results');

urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') startAnalysis();
});

async function startAnalysis() {
    const url = urlInput.value.trim();
    if (!url) {
        showError('请输入目标网址');
        return;
    }

    loading.classList.remove('hidden');
    results.classList.add('hidden');
    errorBanner.classList.add('hidden');
    analyzeBtn.disabled = true;

    try {
        const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });

        if (resp.status === 429) {
            showError('请求过于频繁，请稍后再试（限制：每分钟10次）');
            return;
        }

        if (!resp.ok) {
            showError(`服务器错误: ${resp.status}`);
            return;
        }

        const data = await resp.json();

        if (data.error) {
            showError(data.error);
            return;
        }

        renderResults(data);
    } catch (e) {
        showError(`请求失败: ${e.message}`);
    } finally {
        loading.classList.add('hidden');
        analyzeBtn.disabled = false;
    }
}

function showError(msg) {
    errorBanner.textContent = msg;
    errorBanner.classList.remove('hidden');
    loading.classList.add('hidden');
    analyzeBtn.disabled = false;
}

function renderResults(data) {
    results.classList.remove('hidden');
    renderDNS(data.dns);
    renderTLS(data.tls);
    renderCookies(data.cookies);
    renderWhois(data.whois);
    renderGeoIP(data.geoip);
    renderPerformance(data.performance);
}

function setStatus(id, success) {
    const badge = document.getElementById(`status-${id}`);
    badge.className = 'status-badge ' + (success ? 'success' : 'error');
    badge.textContent = success ? '成功' : '失败';
}

function renderDNS(module) {
    setStatus('dns', module.success);
    const body = document.getElementById('body-dns');

    if (!module.success) {
        body.innerHTML = `<p class="error-msg">${module.error}</p>`;
        return;
    }

    const data = module.data;
    let html = '';
    const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA'];

    for (const type of types) {
        const records = data[type];
        if (!records || records.length === 0) continue;

        html += `<div class="record-group"><h4>${type} 记录</h4><ul>`;
        for (const r of records) {
            if (typeof r === 'object') {
                if (type === 'MX') {
                    html += `<li>优先级 ${r.priority} → ${r.exchange}</li>`;
                } else if (type === 'SOA') {
                    html += `<li>主NS: ${r.mname}<br>邮箱: ${r.rname}<br>序列号: ${r.serial}</li>`;
                }
            } else {
                html += `<li>${escapeHtml(r)}</li>`;
            }
        }
        html += '</ul></div>';
    }

    body.innerHTML = html || '<p class="error-msg">未找到DNS记录</p>';
}

function renderTLS(module) {
    setStatus('tls', module.success);
    const body = document.getElementById('body-tls');

    if (!module.success) {
        body.innerHTML = `<p class="error-msg">${module.error}</p>`;
        return;
    }

    const d = module.data;
    let html = '<table>';

    if (d.valid !== undefined) {
        html += `<tr><td>证书有效</td><td>${d.valid ? '✓ 有效' : '✗ 无效'}</td></tr>`;
    }
    if (d.subject) {
        html += `<tr><td>主题</td><td>${formatObj(d.subject)}</td></tr>`;
    }
    if (d.issuer) {
        html += `<tr><td>颁发者</td><td>${formatObj(d.issuer)}</td></tr>`;
    }
    if (d.not_before) {
        html += `<tr><td>生效时间</td><td>${d.not_before}</td></tr>`;
    }
    if (d.not_after) {
        html += `<tr><td>过期时间</td><td>${d.not_after}</td></tr>`;
    }
    if (d.signature_algorithm) {
        html += `<tr><td>签名算法</td><td>${escapeHtml(d.signature_algorithm)}</td></tr>`;
    }
    if (d.san && d.san.length > 0) {
        html += `<tr><td>SAN</td><td>${d.san.map(escapeHtml).join('<br>')}</td></tr>`;
    }
    if (d.fingerprint_sha256) {
        html += `<tr><td>SHA256指纹</td><td style="word-break:break-all;font-family:monospace;font-size:0.75rem">${d.fingerprint_sha256}</td></tr>`;
    }
    if (d.validation_error) {
        html += `<tr><td>错误</td><td class="error-msg">${escapeHtml(d.validation_error)}</td></tr>`;
    }

    html += '</table>';
    body.innerHTML = html;
}

function renderCookies(module) {
    setStatus('cookies', module.success);
    const body = document.getElementById('body-cookies');

    if (!module.success) {
        body.innerHTML = `<p class="error-msg">${module.error}</p>`;
        return;
    }

    const cookies = module.data;
    if (!cookies || cookies.length === 0) {
        body.innerHTML = '<p>该网站未设置Cookie</p>';
        return;
    }

    let html = '';
    for (const c of cookies) {
        if (c.error) {
            html += `<p class="error-msg">${escapeHtml(c.error)}</p>`;
            continue;
        }
        html += `<div class="cookie-item">`;
        html += `<strong>${escapeHtml(c.name)}</strong> = ${escapeHtml(c.value ? c.value.substring(0, 60) : '')}${c.value && c.value.length > 60 ? '...' : ''}`;
        if (c.attributes && Object.keys(c.attributes).length > 0) {
            html += '<br><small>';
            const attrs = Object.entries(c.attributes)
                .map(([k, v]) => v === true ? k : `${k}=${v}`)
                .join('; ');
            html += escapeHtml(attrs);
            html += '</small>';
        }
        html += '</div>';
    }

    body.innerHTML = html;
}

function renderWhois(module) {
    setStatus('whois', module.success);
    const body = document.getElementById('body-whois');

    if (!module.success) {
        body.innerHTML = `<p class="error-msg">${module.error}</p>`;
        return;
    }

    const d = module.data;
    const fields = [
        ['域名', 'domain_name'],
        ['注册商', 'registrar'],
        ['注册时间', 'creation_date'],
        ['到期时间', 'expiration_date'],
        ['更新时间', 'updated_date'],
        ['域名服务器', 'name_servers'],
        ['状态', 'status'],
        ['注册人', 'registrant'],
        ['组织', 'org'],
        ['国家', 'country'],
    ];

    let html = '<table>';
    for (const [label, key] of fields) {
        let val = d[key];
        if (val === null || val === undefined) continue;
        if (Array.isArray(val)) val = val.join('<br>');
        html += `<tr><td>${label}</td><td>${escapeHtml(String(val))}</td></tr>`;
    }
    html += '</table>';
    body.innerHTML = html;
}

function renderGeoIP(module) {
    setStatus('geoip', module.success);
    const body = document.getElementById('body-geoip');

    if (!module.success) {
        body.innerHTML = `<p class="error-msg">${module.error}</p>`;
        return;
    }

    const d = module.data;
    let html = '<table>';
    const fields = [
        ['IP 地址', d.ip],
        ['国家', `${d.country || '-'} (${d.country_code || '-'})`],
        ['地区', d.region],
        ['城市', d.city],
        ['经度', d.longitude],
        ['纬度', d.latitude],
        ['时区', d.timezone],
        ['邮编', d.postal_code],
    ];

    for (const [label, val] of fields) {
        if (val === null || val === undefined) continue;
        html += `<tr><td>${label}</td><td>${escapeHtml(String(val))}</td></tr>`;
    }
    html += '</table>';
    body.innerHTML = html;
}

function renderPerformance(module) {
    setStatus('performance', module.success);
    const body = document.getElementById('body-performance');

    if (!module.success) {
        body.innerHTML = `<p class="error-msg">${module.error}</p>`;
        return;
    }

    const d = module.data;
    let html = '';
    const metrics = [
        ['HTTP 状态码', d.status_code],
        ['总加载时间', `${d.total_time_ms} ms`],
        ['响应头大小', `${d.response_headers_size_bytes} bytes`],
        ['内容大小', formatBytes(d.content_length)],
        ['最终URL', d.url_final],
        ['重定向次数', d.redirects],
        ['HTTP 版本', d.http_version],
        ['服务器', d.server],
        ['内容类型', d.content_type],
    ];

    for (const [label, val] of metrics) {
        if (val === null || val === undefined) continue;
        html += `<div class="metric"><span class="label">${label}</span><span class="value">${escapeHtml(String(val))}</span></div>`;
    }

    body.innerHTML = html;
}

function formatObj(obj) {
    return Object.entries(obj)
        .map(([k, v]) => `${k}=${escapeHtml(v)}`)
        .join(', ');
}

function formatBytes(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

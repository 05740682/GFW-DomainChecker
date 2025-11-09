export default {
  async fetch(request, env, ctx) {
    try {
      if (!env.kv) {
        return ResponseHelper.html(generateKVErrorPage());
      }

      const url = new URL(request.url);
      if (url.pathname === '/admin') {
        return handleAdminPage(request, env);
      }

      const sites = await ConfigManager.getSites(env);
      if (sites.length === 0) {
        return ResponseHelper.redirect(new URL('/admin', request.url).toString());
      }

      const siteStatuses = await checkAllSitesStatus(sites, request);
      return ResponseHelper.html(generateHTML(siteStatuses));

    } catch (error) {
      return ResponseHelper.error('服务器内部错误');
    }
  }
};

const PasswordHelper = {
  async hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  async verifyPassword(password, hashedPassword) {
    const hashedInput = await this.hashPassword(password);
    return hashedInput === hashedPassword;
  }
};

const SecurityHelper = {
  async isRateLimited(env, request) {
    const attemptKey = 'LOGIN_ATTEMPTS';
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const oneHourAgo = Date.now() - 60 * 60 * 1000;

    let attempts = await env.kv.get(attemptKey);
    attempts = attempts ? JSON.parse(attempts) : [];

    const recentAttempts = attempts.filter(attempt =>
      attempt.ip === ip && attempt.timestamp > oneHourAgo
    );

    return recentAttempts.length >= 5;
  },

  async recordLoginAttempt(env, request) {
    const attemptKey = 'LOGIN_ATTEMPTS';
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const timestamp = Date.now();

    let attempts = await env.kv.get(attemptKey);
    attempts = attempts ? JSON.parse(attempts) : [];

    attempts.push({ ip, timestamp });
    const oneHourAgo = timestamp - 60 * 60 * 1000;
    attempts = attempts.filter(attempt => attempt.timestamp > oneHourAgo);

    await env.kv.put(attemptKey, JSON.stringify(attempts), { expirationTtl: 3600 });
  },

  async resetLoginAttempts(env) {
    await env.kv.delete('LOGIN_ATTEMPTS');
  }
};

async function checkAllSitesStatus(sites, request) {
  return await Promise.all(sites.map(site => checkSingleSiteStatus(site, request)));
}

async function checkSingleSiteStatus(site, request) {
  try {
    const currentHostname = new URL(request.url).hostname;
    const targetHostname = new URL(site.url).hostname;

    if (currentHostname === targetHostname) {
      return { ...site, status: 'online', statusCode: 200, statusText: '正常 (当前站点)' };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(site.url, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Status-Check/1.0)' },
      cf: { cacheEverything: false, polish: 'off', country: 'CN' }
    });

    clearTimeout(timeoutId);

    const isOnline = response.status === 200;
    return {
      ...site,
      status: isOnline ? 'online' : 'offline',
      statusCode: response.status,
      statusText: isOnline ? '正常' : '离线'
    };
  } catch (error) {
    return {
      ...site,
      status: 'offline',
      statusCode: 0,
      statusText: error.name === 'AbortError' ? '请求超时' : '被墙或网络错误'
    };
  }
}

async function getCurrentUrls(env) {
  try {
    const config = await env.kv.get('SITES_CONFIG');
    return config ? JSON.parse(config).join('\n') : '';
  } catch {
    return '';
  }
}

async function handleAdminPage(request, env) {
  const storedHashedPassword = await env.kv.get('ADMIN_PASSWORD_HASH');

  if (!storedHashedPassword) {
    if (request.method === 'POST') {
      const formData = await request.formData();
      if (formData.get('action') === 'set_password') {
        const newPassword = formData.get('new_password');
        const confirmPassword = formData.get('confirm_password');

        if (newPassword && newPassword === confirmPassword) {
          if (newPassword.length < 8) {
            return ResponseHelper.html(generatePasswordSetupPage('密码长度至少8位'));
          }

          const hashedPassword = await PasswordHelper.hashPassword(newPassword);
          await env.kv.put('ADMIN_PASSWORD_HASH', hashedPassword);
          const currentUrls = await getCurrentUrls(env);
          return ResponseHelper.html(generateAdminPage('密码设置成功！', currentUrls));
        }
        return ResponseHelper.html(generatePasswordSetupPage('密码设置失败：两次输入的密码不一致'));
      }
    }
    return ResponseHelper.html(generatePasswordSetupPage());
  }

  if (request.method === 'POST') {
    const formData = await request.formData();
    const action = formData.get('action');

    if (action === 'login') {
      if (await SecurityHelper.isRateLimited(env, request)) {
        return ResponseHelper.html(generatePasswordLoginPage('尝试次数过多，请1小时后再试'));
      }

      const inputPassword = formData.get('password');
      const isValid = await PasswordHelper.verifyPassword(inputPassword, storedHashedPassword);

      if (!isValid) {
        await SecurityHelper.recordLoginAttempt(env, request);
        return ResponseHelper.html(generatePasswordLoginPage('密码错误，请重新输入'));
      }

      await SecurityHelper.resetLoginAttempts(env);
      const currentUrls = await getCurrentUrls(env);
      return ResponseHelper.html(generateAdminPage('登录成功！', currentUrls));
    }

    if (action === 'save') {
      try {
        await ConfigManager.saveSites(env, formData.get('urls'));
        return ResponseHelper.redirect(new URL('/', request.url).toString());
      } catch (error) {
        const currentUrls = await getCurrentUrls(env);
        return ResponseHelper.html(generateAdminPage('保存失败：' + error.message, currentUrls));
      }
    }
  }

  return ResponseHelper.html(generatePasswordLoginPage());
}

function generateAdminPage(message = '', currentUrls = '') {
  const siteCount = currentUrls ? currentUrls.split('\n').filter(url => url.trim()).length : 0;

  const styles = BASE_STYLES + `.container{max-width:700px}textarea{width:100%;height:250px;padding:20px;border:2px solid rgba(0,150,255,.4);border-radius:12px;font-family:'Courier New',monospace;background:rgba(0,30,60,.6);color:#e0f7ff;font-size:16px;resize:vertical;transition:all .3s ease}textarea:focus{outline:none;border-color:#00b4d8;box-shadow:0 0 0 3px rgba(0,180,216,.3),0 0 20px rgba(0,150,255,.3)}textarea::placeholder{color:rgba(224,247,255,.6)}button{background:linear-gradient(135deg,#0077b6 0%,#00b4d8 100%);color:#000814;border:none;padding:15px 30px;border-radius:25px;cursor:pointer;margin:10px;font-size:16px;font-weight:600;transition:all .3s ease;min-width:150px}button:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,.3),0 0 30px rgba(0,180,216,.4);background:linear-gradient(135deg,#00b4d8 0%,#0077b6 100%)}button.home{background:linear-gradient(135deg,#00b4d8 0%,#0096c7 100%)}button.home:hover{background:linear-gradient(135deg,#0096c7 0%,#00b4d8 100%)}.current-count{color:rgba(224,247,255,.9);font-size:16px;margin-top:10px;font-weight:600}.instructions{background:rgba(0,30,60,.6);padding:20px;border-radius:10px;margin:20px 0;text-align:left;font-size:14px;line-height:1.5;color:#b3e0ff}.button-group{display:flex;justify-content:center;gap:15px;flex-wrap:wrap;margin:25px 0}.form-group{margin-bottom:25px}label{display:block;font-size:18px;margin-bottom:12px;font-weight:600;color:rgba(224,247,255,.95)}`;

  const content = `<div class="toast-container" id="toastContainer"></div><div class="container"><h1>网站管理</h1><form method="POST"><div class="form-group"><label for="urls">网站域名列表（每行一个域名）</label><textarea id="urls" name="urls" placeholder="请输入网站域名，每行一个">${currentUrls}</textarea><div class="current-count">当前配置：${siteCount} 个网站</div></div><div class="instructions"><strong>使用说明：</strong><br>• 每行输入一个域名（不需要输入 http:// 或 https://）<br>• 保存配置后将自动返回主页面<br>• 清空所有内容并保存可以删除所有网站</div><div class="button-group"><button type="submit" name="action" value="save">💾 保存配置</button><button type="button" onclick="window.location.href='/'" class="home">🏠 返回主页</button></div></form></div>`;

  const script = getAdminPageScript() + (message ? `setTimeout(()=>showToast('${message}',${message.includes('失败')}),100);` : '');

  return generatePage('网站管理', content, styles, script);
}

function generateHTML(sites) {
  const beijingTime = getBeijingTime();
  const siteCards = generateSiteCards(sites);

  const styles = `*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;position:relative;overflow-x:hidden;background:linear-gradient(135deg,#000814 0%,#001d3d 50%,#003566 100%);user-select:text;-webkit-user-select:text;-moz-user-select:text;-ms-user-select:text}.geometric-bg{position:fixed;top:0;left:0;width:100%;height:100%;z-index:-1;opacity:.4}.container{max-width:1200px;width:100%;text-align:center;z-index:1}.header{margin-bottom:40px;text-shadow:2px 2px 4px rgba(0,0,0,.3)}.header h1{font-size:3rem;margin-bottom:10px;background:linear-gradient(135deg,#00b4d8 0%,#0077b6 50%,#0096c7 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:700;letter-spacing:1px;text-shadow:0 2px 10px rgba(0,0,0,.2)}.nav-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(400px,1fr));gap:25px;margin-top:30px;width:100%}.nav-card{background:rgba(0,20,40,.8);border-radius:20px;padding:25px;color:#e0f7ff;transition:all .3s ease;box-shadow:0 10px 30px rgba(0,0,0,.3),0 0 20px rgba(0,150,255,.2);border:1px solid rgba(0,200,255,.4);position:relative;backdrop-filter:blur(10px);display:flex;flex-direction:column;height:100%}.nav-card:hover{transform:translateY(-5px);box-shadow:0 20px 40px rgba(0,0,0,.4),0 0 40px rgba(0,180,216,.3);background:rgba(0,20,40,.9);border-color:rgba(0,200,255,.6)}.card-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px;position:relative}.card-header h3{font-size:1.4rem;margin:0;color:#f0f7ff;text-align:left;font-weight:600;flex:1;padding-right:40px}.status-indicator{position:absolute;top:0;right:0;display:flex;align-items:center;gap:8px}.status-dot{width:20px;height:20px;border-radius:50%;display:inline-block;border:2px solid rgba(255,255,255,.3)}.status-indicator.online .status-dot{background:#00d500;box-shadow:0 0 10px rgba(0,255,0,.5)}.status-indicator.offline .status-dot{background:#d50000;box-shadow:0 0 10px rgba(255,0,0,.5)}.card-content{flex:1;display:flex;flex-direction:column;gap:15px}.url-display{display:flex;align-items:center;gap:10px;background:rgba(0,30,60,.6);border:1px solid rgba(0,150,255,.3);border-radius:12px;padding:15px;font-family:'Courier New',monospace;font-size:.9rem;color:#c0e7ff;cursor:default}.url-icon{font-size:1.2rem}.status-details{display:flex;flex-direction:column;gap:8px;background:rgba(0,30,60,.6);padding:15px;border-radius:12px;border:1px solid rgba(0,150,255,.3)}.status-item{display:flex;justify-content:space-between;align-items:center;font-size:.85rem}.status-label{color:#a0d0ff;font-weight:500}.status-value{font-weight:600;padding:2px 8px;border-radius:6px;font-size:.8rem}.status-value.success{background:rgba(0,255,0,.15);color:#00ff00}.status-value.error{background:rgba(255,0,0,.15);color:#ff0000}.card-footer{display:flex;justify-content:space-between;align-items:center;margin-top:20px;padding-top:15px;border-top:1px solid rgba(0,150,255,.3)}.visit-time{font-size:.8rem;color:#a0d0ff}.visit-btn{background:linear-gradient(135deg,#0077b6 0%,#00b4d8 100%);color:#000814;border:none;padding:10px 20px;border-radius:8px;font-size:.9rem;font-weight:600;cursor:pointer;transition:all .3s ease}.visit-btn:hover{transform:translateY(-2px);box-shadow:0 5px 15px rgba(0,180,216,.4)}.footer{margin-top:50px;color:#e0f7ff;opacity:.7;font-size:.9rem;text-shadow:1px 1px 2px rgba(0,0,0,.3)}.last-update{margin-top:10px;font-size:.8rem;opacity:.6}@media (max-width:768px){.nav-grid{grid-template-columns:1fr}.header h1{font-size:2.2rem}.nav-card{padding:20px}.card-header h3{padding-right:35px}.status-dot{width:18px;height:18px}}`;

  const content = `<canvas class="geometric-bg" id="geometricBg"></canvas><div class="container"><div class="header"><h1>网站导航 - 状态监控</h1></div><div class="nav-grid">${siteCards}</div><div class="footer"><p>Powered by Cloudflare Workers</p><div class="last-update">最后检查时间: ${beijingTime}</div></div></div>`;

  return generatePage('网站导航 - 状态监控', content, styles, getMainScript());
}

function generateKVErrorPage() {
  const styles = BASE_STYLES + `p{font-size:1.1rem;color:#b3e0ff;line-height:1.6}`;
  const content = `<div class="container"><h1>❌ KV空间未绑定</h1><p>请检查Cloudflare Workers的KV命名空间绑定配置</p></div>`;
  return generatePage('错误 - KV空间未绑定', content, styles);
}

function generatePage(title, content, styles, scripts = '') {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title}</title><style>${styles}</style></head>
<body>${content}${scripts ? `<script>${scripts}</script>` : ''}</body>
</html>`;
}

function generatePasswordLoginPage(message = '') {
  const styles = BASE_STYLES + `input{width:100%;padding:15px;border:2px solid rgba(0,150,255,.4);border-radius:10px;background:rgba(0,30,60,.6);color:#e0f7ff;font-size:16px;margin-bottom:20px;transition:all .3s ease}input:focus{outline:none;border-color:#00b4d8;box-shadow:0 0 0 3px rgba(0,180,216,.3),0 0 20px rgba(0,150,255,.3)}input::placeholder{color:rgba(224,247,255,.6)}button{background:linear-gradient(135deg,#0077b6 0%,#00b4d8 100%);color:#000814;border:none;padding:15px 30px;border-radius:25px;cursor:pointer;width:100%;font-size:16px;font-weight:600;transition:all .3s ease}button:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,.3),0 0 30px rgba(0,180,216,.4);background:linear-gradient(135deg,#00b4d8 0%,#0077b6 100%)}`;

  const content = `<div class="toast-container" id="toastContainer"></div><div class="container"><h1>🔐 管理认证</h1><form method="POST"><input type="password" name="password" placeholder="请输入管理密码" required><button type="submit" name="action" value="login">进入管理页面</button></form></div>`;

  const toastScript = `function showToast(e,t=!1){const n=document.getElementById("toastContainer"),o=document.createElement("div");const i=e.length>15;o.className="toast"+(t?" error":"")+(i?" multiline":""),o.textContent=e,n.appendChild(o),setTimeout(()=>{o.parentNode&&o.parentNode.removeChild(o)},5e3)}`;
  const messageScript = message ? `setTimeout(()=>showToast('${message}',${message.includes('错误')}),100);` : '';

  return generatePage('管理认证', content, styles, toastScript + messageScript);
}

function generatePasswordSetupPage(message = '') {
  const styles = BASE_STYLES + `input{width:100%;padding:15px;border:2px solid rgba(0,150,255,.4);border-radius:10px;background:rgba(0,30,60,.6);color:#e0f7ff;font-size:16px;margin-bottom:20px;transition:all .3s ease}input:focus{outline:none;border-color:#00b4d8;box-shadow:0 0 0 3px rgba(0,180,216,.3),0 0 20px rgba(0,150,255,.3)}input::placeholder{color:rgba(224,247,255,.6)}button{background:linear-gradient(135deg,#0077b6 0%,#00b4d8 100%);color:#000814;border:none;padding:15px 30px;border-radius:25px;cursor:pointer;width:100%;font-size:16px;font-weight:600;transition:all .3s ease}button:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(0,0,0,.3),0 0 30px rgba(0,180,216,.4);background:linear-gradient(135deg,#00b4d8 0%,#0077b6 100%)}.instructions{background:rgba(0,30,60,.6);padding:15px;border-radius:10px;margin:20px 0;text-align:left;font-size:14px;line-height:1.5;color:#b3e0ff}`;

  const content = `<div class="toast-container" id="toastContainer"></div><div class="container"><h1>🔐 首次设置</h1><form method="POST"><input type="password" name="new_password" placeholder="设置管理密码" required><input type="password" name="confirm_password" placeholder="确认管理密码" required><div class="instructions"><strong>注意：</strong><br>• 请牢记您设置的密码<br>• 每次访问管理页面都需要输入密码</div><button type="submit" name="action" value="set_password">设置密码</button></form></div>`;

  const toastScript = `function showToast(e,t=!1){const n=document.getElementById("toastContainer"),o=document.createElement("div");const i=e.length>15;o.className="toast"+(t?" error":"")+(i?" multiline":""),o.textContent=e,n.appendChild(o),setTimeout(()=>{o.parentNode&&o.parentNode.removeChild(o)},5e3)}`;
  const messageScript = message ? `setTimeout(()=>showToast('${message}',${message.includes('失败')}),100);` : '';

  return generatePage('首次设置 - 网站管理', content, styles, toastScript + messageScript);
}

function generateSiteCards(sites) {
  return sites.map(site => `
    <div class="nav-card">
      <div class="card-header">
        <h3>${site.name}</h3>
        <div class="status-indicator ${site.status}">
          <span class="status-dot"></span>
        </div>
      </div>
      <div class="card-content">
        <div class="url-display">
          <span class="url-icon">🌐</span>
          <span class="url-text">${site.displayUrl}</span>
        </div>
        <div class="status-details">
          <div class="status-item">
            <span class="status-label">状态码:</span>
            <span class="status-value ${site.statusCode === 200 ? 'success' : 'error'}">${site.statusCode}</span>
          </div>
          <div class="status-item">
            <span class="status-label">详情:</span>
            <span class="status-value">${site.statusText}</span>
          </div>
        </div>
      </div>
      <div class="card-footer">
        <span class="visit-time">${getBeijingTime().split(' ')[1]}</span>
        <button class="visit-btn" onclick="window.open('${site.url}', '_blank')">访问网站 →</button>
      </div>
    </div>
  `).join('');
}

function getAdminPageScript() {
  return `function showToast(e,t=!1){const n=document.getElementById("toastContainer"),o=document.createElement("div");const i=e.length>15;o.className="toast"+(t?" error":"")+(i?" multiline":""),o.textContent=e,n.appendChild(o),setTimeout(()=>{o.parentNode&&o.parentNode.removeChild(o)},5e3)}const e=document.getElementById("urls");e&&(e.addEventListener("input",function(){const e=this.value.split("\\n").length;this.style.height="auto",this.style.height=Math.min(Math.max(20*e+40,250),400)+"px";const t=this.value.split("\\n").filter(e=>e.trim()).length,o=this.nextElementSibling;o&&o.classList.contains("current-count")&&(o.textContent="当前配置："+t+" 个网站")}),setTimeout(()=>{const e=new Event("input");e.dispatchEvent(e)},100));`;
}

function getBeijingTime() {
  const now = new Date();
  const beijingTime = new Date(now.getTime() + (8 * 60 * 60 * 1000));

  const year = beijingTime.getUTCFullYear();
  const month = String(beijingTime.getUTCMonth() + 1).padStart(2, '0');
  const day = String(beijingTime.getUTCDate()).padStart(2, '0');
  const hours = String(beijingTime.getUTCHours()).padStart(2, '0');
  const minutes = String(beijingTime.getUTCMinutes()).padStart(2, '0');
  const seconds = String(beijingTime.getUTCSeconds()).padStart(2, '0');

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} (北京时间)`;
}

function getMainScript() {
  return `function createGeometricBackground(){const e=document.getElementById("geometricBg"),t=e.getContext("2d");function n(){e.width=window.innerWidth,e.height=window.innerHeight}n(),window.addEventListener("resize",n);const o=[],i=["rgba(0, 180, 216, 0.15)","rgba(0, 119, 182, 0.12)","rgba(0, 150, 199, 0.10)","rgba(0, 100, 255, 0.08)","rgba(255, 107, 107, 0.06)","rgba(224, 247, 255, 0.04)"];for(let a=0;a<Math.max(80,Math.floor((e.width*e.height)/8000));a++)o.push({x:Math.random()*e.width,y:Math.random()*e.height,size:Math.random()*30+15,type:Math.floor(4*Math.random()),color:i[Math.floor(Math.random()*i.length)],rotation:2*Math.PI*Math.random(),speed:.3*Math.random()+.05,connections:[],pulse:2*Math.PI*Math.random()});function r(){for(let a=0;a<o.length;a++){o[a].connections=[];for(let e=a+1;e<o.length;e++){const t=o[a].x-o[e].x,i=o[a].y-o[e].y,l=Math.sqrt(t*t+i*i);l<150&&(o[a].connections.push(e),o[e].connections.push(a))}}}function l(){t.clearRect(0,0,e.width,e.height),t.strokeStyle="rgba(0, 180, 216, 0.1)",t.lineWidth=.8;for(let a=0;a<o.length;a++)for(const n of o[a].connections){const i=o[a].x-o[n].x,l=o[a].y-o[n].y,c=Math.sqrt(i*i+l*l),d=Math.max(.05,1-c/150);t.strokeStyle="rgba(0, 180, 216,"+.1*d+")",t.beginPath(),t.moveTo(o[a].x,o[a].y),t.lineTo(o[n].x,o[n].y),t.stroke()}for(const a of o){t.save(),t.translate(a.x,a.y),t.rotate(a.rotation);const n=1+.2*Math.sin(a.pulse);a.pulse+=.02,t.scale(n,n),t.fillStyle=a.color;switch(a.type){case 0:t.beginPath(),t.arc(0,0,a.size/2,0,2*Math.PI),t.fill();break;case 1:t.beginPath(),t.moveTo(0,-a.size/2),t.lineTo(a.size/2,a.size/2),t.lineTo(-a.size/2,a.size/2),t.closePath(),t.fill();break;case 2:t.fillRect(-a.size/2,-a.size/2,a.size,a.size);break;case 3:t.beginPath();for(let e=0;e<6;e++){const t=2*e*Math.PI/6,n=a.size/2*Math.cos(t),o=a.size/2*Math.sin(t);0===e?t.moveTo(n,o):t.lineTo(n,o)}t.closePath(),t.fill()}t.restore(),a.x+=Math.cos(a.rotation)*a.speed,a.y+=Math.sin(a.rotation)*a.speed,(a.x<-2*a.size)&&(a.x=e.width+2*a.size),(a.x>e.width+2*a.size)&&(a.x=-2*a.size),(a.y<-2*a.size)&&(a.y=e.height+2*a.size),(a.y>e.height+2*a.size)&&(a.y=-2*a.size),a.rotation+=.001}Math.random()<.02&&r(),requestAnimationFrame(l)}r(),l()}document.addEventListener("DOMContentLoaded",createGeometricBackground);`;
}

const BASE_STYLES = `*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:30px;background:linear-gradient(135deg,#000814 0%,#001d3d 50%,#003566 100%);color:#e0f7ff;text-align:center}.container{max-width:500px;width:100%;background:rgba(0,20,40,.8);padding:40px;border-radius:20px;backdrop-filter:blur(15px);box-shadow:0 15px 35px rgba(0,0,0,.4),0 0 50px rgba(0,150,255,.2);border:1px solid rgba(0,200,255,.4)}h1{font-size:2rem;margin-bottom:25px;background:linear-gradient(135deg,#00b4d8 0%,#0077b6 50%,#0096c7 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;font-weight:700;text-shadow:0 0 20px rgba(0,180,216,.5)}.toast-container{position:fixed;bottom:20px;right:20px;z-index:1000}.toast{background:rgba(0,20,40,.95);color:#e0f7ff;padding:15px 20px;border-radius:10px;margin-bottom:10px;box-shadow:0 5px 15px rgba(0,0,0,.3),0 0 20px rgba(0,150,255,.2);border-left:4px solid #00b4d8;border:1px solid rgba(0,200,255,.3);animation:slideIn .3s ease,fadeOut .3s ease 4.7s forwards;max-width:400px;min-width:300px;font-weight:600;white-space:nowrap;overflow:visible;text-overflow:unset}.toast.multiline{white-space:normal;word-wrap:break-word;min-width:350px;max-width:500px}.toast.error{border-left-color:#ff6b6b;border-color:rgba(255,107,107,.3)}@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}@keyframes fadeOut{from{opacity:1}to{opacity:0}}`;

const ConfigManager = {
  async getSites(env) {
    try {
      const config = await env.kv.get('SITES_CONFIG');
      if (!config) return [];

      return JSON.parse(config).map((url, index) => ({
        name: `网站 ${index + 1}`,
        url: 'https://' + url,
        displayUrl: url,
      }));
    } catch {
      return [];
    }
  },

  async saveSites(env, urlText) {
    const urls = urlText.split('\n')
      .map(url => url.trim())
      .filter(url => url)
      .map(url => url.replace(/^https?:\/\//, '').split('/')[0]);

    await env.kv.put('SITES_CONFIG', JSON.stringify(urls));
    return urls;
  }
};

const ResponseHelper = {
  html(content, status = 200) {
    return new Response(content, {
      status,
      headers: { 'Content-Type': 'text/html; charset=UTF-8' }
    });
  },

  redirect(url, status = 302) {
    return Response.redirect(url, status);
  },

  error(message, status = 500) {
    return new Response(message, { status });
  }
};
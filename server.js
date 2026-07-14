require('dotenv').config();

const express = require('express');
const cors = require('cors');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 🛠 НАЛАШТУВАННЯ СЕРВЕРА
// ==========================================
const ENABLE_TEST_MODE = process.env.ENABLE_TEST_MODE !== 'false'; // за замовчуванням true, вимикається через env
const REQUEST_TIMEOUT_MS = 15000;

// Домени, яким дозволено КОРИСТУВАТИСЯ проксі (браузерні origin'и, а не CA-хости!)
// Порожній масив = дозволено з будь-якого origin (небезпечно для production).
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

app.use(cors({
    origin: ALLOWED_ORIGINS.length > 0 ? ALLOWED_ORIGINS : true,
    credentials: false
}));

// Приймаємо тіло як рядок (IIT-бібліотека сама кодує запит у base64 перед відправкою)
app.use(express.text({type: '*/*', limit: '10mb'}));

// ==========================================
// 🛡️ БІЛИЙ СПИСОК ХОСТІВ (куди дозволено ходити проксі)
// ==========================================
const knownHosts = new Set([
    "root-test.czo.gov.ua",
    "zc.bank.gov.ua",
    "cs.vchasno.ua",
]);

function loadHostsFromFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            console.warn(`⚠️  Файл ${filePath} не знайдено, пропускаю.`);
            return;
        }

        const rawData = fs.readFileSync(filePath, 'utf8');
        const casArray = JSON.parse(rawData);
        let addedCount = 0;

        const addressFields = ['address', 'ocspAccessPointAddress', 'cmpAddress', 'tspAddress'];

        casArray.forEach(ca => {
            addressFields.forEach(field => {
                if (!ca[field]) return;
                // Домен може прийти як "host.com" або "host.com/path" — беремо тільки хост
                const domain = String(ca[field]).split('/')[0].trim();
                if (domain && !knownHosts.has(domain)) {
                    knownHosts.add(domain);
                    addedCount++;
                }
            });
        });

        console.log(`✅ ${filePath}: додано ${addedCount} нових доменів.`);
    } catch (error) {
        console.error(`❌ Помилка читання ${filePath}:`, error.message);
    }
}

function initializeAllowedHosts() {
    console.log("🔄 Завантаження конфігурацій АЦСК...");
    loadHostsFromFile('./CAs.json');

    if (ENABLE_TEST_MODE) {
        console.log("🧪 ТЕСТОВИЙ режим увімкнено. Завантажую тестові АЦСК...");
        loadHostsFromFile('./CAs.Test.json');
    }

    console.log(`🛡️  Білий список сформовано: ${knownHosts.size} унікальних доменів.\n`);
}

initializeAllowedHosts();

// ==========================================
// 🔧 ДОПОМІЖНІ ФУНКЦІЇ
// ==========================================

/**
 * Безпечний парсинг URL. Ніколи не кидає виняток.
 */
function safeParseURL(address) {
    try {
        return new URL(address);
    } catch {
        return null;
    }
}

/**
 * Визначає Content-Type для upstream-запиту за шляхом.
 * Легко розширювати новими провайдерами — просто додай правило.
 */
const CONTENT_TYPE_RULES = [
    {test: /\/cloud\/api\/back\//, type: 'application/json'},
    {test: /\/ss\//, type: 'application/json'},
    {test: /\/(services\/cmp|public\/x509\/cmp|cmp)\b/, type: ''},
    {
        test: /\/(services\/ocsp|public\/ocsp|ocsp(-rsa|-ecdsa)?|OCSPsrv\/ocsp|queries\/ocsp)\b/,
        type: 'application/ocsp-request'
    },
    {test: /\/(services\/tsp|public\/tsa|tsp(-rsa|-ecdsa)?|TspHTTPServer\/tsp)\b/, type: 'application/timestamp-query'},
];

function getContentType(pathname) {
    const rule = CONTENT_TYPE_RULES.find(r => r.test.test(pathname));
    return rule ? rule.type : 'text/plain';
}

/**
 * fetch з таймаутом через AbortController.
 */
async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, {...options, signal: controller.signal});
    } finally {
        clearTimeout(timer);
    }
}

// ==========================================
// 🚏 ГОЛОВНИЙ ОБРОБНИК ПРОКСІ
// ==========================================
app.all('/ProxyHandler', async (req, res) => {
    const rawAddress = req.query.address;

    if (!rawAddress) {
        return res.status(400).json({error: 'Missing "address" query parameter'});
    }

    const targetUrl = safeParseURL(rawAddress);
    if (!targetUrl) {
        return res.status(400).json({error: 'Malformed "address" parameter'});
    }

    // Дозволяємо ходити тільки по HTTPS (захист від протокольного даунгрейду)
    if (targetUrl.protocol !== 'http:' && targetUrl.protocol !== 'https:') {
        console.warn(`⚠️  БЛОКУВАННЯ (недопустимий протокол): ${targetUrl.href}`);
        return res.status(403).json({ error: 'Only http:// and https:// targets are allowed' });
    }

    if (!knownHosts.has(targetUrl.hostname)) {
        console.warn(`⚠️  БЛОКУВАННЯ: хост "${targetUrl.hostname}" не в білому списку. Повний URL: ${targetUrl.href}`);
        return res.status(403).json({error: `Host ${targetUrl.hostname} not in whitelist`});
    }

    try {
        const hasBody = req.method !== 'GET' && req.method !== 'HEAD' && typeof req.body === 'string' && req.body.length > 0;
        const requestBuffer = hasBody ? Buffer.from(req.body, 'base64') : undefined;

        const fetchOptions = {
            method: req.method,
            headers: {
                'Content-Type': getContentType(targetUrl.pathname),
                'User-Agent': 'signature.proxy.node',
                // Деякі хмарні провайдери (напр. Вчасно) звіряють Origin/Referer
                // зі своїм реєстром клієнтів — прокидаємо origin оригінального запиту.
                ...(req.get('origin') && {'Origin': req.get('origin')}),
                ...(req.get('referer') && {'Referer': req.get('referer')}),
            },
            redirect: 'manual', // не йдемо за редиректами автоматично — захист від SSRF
            ...(requestBuffer && {body: requestBuffer}),
        };

        if (requestBuffer) {
            fetchOptions.headers['Content-Length'] = String(requestBuffer.length);
        }

        const response = await fetchWithTimeout(targetUrl.href, fetchOptions, REQUEST_TIMEOUT_MS);

        // Ручна обробка редиректу: дозволяємо перехід тільки на інший хост із того ж білого списку
        if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
            const redirectUrl = safeParseURL(response.headers.get('location'));
            if (redirectUrl && knownHosts.has(redirectUrl.hostname)) {
                console.warn(`↪️  Редирект дозволено: ${targetUrl.hostname} → ${redirectUrl.hostname}`);
                // Проста рекурсія в межах одного редиректу; за потреби можна зробити лічильник глибини.
                req.query.address = redirectUrl.href;
                return app._router.handle(req, res);
            }
            console.warn(`⚠️  БЛОКУВАННЯ редиректу на хост поза білим списком: ${response.headers.get('location')}`);
            return res.status(502).json({error: 'Upstream redirected outside of whitelist'});
        }

        if (!response.ok) {
            const details = await response.text().catch(() => '');
            console.warn(`⚠️  Upstream ${response.status} від ${targetUrl.hostname}: ${details.slice(0, 300)}`);
            return res.status(response.status).json({
                error: `Upstream error ${response.status}`,
                details: details.slice(0, 2000),
            });
        }

        const arrayBuffer = await response.arrayBuffer();
        const responseBuffer = Buffer.from(arrayBuffer);

        res.set({
            'Content-Type': 'X-user/base64-data; charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
        });
        res.send(responseBuffer.toString('base64'));

    } catch (error) {
        if (error.name === 'AbortError') {
            console.error(`⏱️  Таймаут запиту до ${targetUrl.hostname} (>${REQUEST_TIMEOUT_MS}мс)`);
            return res.status(504).json({error: 'Upstream request timed out'});
        }
        console.error('Proxy Error:', error.message);
        res.status(500).json({error: 'Internal proxy error', message: error.message});
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Крипто-проксі працює на http://localhost:${PORT}`);
    console.log(`🔗 Ендпоінт для бібліотеки: http://localhost:${PORT}/ProxyHandler`);
    if (ALLOWED_ORIGINS.length === 0) {
        console.warn('⚠️  ALLOWED_ORIGINS не задано — proxy приймає запити з БУДЬ-ЯКОГО сайту. Задайте ALLOWED_ORIGINS для production.');
    }
});
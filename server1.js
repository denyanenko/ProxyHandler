const express = require('express');
const cors = require('cors');
const fs = require('fs');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.text({ type: '*/*', limit: '10mb' }));

// ==========================================
// 🛠 НАЛАШТУВАННЯ СЕРВЕРА
// ==========================================
// Змініть на false, коли будете викладати на реальний сервер (Production)
const ENABLE_TEST_MODE = true;

const knownHosts = new Set([
    "root-test.czo.gov.ua",
    "zc.bank.gov.ua",
    "cs.vchasno.ua",


]);

// Універсальна функція для читання будь-якого файлу конфігурації
function loadHostsFromFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) {
            console.warn(`⚠️ Попередження: Файл ${filePath} не знайдено.`);
            return;
        }

        const rawData = fs.readFileSync(filePath, 'utf8');
        const casArray = JSON.parse(rawData);
        let addedCount = 0;

        casArray.forEach(ca => {
            const addressFields = ['address', 'ocspAccessPointAddress', 'cmpAddress', 'tspAddress'];

            addressFields.forEach(field => {
                if (ca[field]) {
                    const domain = ca[field].split('/')[0];
                    if (domain && !knownHosts.has(domain)) {
                        knownHosts.add(domain);
                        addedCount++;
                    }
                }
            });
        });

        console.log(`✅ ${filePath}: додано ${addedCount} нових доменів.`);
    } catch (error) {
        console.error(`❌ Помилка читання ${filePath}:`, error.message);
    }
}

// Головна функція ініціалізації білого списку
function initializeAllowedHosts() {
    console.log("🔄 Завантаження конфігурацій АЦСК...");

    // 1. Завжди вантажимо бойові сервери
    loadHostsFromFile('./CAs.json');

    // 2. Якщо увімкнено тестовий режим — довантажуємо тестові
    if (ENABLE_TEST_MODE) {
        console.log("🧪 Увімкнено ТЕСТОВИЙ режим. Завантажую тестові АЦСК...");
        loadHostsFromFile('./CAs.Test.json');
    }

    console.log(`🛡️ Білий список сформовано! Всього унікальних доменів: ${knownHosts.size}\n`);
}

// Запускаємо формування списку при старті сервера
initializeAllowedHosts();

// Функція перевірки (залишається без змін)
function isKnownHost(address) {
    try {
        const url = new URL(address);
        return knownHosts.has(url.hostname);
    } catch (e) {
        return false;
    }
}

// Функція визначення правильного заголовка (Content-Type)
function getContentType(address) {
    try {
        const url = new URL(address);
        const path = url.pathname;

        if (path.includes('/cloud/api/back/')) return 'application/json';
        if (path.includes('/ss/')) return 'application/json';
        if (path.match(/\/(services\/cmp|public\/x509\/cmp|cmp)\b/)) return '';
        if (path.match(/\/(services\/ocsp|public\/ocsp|ocsp|ocsp-rsa|ocsp-ecdsa|OCSPsrv\/ocsp|queries\/ocsp)\b/)) return 'application/ocsp-request';
        if (path.match(/\/(services\/tsp|public\/tsa|tsp|tsp-rsa|tsp-ecdsa|TspHTTPServer\/tsp)\b/)) return 'application/timestamp-query';

        return 'text/plain';
    } catch (e) {
        return 'text/plain';
    }
}

// Головний обробник проксі
app.all('/ProxyHandler', async (req, res) => {
    const address = req.query.address;
    const libContentType = req.query.contentType; // те, що каже сама бібліотека

    if (!address) {
        return res.status(400).send('Bad Request: Missing address');
    }

    const hostname = new URL(address).hostname;
    if (!knownHosts.has(hostname)) {
        console.warn("⚠️ БЛОКУВАННЯ: Запит до невідомого хоста:", hostname);
        return res.status(403).send("Forbidden: Host " + hostname + " not in whitelist");
    }

    const isKSP = address.includes('/ss/') || address.includes('/cloud/api/back/');

    try {
        const requestBuffer = req.body && typeof req.body === 'string'
            ? Buffer.from(req.body, 'base64')
            : undefined;

        const fetchOptions = {
            method: req.method,
            headers: {
                // Спершу довіряємо тому, що каже бібліотека, інакше — своя евристика
                'Content-Type': libContentType || getContentType(address),
                'User-Agent': 'signature.proxy.node'
            }
        };

        if (req.method === 'POST' && requestBuffer) {
            fetchOptions.body = requestBuffer;
        }

        const response = await fetch(address, fetchOptions);
        const arrayBuffer = await response.arrayBuffer();
        const responseBuffer = Buffer.from(arrayBuffer);

        if (isKSP) {
            // КСП (Вчасно, хмарний підпис) — чистий passthrough, без base64
            res.status(response.status);
            res.setHeader('Content-Type', response.headers.get('content-type') || 'application/json');
            return res.send(responseBuffer);
        }

        // CA-ресурси (CRL/OCSP/CMP/TSP) — стара логіка з base64
        if (!response.ok) {
            return res.status(500).send(`Upstream Error: ${response.status}`);
        }
        res.setHeader('Content-Type', 'X-user/base64-data; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.send(responseBuffer.toString('base64'));

    } catch (error) {
        console.error('Proxy Error:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

app.listen(port, () => {
    console.log(`🚀 Крипто-проксі працює на http://localhost:${port}`);
    console.log(`🔗 Ендпоінт для бібліотеки: http://localhost:${port}/ProxyHandler`);
});

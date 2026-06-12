const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const fs = require('fs');

const PHONES_FILE = './phones.txt';
const MESSAGE_FILE = './message.txt';
const DELAY_MS = 3000; // 3 seconds between messages to avoid ban

function loadPhones() {
    if (!fs.existsSync(PHONES_FILE)) {
        console.error(`[ERROR] ${PHONES_FILE} not found`);
        process.exit(1);
    }
    return fs
        .readFileSync(PHONES_FILE, 'utf8')
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.length > 0 && !l.startsWith('#'));
}

function loadMessage() {
    if (!fs.existsSync(MESSAGE_FILE)) {
        console.error(`[ERROR] ${MESSAGE_FILE} not found`);
        process.exit(1);
    }
    return fs.readFileSync(MESSAGE_FILE, 'utf8').trim();
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Normalize phone: strip spaces/dashes, ensure no leading +
function toWhatsAppId(phone) {
    const digits = phone.replace(/[\s\-\(\)]/g, '').replace(/^\+/, '');
    return `${digits}@c.us`;
}

async function sendAll(client, phones, message) {
    console.log(`\n[INFO] Sending to ${phones.length} contacts...\n`);
    let ok = 0, fail = 0;

    for (let i = 0; i < phones.length; i++) {
        const phone = phones[i];
        const chatId = toWhatsAppId(phone);
        try {
            await client.sendMessage(chatId, message);
            console.log(`[${i + 1}/${phones.length}] ✓ Sent to ${phone}`);
            ok++;
        } catch (err) {
            console.log(`[${i + 1}/${phones.length}] ✗ Failed ${phone}: ${err.message}`);
            fail++;
        }
        if (i < phones.length - 1) await sleep(DELAY_MS);
    }

    console.log(`\n[DONE] Success: ${ok} | Failed: ${fail}`);
    await client.destroy();
    process.exit(0);
}

const client = new Client({
    authStrategy: new LocalAuth({ dataPath: '/app/.wwebjs_auth' }),
    puppeteer: {
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
        ],
        headless: true,
    },
});

client.on('qr', qr => {
    console.log('\n[SCAN] Scan this QR code with WhatsApp:\n');
    qrcode.generate(qr, { small: true });
});

client.on('authenticated', () => console.log('[AUTH] Authenticated!'));
client.on('auth_failure', msg => { console.error('[AUTH FAIL]', msg); process.exit(1); });

client.on('ready', async () => {
    console.log('[READY] WhatsApp client is ready.');
    const phones = loadPhones();
    const message = loadMessage();
    console.log(`[INFO] Message preview: "${message.substring(0, 80)}..."`);
    await sendAll(client, phones, message);
});

client.initialize();

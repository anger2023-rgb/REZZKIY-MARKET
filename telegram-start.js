import { timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const webhookPath = '/api/telegram/start';
const bannerPath = new URL('./start-banner.jpg', import.meta.url);

export function configureTelegramStart(app, siteUrl) {
  const secret = process.env.TELEGRAM_START_WEBHOOK_SECRET;
  if (!secret) return;

  if (!/^[A-Za-z0-9_-]{1,256}$/.test(secret)) {
    console.error('Telegram /start: invalid TELEGRAM_START_WEBHOOK_SECRET');
    return;
  }

  const expectedSecret = Buffer.from(secret);
  const webhookUrl = new URL(webhookPath, siteUrl).href;
  const apiUrl = 'https://api.telegram.org/bot' + process.env.BOT_TOKEN + '/';

  async function callTelegram(method, body) {
    const response = await fetch(apiUrl + method, {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(10000)
    });
    const result = await response.json();
    if (!response.ok || !result.ok) {
      throw new Error(method + ' failed with status ' + response.status);
    }
    return result.result;
  }

  app.post(webhookPath, async (req, res) => {
    const receivedSecret = Buffer.from(req.get('X-Telegram-Bot-Api-Secret-Token') || '');
    if (receivedSecret.length !== expectedSecret.length ||
        !timingSafeEqual(receivedSecret, expectedSecret)) {
      return res.sendStatus(403);
    }

    const message = req.body?.message;
    if (message?.chat?.type !== 'private' ||
        typeof message.text !== 'string' ||
        !/^\/start(?:@[A-Za-z0-9_]+)?(?:\s|$)/.test(message.text)) {
      return res.sendStatus(200);
    }

    try {
      const photo = await readFile(bannerPath);
      const form = new FormData();
      form.set('chat_id', String(message.chat.id));
      form.set('photo', new Blob([photo], { type: 'image/jpeg' }), 'start-banner.jpg');
      form.set('reply_markup', JSON.stringify({
        inline_keyboard: [[{
          text: 'Купить/продать скины',
          web_app: { url: siteUrl }
        }]]
      }));
      await callTelegram('sendPhoto', form);
      return res.sendStatus(200);
    } catch {
      console.error('Telegram /start: could not send banner');
      return res.sendStatus(502);
    }
  });

  return async function registerTelegramStart() {
    try {
      const info = await callTelegram('getWebhookInfo');
      if (info.url && info.url !== webhookUrl) {
        console.error('Telegram /start: another webhook is already configured');
        return;
      }

      await callTelegram('setWebhook', new URLSearchParams({
        url: webhookUrl,
        secret_token: secret,
        allowed_updates: JSON.stringify(['message'])
      }));
      console.log('Telegram /start webhook registered');
    } catch {
      console.error('Telegram /start: webhook registration failed');
    }
  };
}

import express from 'express';
import puppeteer from 'puppeteer';

const app = express();

app.get('/', async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', '*');
  res.set('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  const host = req.query.host;
  if (!host) {
    return res.status(400).send('Missing host query parameter example: /?host=example.com');
  }

  let browser = null;
  try {
    browser = await puppeteer.launch({
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();
    page.setUserAgent({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36' });
    await page.goto('https://www.digicert.com/help/?' + new URLSearchParams({ host }), { waitUntil: 'networkidle2' });
    const container = await page.$('.container');
    if (!container) {
      return res.status(404).send('Element .container not found');
    }
    const screenshotBase64 = await container.screenshot({ encoding: 'base64' });
    const screenshotDataUrl = `data:image/png;base64,${screenshotBase64}`;

    res.type('text/plain');
    res.send(screenshotDataUrl);

  } catch (error) {
    console.error(error);
    res.status(500).send('Error generating screenshot');
  } finally {
    if (browser) {
      await browser.close();
    }
  }
});

app.listen(8080);
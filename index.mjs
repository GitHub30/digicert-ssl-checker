import express from 'express';
import puppeteer from 'puppeteer';

const app = express();

app.get('/', async (req, res) => {
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
    const screenshot = await page.screenshot();

    res.set('Content-Type', 'image/png');
    res.send(screenshot);

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
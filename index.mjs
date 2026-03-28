import express from 'express';
import puppeteer from 'puppeteer';

const app = express();

app.get('/', async (req, res) => {
  let browser = null;
  try {
    browser = await puppeteer.launch({
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    const page = await browser.newPage();
    await page.goto('https://example.com');
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
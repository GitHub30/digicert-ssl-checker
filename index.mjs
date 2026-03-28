import express from 'express'
import puppeteer from 'puppeteer'

const app = express()

app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*')
  res.set('Access-Control-Allow-Methods', '*')
  res.set('Access-Control-Allow-Headers', '*')

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204)
  }

  next();
});

app.get('/', async (req, res) => {
  const host = req.query.host
  if (!host) {
    return res.sendStatus(204)
  }

  let browser = null
  try {
    browser = await puppeteer.launch({
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    })
    const page = await browser.newPage()
    page.setUserAgent({ userAgent: 'Mozilla/5.0 (Windows NT 10.0 Win64 x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36' })
    await page.goto('https://www.digicert.com/help/?' + new URLSearchParams({ host }), { waitUntil: 'networkidle2', timeout: 10000 })
    await page.addStyleTag({ content: 'header, #transcend-consent-manager { display: none !important }' })
    const container = await page.$('.container')
    if (!container) {
      return res.status(404).json({ error: 'Element .container not found', html: await page.content() })
    }

    const results = await page.$('#results')
    if (!results) {
      return res.status(404).json({ error: 'Element #results not found', html: await page.content() })
    }

    const screenshot = await container.screenshot({ encoding: 'base64' })
    const html = await page.$eval('#results', el => el.innerHTML)

    res.json({
      url: 'data:image/png;base64,' + screenshot,
      html
    })

  } catch (error) {
    console.error(error)
    res.status(500).json(error instanceof Error ? { message: error.message, stack: error.stack } : { error })
  } finally {
    if (browser) {
      await browser.close()
    }
  }
})

app.listen(8080)
import express from 'express'
import puppeteer from 'puppeteer'

const app = express()

app.get('/', async (req, res) => {
  res.set('Access-Control-Allow-Origin', '*')
  res.set('Access-Control-Allow-Methods', '*')
  res.set('Access-Control-Allow-Headers', '*')

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204)
  }

  const host = req.query.host
  if (!host) {
    return res.status(400).send('Missing host query parameter example: /?host=example.com')
  }

  let browser = null
  try {
    browser = await puppeteer.launch({
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    })

    const page = await browser.newPage()
    page.setUserAgent({ userAgent: 'Mozilla/5.0 (Windows NT 10.0 Win64 x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36' })
    await page.goto('https://www.digicert.com/help/?' + new URLSearchParams({ host }), { waitUntil: 'networkidle2' })
    await page.addStyleTag({ content: 'header, #transcend-consent-manager { display: none !important }' })
    const container = await page.$('.container')
    if (!container) {
      return res.status(404).send('Element .container not found')
    }

    const results = await page.$('.results')
    if (!results) {
      return res.status(404).send('Element .results not found')
    }

    const screenshot = await container.screenshot({ encoding: 'base64' })
    const html = await page.$eval('.results', (el) => el.innerHTML)

    res.json({
      url: 'data:image/png;base64,' + screenshot,
      html
    })

  } catch (error) {
    console.error(error)
    res.status(500).send(error.message)
  } finally {
    if (browser) {
      await browser.close()
    }
  }
})

app.listen(8080)
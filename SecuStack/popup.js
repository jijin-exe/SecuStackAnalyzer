document.addEventListener('DOMContentLoaded', async () => {
    const resultsDiv = document.getElementById('results');

    try {
        let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab || !tab.url || !tab.url.startsWith('http')) {
            resultsDiv.innerHTML = '<p>❌ <b>Restricted Page</b></p><p>Extensions cannot scan Chrome settings, New Tabs, or the Web Store. Please open a normal website and try again.</p>';
            return;
        }

        resultsDiv.innerHTML = `<p>⏳ Running Deep Stack Analysis & IP Resolution...</p>`;

        const urlObj = new URL(tab.url);
        const hostname = urlObj.hostname;

        const injectionResults = await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            world: "MAIN", 
            func: () => {
                const tech = {};
                const add = (category, name) => {
                    if (!tech[category]) tech[category] = [];
                    if (!tech[category].includes(name)) tech[category].push(name);
                };

                const html = document.documentElement.innerHTML.toLowerCase();
                const scripts = Array.from(document.scripts).map(s => s.src.toLowerCase());
                const links = Array.from(document.querySelectorAll('link')).map(l => l.href.toLowerCase());
                
                // JavaScript Frameworks & Libraries
                if (window.Vue || document.querySelector('[data-v-]')) add('JavaScript frameworks', 'Vue.js');
                if (window.React || document.querySelector('[data-reactroot]')) add('JavaScript frameworks', 'React');
                if (window.angular || document.querySelector('[ng-app]')) add('JavaScript frameworks', 'Angular');
                if (window.jQuery || scripts.some(s => s.includes('jquery'))) add('JavaScript libraries', 'jQuery');
                if (window.marked || scripts.some(s => s.includes('marked'))) add('JavaScript libraries', 'Marked');
                
                // FIX: Closure Library - Scrapes scripts for closure references
                if (window.goog || scripts.some(s => s.includes('closure'))) add('JavaScript libraries', 'Closure Library'); 
                
                // FIX: Analytics - Replaced false-positive checks with strict URL scraping
                if (window.ga || window.gtag || scripts.some(s => s.includes('google-analytics'))) add('Analytics', 'Google Analytics');
                if (scripts.some(s => s.includes('hotjar.com'))) add('Analytics', 'Hotjar'); // No more false positives!
                if (window.loglib || scripts.some(s => s.includes('loglib'))) add('Analytics', 'Loglib');
                
                // CMS & Ecommerce
                const metaGen = document.querySelector('meta[name="generator"]');
                const generator = metaGen ? metaGen.content.toLowerCase() : '';
                if (generator.includes('wordpress') || html.includes('wp-content')) add('CMS', 'WordPress');
                if (window.Shopify || html.includes('cdn.shopify.com')) add('Ecommerce', 'Shopify');

                // FIX: AWS - Scrapes all links, scripts, and raw HTML for Amazon AWS footprints
                if (scripts.some(s => s.includes('amazonaws.com')) || links.some(l => l.includes('amazonaws.com')) || html.includes('amazonaws.com')) {
                    add('PaaS', 'Amazon Web Services');
                }

                // Miscellaneous & Fonts
                if (document.querySelector('link[rel="manifest"]')) add('Miscellaneous', 'PWA');
                if (links.some(l => l.includes('fonts.googleapis.com'))) add('Font scripts', 'Google Font API');

                return tech;
            }
        });

        const clientTech = (injectionResults && injectionResults[0]) ? injectionResults[0].result : {};

        let ip = null;
        try {
            const dnsResponse = await fetch(`https://dns.google/resolve?name=${hostname}`);
            const dnsData = await dnsResponse.json();
            if (dnsData.Answer) {
                const aRecord = dnsData.Answer.find(record => record.type === 1);
                if (aRecord) ip = aRecord.data;
            }
        } catch(e) {
            console.log("DNS resolve failed");
        }

        let portsDisplay = 'OSINT disabled (Local)';
        let vulnsDisplay = 'N/A';
        let cpesDisplay = 'Unknown';
        
        if (ip && !ip.startsWith('127.') && !ip.startsWith('192.168.') && !ip.startsWith('10.')) {
            try {
                const shodanResponse = await fetch(`https://internetdb.shodan.io/${ip}`);
                if (shodanResponse.ok) {
                    const shodanData = await shodanResponse.json();
                    portsDisplay = (shodanData.ports && shodanData.ports.length > 0) ? shodanData.ports.join(', ') : 'None detected';
                    vulnsDisplay = (shodanData.vulns && shodanData.vulns.length > 0) ? shodanData.vulns.slice(0, 5).join(', ') : 'No known CVEs';
                    if (shodanData.cpes && shodanData.cpes.length > 0) {
                        const cpes = shodanData.cpes.map(cpe => cpe.replace('cpe:2.3:a:', '').replace('cpe:2.3:o:', '').split(':')[0]);
                        cpesDisplay = [...new Set(cpes)].slice(0, 4).join(', ');
                    }
                } else {
                    portsDisplay = 'No external data found';
                }
            } catch(e) {
                portsDisplay = 'OSINT connection failed';
            }
        }

        chrome.storage.session.get(tab.id.toString(), (data) => {
            const headersArray = data[tab.id] || [];
            const headers = {};
            headersArray.forEach(h => headers[h.name.toLowerCase()] = h.value);

            const server = headers['server'] || 'Hidden';
            const poweredBy = headers['x-powered-by'] || 'Hidden';
            
            // HTTP/3 from headers
            if (headers['alt-svc'] && headers['alt-svc'].includes('h3')) {
                if (!clientTech['Miscellaneous']) clientTech['Miscellaneous'] = [];
                clientTech['Miscellaneous'].push('HTTP/3');
            }

            // AWS from headers fallback
            if (server.toLowerCase().includes('amazon') || headers['x-amz-cf-id']) {
                if (!clientTech['PaaS']) clientTech['PaaS'] = [];
                if (!clientTech['PaaS'].includes('Amazon Web Services')) clientTech['PaaS'].push('Amazon Web Services');
            }

            let clientHtml = '';
            for (const [category, tools] of Object.entries(clientTech)) {
                clientHtml += `<p style="margin-bottom: 2px; color: #007bff;"><strong>${category}</strong></p><p style="margin-top: 0; background: none; border: none; padding: 0 0 10px 0;">${tools.join(', ')}</p>`;
            }
            if (clientHtml === '') clientHtml = '<p>No recognized client libraries.</p>';

            resultsDiv.innerHTML = `
                <h3>🌐 Target Network</h3>
                <p><strong>Hostname:</strong> ${hostname}</p>
                <p><strong>IP Address:</strong> ${ip || 'Unknown'}</p>

                <h3>💻 Client Tech Stack</h3>
                ${clientHtml}

                <h3>⚙️ Server-Side</h3>
                <p><strong>OSINT Server/OS:</strong> ${cpesDisplay !== 'Unknown' ? cpesDisplay : server}</p>
                <p><strong>Powered By:</strong> ${poweredBy}</p>

                <h3>🚪 Open Ports (OSINT)</h3>
                <p><strong>Ports:</strong> ${portsDisplay}</p>

                <h3>⚠️ Known Vulnerabilities</h3>
                <p style="color: ${vulnsDisplay.includes('CVE') ? '#721c24' : '#155724'}; font-weight: bold;">
                    ${vulnsDisplay}
                </p>
            `;
        });

    } catch (error) {
        resultsDiv.innerHTML = `<p>❌ <b>Crash Report:</b><br>${error.message}</p>`;
    }
});
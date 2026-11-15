
document.addEventListener("DOMContentLoaded", function () {

    // ==================================
    // 1. GET HTML ELEMENTS
    // ==================================

    const urlInput = document.getElementById("urlInput");
    const scanBtn = document.getElementById("scanBtn");
    const resultBox = document.getElementById("result");

    const status = document.getElementById("status");
    const scoreText = document.getElementById("score");
    const progressBar = document.getElementById("progressBar");
    const scannedUrl = document.getElementById("scannedUrl");
    const reasonsList = document.getElementById("reasons");
    const historyList = document.getElementById("historyList");

    // ==================================
    // 2. SCAN HISTORY
    // ==================================

    let scanHistory = [];

    try {
        scanHistory = JSON.parse(
            localStorage.getItem("phishguardHistory") || "[]"
        );

        if (!Array.isArray(scanHistory)) {
            scanHistory = [];
        }
    } catch {
        scanHistory = [];
    }

    // ==================================
    // 3. PERSON 2 - DETECTION LOGIC
    // ==================================

    function analyzeURL(input) {

        let score = 0;
        const reasons = [];

        const suspiciousWords = [
            "login", "verify", "update", "secure",
            "account", "banking", "password",
            "confirm", "wallet", "kyc",
            "payment", "claim", "reward"
        ];

        const shortenedDomains = [
            "bit.ly", "tinyurl.com", "t.co",
            "is.gd", "cutt.ly", "rb.gy"
        ];

        let url;

        try {

            let cleanURL = input.trim();

            if (!/^https?:\/\//i.test(cleanURL)) {
                cleanURL = "https://" + cleanURL;
            }

            url = new URL(cleanURL);

            if (!["http:", "https:"].includes(url.protocol)) {
                throw new Error("Unsupported protocol");
            }

            if (!url.hostname || !url.hostname.includes(".")) {
                throw new Error("Invalid hostname");
            }

        } catch {

            return {
                valid: false,
                score: 0,
                category: null,
                reasons: ["Please enter a valid website URL."]
            };

        }

        const hostname = url.hostname.toLowerCase();
        const fullURL = url.href.toLowerCase();

        // CHECK 1: HTTP

        if (url.protocol === "http:") {
            score += 15;
            reasons.push("The URL uses HTTP instead of HTTPS.");
        }

        // CHECK 2: IP ADDRESS

        const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;

        if (ipPattern.test(hostname)) {

            const validIP = hostname.split(".").every(part => {
                const number = Number(part);
                return number >= 0 && number <= 255;
            });

            if (validIP) {
                score += 25;
                reasons.push(
                    "The website uses an IP address instead of a domain name."
                );
            }
        }

        // CHECK 3: SUSPICIOUS KEYWORDS

        const matchedWords = suspiciousWords.filter(word =>
            fullURL.includes(word)
        );

        if (matchedWords.length > 0) {
            score += Math.min(matchedWords.length * 12, 36);

            reasons.push(
                "Suspicious keywords found: " + matchedWords.join(", ")
            );
        }

        // CHECK 4: LONG URL

        if (fullURL.length > 75) {
            score += 10;
            reasons.push("The URL is unusually long.");
        }

        // CHECK 5: SUBDOMAINS

        const subdomainCount = hostname.split(".").length - 2;

        if (subdomainCount >= 3) {
            score += 15;
            reasons.push("The URL contains multiple subdomains.");
        }

        // CHECK 6: @ SYMBOL

        if (url.href.includes("@")) {
            score += 25;
            reasons.push(
                "The URL contains an @ symbol, which may hide the actual destination."
            );
        }

        // CHECK 7: SHORTENED URL

        if (shortenedDomains.includes(hostname)) {
            score += 25;
            reasons.push(
                "The URL uses a known URL-shortening service."
            );
        }

        // CHECK 8: PUNYCODE

        if (hostname.includes("xn--")) {
            score += 25;
            reasons.push(
                "The domain contains encoded international characters."
            );
        }

        score = Math.min(score, 100);

        // RISK CLASSIFICATION

        let category;

        if (score >= 60) {
            category = "high";
        } else if (score >= 30) {
            category = "suspicious";
        } else {
            category = "low";
        }

        if (reasons.length === 0) {
            reasons.push(
                "No suspicious indicators were detected by these basic checks."
            );
        }

        return {
            valid: true,
            score: score,
            category: category,
            reasons: reasons,
            hostname: hostname
        };
    }

    // ==================================
    // 4. DISPLAY SCAN RESULT
    // ==================================

    function displayResult(url, analysis) {

        resultBox.classList.remove("hidden");

        scannedUrl.textContent = "Scanned URL: " + url;

        scoreText.textContent = analysis.score + "%";

        progressBar.style.width = "0%";
        progressBar.style.background = "";

        status.className = "";

        if (analysis.category === "low") {

            status.textContent = "✓ LOW RISK";
            status.classList.add("safe");
            progressBar.style.background = "#22c55e";

        } else if (analysis.category === "suspicious") {

            status.textContent = "⚠ SUSPICIOUS WEBSITE";
            status.classList.add("warning");
            progressBar.style.background = "#f59e0b";

        } else {

            status.textContent = "⚠ HIGH PHISHING RISK";
            status.classList.add("danger");
            progressBar.style.background = "#ef4444";

        }

        reasonsList.replaceChildren();

        analysis.reasons.forEach(reason => {

            const li = document.createElement("li");
            li.textContent = reason;
            reasonsList.appendChild(li);

        });

        requestAnimationFrame(() => {
            progressBar.style.width = analysis.score + "%";
        });
    }

    // ==================================
    // 5. SCAN URL
    // ==================================

    function scanURL() {

        const url = urlInput.value.trim();

        if (!url) {
            alert("Please enter a website URL!");
            return;
        }

        scanBtn.disabled = true;
        scanBtn.textContent = "Scanning...";

        try {

            const analysis = analyzeURL(url);

            if (!analysis.valid) {
                alert(analysis.reasons.join("\n"));
                return;
            }

            displayResult(url, analysis);

            // SAVE HISTORY

            scanHistory.unshift({
                url: url,
                score: analysis.score,
                category: analysis.category,
                date: new Date().toLocaleString()
            });

            scanHistory = scanHistory.slice(0, 10);

            try {
                localStorage.setItem(
                    "phishguardHistory",
                    JSON.stringify(scanHistory)
                );
            } catch (error) {
                console.warn("Could not save scan history:", error);
            }

            showHistory();

        } finally {

            scanBtn.disabled = false;
            scanBtn.textContent = "Scan URL";

        }
    }

    // ==================================
    // 6. DISPLAY HISTORY
    // ==================================

    function showHistory() {

        historyList.replaceChildren();

        if (scanHistory.length === 0) {

            const empty = document.createElement("p");
            empty.className = "empty";
            empty.textContent = "No scans performed yet.";

            historyList.appendChild(empty);
            return;
        }

        scanHistory.forEach(item => {

            const row = document.createElement("div");
            row.className = "history-item";

            const details = document.createElement("div");

            const website = document.createElement("p");
            website.className = "history-url";
            website.textContent = item.url;

            const date = document.createElement("small");
            date.textContent = item.date;

            details.append(website, date);

            const risk = document.createElement("strong");
            risk.textContent = item.score + "% risk";

            if (item.category === "high") {
                risk.style.color = "#f87171";
            } else if (item.category === "suspicious") {
                risk.style.color = "#fbbf24";
            } else {
                risk.style.color = "#4ade80";
            }

            row.append(details, risk);
            historyList.appendChild(row);

        });
    }

    // ==================================
    // 7. CLEAR HISTORY
    // ==================================

    function clearHistory() {

        scanHistory = [];

        localStorage.removeItem("phishguardHistory");

        showHistory();
    }

    // ==================================
    // 8. BUTTON EVENTS
    // ==================================

    scanBtn.addEventListener("click", scanURL);

    urlInput.addEventListener("keydown", function(event) {
        if (event.key === "Enter") {
            scanURL();
        }
    });

    document.querySelector(".clear-btn")
        .addEventListener("click", clearHistory);

    // MAKE FUNCTIONS AVAILABLE
    // FOR EXISTING HTML INLINE HANDLERS

    window.scanURL = scanURL;
    window.clearHistory = clearHistory;

    // INITIAL HISTORY

    showHistory();

});

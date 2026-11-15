
document.addEventListener("DOMContentLoaded", function () {

    // ==========================================
    // 1. MOBILE NAVIGATION
    // ==========================================

    const menuButton = document.getElementById("menuButton");
    const navLinks = document.getElementById("navLinks");

    if (menuButton && navLinks) {
        menuButton.addEventListener("click", function () {
            navLinks.classList.toggle("mobile-open");
            menuButton.textContent =
                navLinks.classList.contains("mobile-open") ? "✕" : "☰";
        });

        navLinks.querySelectorAll("a").forEach(link => {
            link.addEventListener("click", function () {
                navLinks.classList.remove("mobile-open");
                menuButton.textContent = "☰";
            });
        });
    }

    // ==========================================
    // 2. FRAUD AWARENESS CAROUSEL
    // ==========================================

    const deck = document.getElementById("fraudDeck");
    const nextButton = document.getElementById("nextFraud");
    const counter = document.getElementById("deckCounter");

    if (deck && nextButton && counter) {
        let cards = Array.from(deck.querySelectorAll(".fraud-card"));
        let currentIndex = 0;
        let isAnimating = false;

        function updateCards() {
            cards.forEach((card, index) => {
                card.classList.remove(
                    "active", "stack-1", "stack-2",
                    "stack-3", "moving-back"
                );

                card.classList.add(
                    index === 0 ? "active" : "stack-" + index
                );
            });

            counter.textContent =
                String(currentIndex + 1).padStart(2, "0") +
                " / " +
                String(cards.length).padStart(2, "0");
        }

        nextButton.addEventListener("click", function () {
            if (isAnimating || cards.length <= 1) return;

            isAnimating = true;

            const firstCard = cards[0];
            firstCard.classList.add("moving-back");

            setTimeout(function () {
                cards.push(cards.shift());
                deck.appendChild(firstCard);

                currentIndex = (currentIndex + 1) % cards.length;

                updateCards();
                isAnimating = false;
            }, 450);
        });

        if (cards.length > 0) updateCards();
    }

    // ==========================================
    // 3. SCANNER ELEMENTS
    // ==========================================

    const scanForm = document.getElementById("scanForm");
    const urlInput = document.getElementById("urlInput");
    const scanButton = document.getElementById("scanBtn");

    const resultContainer = document.getElementById("resultContainer");
    const riskPercent = document.getElementById("riskPercent");
    const riskBadge = document.getElementById("riskBadge");
    const riskTitle = document.getElementById("riskTitle");
    const riskDescription = document.getElementById("riskDescription");
    const riskProgress = document.getElementById("riskProgress");
    const riskReasons = document.getElementById("riskReasons");
    const resultNote = document.getElementById("resultNote");

    // ==========================================
    // 4. SCAN HISTORY
    // ==========================================

    let scanHistory = [];

    try {
        scanHistory = JSON.parse(
            localStorage.getItem("phishguardHistory") || "[]"
        );

        if (!Array.isArray(scanHistory)) {
            scanHistory = [];
        }
    } catch (error) {
        scanHistory = [];
    }

    let historySection = document.getElementById("historySection");

    if (!historySection && resultContainer && resultContainer.parentNode) {
        historySection = document.createElement("div");
        historySection.id = "historySection";
        historySection.className = "scan-history";

        historySection.innerHTML = `
            <div class="history-heading">
                <h3>Recent Scan History</h3>
                <button type="button" id="clearHistoryBtn">
                    Clear History
                </button>
            </div>
            <div id="historyList"></div>
        `;

        resultContainer.parentNode.appendChild(historySection);
    }

    const historyList = document.getElementById("historyList");
    const clearHistoryBtn = document.getElementById("clearHistoryBtn");

    function showHistory() {
        if (!historyList) return;

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

            risk.style.color =
                item.category === "high" ? "#ef4444" :
                item.category === "suspicious" ? "#f59e0b" :
                "#22c55e";

            row.append(details, risk);
            historyList.appendChild(row);
        });
    }

    function saveHistory(url, result) {
        scanHistory.unshift({
            url: url,
            score: result.score,
            category: result.category,
            date: new Date().toLocaleString()
        });

        scanHistory = scanHistory.slice(0, 10);

        try {
            localStorage.setItem(
                "phishguardHistory",
                JSON.stringify(scanHistory)
            );
        } catch (error) {
            console.warn("History could not be saved:", error);
        }

        showHistory();
    }

    function clearHistory() {
        scanHistory = [];

        try {
            localStorage.removeItem("phishguardHistory");
        } catch (error) {
            console.warn("History could not be cleared:", error);
        }

        showHistory();
        updateStatistics();
    }

    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener("click", clearHistory);
    }

    // ==========================================
    // 5. PERSON 2 - URL DETECTION LOGIC
    // ==========================================

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

            // Reject empty input and whitespace
            if (!cleanURL || /\s/.test(cleanURL)) {
                throw new Error("Invalid URL");
            }

            // Add HTTPS if protocol is missing
            if (!/^https?:\/\//i.test(cleanURL)) {
                cleanURL = "https://" + cleanURL;
            }

            // Reject duplicated URL patterns
            if (/^https?:\/\/[^/?#]+https?:\/\//i.test(cleanURL)) {
                throw new Error("Duplicated URL");
            }

            url = new URL(cleanURL);

            // Allow only HTTP and HTTPS
            if (!["http:", "https:"].includes(url.protocol)) {
                throw new Error("Unsupported protocol");
            }

            const hostname = url.hostname.toLowerCase();

            if (!hostname || hostname === "localhost") {
                throw new Error("Invalid hostname");
            }

            // Validate IPv4
            const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
            const isIP = ipPattern.test(hostname);

            if (isIP) {
                const validIP = hostname.split(".").every(part => {
                    const number = Number(part);
                    return number >= 0 && number <= 255;
                });

                if (!validIP) {
                    throw new Error("Invalid IP address");
                }
            } else {
                // Validate domain name
                const domainPattern =
                    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

                if (!domainPattern.test(hostname)) {
                    throw new Error("Invalid domain");
                }
            }

        } catch (error) {
            return {
                valid: false,
                score: 0,
                category: null,
                reasons: [
                    "Invalid URL. Please enter a complete and valid website address."
                ]
            };
        }

        const hostname = url.hostname.toLowerCase();
        const fullURL = url.href.toLowerCase();

        // Check 1: HTTP protocol
        if (url.protocol === "http:") {
            score += 15;
            reasons.push("The URL uses HTTP instead of HTTPS.");
        }

        // Check 2: IP address
        const ipPattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;

        if (ipPattern.test(hostname)) {
            score += 25;
            reasons.push(
                "The website uses an IP address instead of a domain name."
            );
        }

        // Check 3: Suspicious keywords
        const matchedWords = suspiciousWords.filter(word =>
            fullURL.includes(word)
        );

        if (matchedWords.length > 0) {
            score += Math.min(matchedWords.length * 12, 36);
            reasons.push(
                "Suspicious keywords found: " + matchedWords.join(", ")
            );
        }

        // Check 4: Long URL
        if (fullURL.length > 75) {
            score += 10;
            reasons.push("The URL is unusually long.");
        }

        // Check 5: Multiple subdomains
        const subdomainCount = hostname.split(".").length - 2;

        if (subdomainCount >= 3) {
            score += 15;
            reasons.push("The URL contains multiple subdomains.");
        }

        // Check 6: URL credentials
        if (url.username || url.password) {
            score += 25;
            reasons.push(
                "The URL contains credentials before the hostname."
            );
        }

        // Check 7: URL shortener
        if (shortenedDomains.includes(hostname)) {
            score += 25;
            reasons.push(
                "The URL uses a known URL-shortening service."
            );
        }

        // Check 8: Punycode
        if (hostname.includes("xn--")) {
            score += 25;
            reasons.push(
                "The domain contains encoded international characters."
            );
        }

        score = Math.min(score, 100);

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
            score,
            category,
            reasons,
            hostname
        };
    }

    // ==========================================
    // 6. DISPLAY SCAN RESULT
    // ==========================================

    function displayResult(result, enteredURL) {
        if (!resultContainer) return;

        resultContainer.hidden = false;

        riskPercent.textContent = result.score;
        riskProgress.style.width = "0%";

        riskBadge.className = "risk-badge";
        riskProgress.className = "progress-fill";

        if (!result.valid) {
            riskBadge.textContent = "INVALID URL";
            riskBadge.classList.add("high");

            riskTitle.textContent = "Invalid website address";
            riskDescription.textContent =
                "Please check the URL and try again.";

            resultNote.textContent =
                "A valid URL is required for this demo analysis.";
        } else {
            if (result.category === "low") {
                riskBadge.textContent = "LOW RISK";
                riskBadge.classList.add("low");
                riskTitle.textContent = "Low risk indicators";
                riskDescription.textContent =
                    "Few suspicious characteristics were detected.";

            } else if (result.category === "suspicious") {
                riskBadge.textContent = "SUSPICIOUS";
                riskBadge.classList.add("medium");
                riskTitle.textContent = "Suspicious URL detected";
                riskDescription.textContent =
                    "Some characteristics require extra attention.";
                riskProgress.classList.add("medium");

            } else {
                riskBadge.textContent = "HIGH RISK";
                riskBadge.classList.add("high");
                riskTitle.textContent = "High risk indicators";
                riskDescription.textContent =
                    "Several suspicious characteristics were detected.";
                riskProgress.classList.add("high");
            }

            riskDescription.textContent += " Scanned: " + enteredURL;

            resultNote.textContent =
                "This is a heuristic risk score, not a verified probability " +
                "or a guarantee that the website is safe or malicious.";
        }

        riskReasons.replaceChildren();

        result.reasons.forEach(reason => {
            const li = document.createElement("li");
            li.textContent = reason;
            riskReasons.appendChild(li);
        });

        if (result.valid) {
            requestAnimationFrame(() => {
                riskProgress.style.width = result.score + "%";
            });
        }
    }

    // ==========================================
    // 7. SCAN STATISTICS
    // ==========================================

    function updateStatistics() {
        const stats = {
            low: 0,
            suspicious: 0,
            high: 0
        };

        scanHistory.forEach(item => {
            if (Object.prototype.hasOwnProperty.call(stats, item.category)) {
                stats[item.category]++;
            }
        });

        const total =
            stats.low + stats.suspicious + stats.high;

        const totalElement = document.getElementById("totalScans");
        const safeCount = document.getElementById("safeCount");
        const suspiciousCount = document.getElementById("suspiciousCount");
        const dangerCount = document.getElementById("dangerCount");

        if (totalElement) totalElement.textContent = total;
        if (safeCount) safeCount.textContent = stats.low;
        if (suspiciousCount) suspiciousCount.textContent = stats.suspicious;
        if (dangerCount) dangerCount.textContent = stats.high;

        const safeBar = document.getElementById("safeBar");
        const suspiciousBar = document.getElementById("suspiciousBar");
        const dangerBar = document.getElementById("dangerBar");

        if (safeBar) {
            safeBar.style.width =
                (total ? stats.low / total * 100 : 0) + "%";
        }

        if (suspiciousBar) {
            suspiciousBar.style.width =
                (total ? stats.suspicious / total * 100 : 0) + "%";
        }

        if (dangerBar) {
            dangerBar.style.width =
                (total ? stats.high / total * 100 : 0) + "%";
        }
    }

    // ==========================================
    // 8. SCAN FORM EVENT
    // ==========================================

    if (scanForm && urlInput && scanButton && resultContainer) {
        scanForm.addEventListener("submit", function (event) {
            event.preventDefault();

            const enteredURL = urlInput.value.trim();

            if (!enteredURL) {
                alert("Please enter a website URL.");
                return;
            }

            scanButton.disabled = true;
            scanButton.textContent = "Analyzing...";
            resultContainer.hidden = true;

            setTimeout(function () {
                try {
                    const result = analyzeURL(enteredURL);

                    displayResult(result, enteredURL);

                    // Save only valid URLs
                    if (result.valid) {
                        saveHistory(enteredURL, result);
                        updateStatistics();
                    }

                    resultContainer.scrollIntoView({
                        behavior: "smooth",
                        block: "nearest"
                    });

                } catch (error) {
                    console.error("Scan error:", error);
                    alert("Something went wrong. Please try again.");

                } finally {
                    scanButton.disabled = false;
                    scanButton.textContent = "Analyze URL ↗";
                }
            }, 450);
        });
    }

    // ==========================================
    // 9. INITIALIZE
    // ==========================================

    showHistory();
    updateStatistics();

});

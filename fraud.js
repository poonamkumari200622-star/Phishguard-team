
document.addEventListener("DOMContentLoaded", function () {

    /* =================================
      
/* FRAUD AWARENESS CAROUSEL */

const deck = document.getElementById("fraudDeck");
const nextButton = document.getElementById("nextFraud");
const counter = document.getElementById("deckCounter");

if (deck && nextButton && counter) {

    let cards = Array.from(
        deck.querySelectorAll(".fraud-card")
    );

    let currentIndex = 0;
    let isAnimating = false;

    function updateCards() {

        cards.forEach((card, index) => {

            card.classList.remove(
                "active",
                "stack-1",
                "stack-2",
                "stack-3",
                "moving-back"
            );

            if (index === 0) {
                card.classList.add("active");
            } else {
                card.classList.add("stack-" + index);
            }
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

    updateCards();
}

    /* =================================
       2. MOBILE NAVIGATION
    ================================= */

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


    /* =================================
       3. SCAN STATISTICS
    ================================= */

    const scanStats = {
        low: 0,
        suspicious: 0,
        high: 0
    };

    function updateStatistics() {

        const total =
            scanStats.low +
            scanStats.suspicious +
            scanStats.high;

        document.getElementById("totalScans").textContent = total;

        document.getElementById("safeCount").textContent =
            scanStats.low;

        document.getElementById("suspiciousCount").textContent =
            scanStats.suspicious;

        document.getElementById("dangerCount").textContent =
            scanStats.high;

        const lowPercent = total
            ? (scanStats.low / total) * 100 : 0;

        const suspiciousPercent = total
            ? (scanStats.suspicious / total) * 100 : 0;

        const highPercent = total
            ? (scanStats.high / total) * 100 : 0;

        document.getElementById("safeBar").style.width =
            lowPercent + "%";

        document.getElementById("suspiciousBar").style.width =
            suspiciousPercent + "%";

        document.getElementById("dangerBar").style.width =
            highPercent + "%";
    }


    /* =================================
       4. URL RISK ANALYSIS
    ================================= */

    const scanForm = document.getElementById("scanForm");
    const urlInput = document.getElementById("urlInput");
    const scanButton = document.getElementById("scanBtn");

    const resultContainer =
        document.getElementById("resultContainer");

    const riskPercent =
        document.getElementById("riskPercent");

    const riskBadge =
        document.getElementById("riskBadge");

    const riskTitle =
        document.getElementById("riskTitle");

    const riskDescription =
        document.getElementById("riskDescription");

    const riskProgress =
        document.getElementById("riskProgress");

    const riskReasons =
        document.getElementById("riskReasons");

    const resultNote =
        document.getElementById("resultNote");


    function analyzeURL(input) {

        let score = 0;
        const reasons = [];

        const suspiciousWords = [
            "login",
            "verify",
            "update",
            "secure",
            "account",
            "banking",
            "password",
            "confirm",
            "wallet",
            "kyc",
            "payment",
            "claim",
            "reward"
        ];

        const shortenedDomains = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "cutt.ly",
            "rb.gy"
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

        } catch (error) {

            return {
                valid: false,
                score: 0,
                reasons: ["Please enter a valid website URL."]
            };
        }


        const hostname = url.hostname.toLowerCase();
        const fullURL = url.href.toLowerCase();


        // 1. HTTP instead of HTTPS

        if (url.protocol === "http:") {

            score += 15;

            reasons.push(
                "The URL uses HTTP instead of HTTPS."
            );
        }


        // 2. IP address instead of domain

        const ipPattern =
            /^(?:\d{1,3}\.){3}\d{1,3}$/;

        if (ipPattern.test(hostname)) {

            score += 25;

            reasons.push(
                "The website uses an IP address instead of a domain name."
            );
        }


        // 3. Suspicious keywords

        const matchedWords = suspiciousWords.filter(word =>
            fullURL.includes(word)
        );

        if (matchedWords.length > 0) {

            score += Math.min(matchedWords.length * 12, 36);

            reasons.push(
                "Suspicious keywords found: " +
                matchedWords.join(", ")
            );
        }


        // 4. Unusually long URL

        if (fullURL.length > 75) {

            score += 10;

            reasons.push(
                "The URL is unusually long."
            );
        }


        // 5. Many subdomains

        const subdomainCount = hostname.split(".").length - 2;

        if (subdomainCount >= 3) {

            score += 15;

            reasons.push(
                "The URL contains multiple subdomains."
            );
        }


        // 6. @ symbol

        if (url.href.includes("@")) {

            score += 25;

            reasons.push(
                "The URL contains an @ symbol, which may hide the actual destination."
            );
        }


        // 7. URL shorteners

        if (shortenedDomains.includes(hostname)) {

            score += 25;

            reasons.push(
                "The URL uses a known URL-shortening service."
            );
        }


        // 8. Punycode

        if (hostname.includes("xn--")) {

            score += 25;

            reasons.push(
                "The domain contains encoded international characters."
            );
        }


        // Keep score between 0 and 100

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
            score: score,
            category: category,
            reasons: reasons,
            hostname: hostname
        };
    }


    /* =================================
       5. DISPLAY SCAN RESULT
    ================================= */

    function displayResult(result) {

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

            riskReasons.innerHTML = "";

            result.reasons.forEach(reason => {
                const li = document.createElement("li");
                li.textContent = reason;
                riskReasons.appendChild(li);
            });

            resultNote.textContent =
                "A valid URL is required for this demo analysis.";

            return;
        }


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


        riskReasons.innerHTML = "";

        result.reasons.forEach(reason => {

            const li = document.createElement("li");

            li.textContent = reason;

            riskReasons.appendChild(li);
        });


        resultNote.textContent =
            "This is a heuristic risk score, not a verified probability " +
            "or a guarantee that the website is safe or malicious. " +
            "Do not enter sensitive information on unfamiliar websites.";


        requestAnimationFrame(() => {

            riskProgress.style.width = result.score + "%";

        });


        scanStats[result.category]++;

        updateStatistics();
    }


    /* =================================
       6. SCAN BUTTON EVENT
    ================================= */

    if (scanForm) {

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

                const result = analyzeURL(enteredURL);

                displayResult(result);

                scanButton.disabled = false;
                scanButton.textContent = "Analyze URL ↗";

                resultContainer.scrollIntoView({
                    behavior: "smooth",
                    block: "nearest"
                });

            }, 450);

        });
    }


    // Initial statistics display

    updateStatistics();

});


document.getElementById("nextFraud").addEventListener("click", function () {
    alert("Next Message button is working!");
});
const axios = require('axios');
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors")
const cvss = require('cvss');

const app = express();
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors("*"))

let CVES
const YEARS = ["2020", "2021", "2022"]

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1) + min)
}

app.use("/cves", async (req, res) => {
    const N = 5
    if (!CVES) {
        CVES = await getCVElist()
    }
    let result = []
    for (i = 0; i < N; i++) {
        result.push(CVES[randomInt(0, CVES.length - 1)])
    }
    res.status(200).json({ cves: result })
})

const abbreviate = (metric) => {
    return metric.charAt(0)
}

const getCVElist = async () => {
    let data = []
    YEARS.forEach((YEAR) => {
        const path = `https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=${YEAR}-08-01T00:00:00.000&pubEndDate=${YEAR}-11-28T00:00:00.000`
        const result = axios.get(path)
        data.push(result)
    })
    data = await Promise.all(data)
    data = data.map(elm => elm.data.vulnerabilities).flat()
    data = data.map(cve => {
        cve = cve.cve
        if (cve.metrics.cvssMetricV31) {
            const metrics = cve.metrics.cvssMetricV31[0].cvssData
            return {
                id: cve.id,
                description: cve.descriptions[0].value,
                vectorString: metrics.vectorString.split("/").slice(1).join("/"),
                AV: abbreviate(metrics.attackVector),
                AC: abbreviate(metrics.attackComplexity),
                PR: abbreviate(metrics.privilegesRequired),
                UI: abbreviate(metrics.userInteraction),
                S: abbreviate(metrics.scope),
                C: abbreviate(metrics.confidentialityImpact),
                I: abbreviate(metrics.integrityImpact),
                A: abbreviate(metrics.availabilityImpact),
                Score: metrics.baseScore,
                Severity: metrics.baseSeverity
            }
        }
    })
    data = data.filter(elm => elm != undefined)
    return data
}

app.use("/score/:vectorString", async (req, res) => {
    const vector_string = req.originalUrl.split("/score/")[1]
    const score = cvss.getScore(`CVSS:3.0/${vector_string}`);
    const rating = cvss.getRating(score);
    res.status(200).json({ score: score, rating: rating })
})

const PORT = 4000;
app.listen(
    PORT,
    console.log(`Server has started:\n -port:${PORT}\n`)
);




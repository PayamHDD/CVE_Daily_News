import re
import json
import asyncio
import aiohttp
#from Config.model import CPE, CVE
from typing import Optional, Dict, Any
from datetime import datetime, timedelta


#A class to provide NVD's Vulnerability feature (CVE)
class Vulnerability:
    #Base function to retrieve data
    def __init__(self, api_key=None, timeout=5):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.timeout = timeout
    async def _fetch(self, url: str):
        print(f"Fetching: {url}")
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                async with session.get(url, headers=headers) as resp:
                    resp.raise_for_status()
                    return await resp.json()
        except aiohttp.ClientError as err:
            print(f"Error fetching data: {err}")
            return None



    #Function to retrieve CVE data
    async def fetch_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}?cveId={cve_id}"
        data =  await self._fetch(url)
        if data:
            result = {}
            if data.get("vulnerabilities"):
                cve = data.get("vulnerabilities")[0]["cve"]
                affected = cve.get("affected", None)[0]
                metrics = cve.get("metrics", None)
                weaknesses = cve.get("weaknesses", None)
                references = cve.get("references")

                ######### CVE Base Information #########
                result["CVE-ID:"] = cve.get("id")
                result["Status:"] = cve.get("vulnStatus")
                result["Published:"] = cve.get("published")
                #result["Description"] = cve.get("descriptions")["value"] if cve.get("descriptions") \
                    #and cve.get("descriptions")["lang"] == "en" else None
                result["Affected Vendor:"] = affected.get("affectedData")[0]["vendor"] if affected else None
                result["Affected Product:"] = affected.get("affectedData")[0]["product"] if affected else None
                result["CVSSv3.1 Base Score:"] = metrics.get("cvssMetricV31")[0]["cvssData"]["baseScore"] \
                    if metrics.get("cvssMetricV31") else None
                result["CVSSv3.1 Severity v3.1:"] = metrics.get("cvssMetricV31")[0]["cvssData"]["baseSeverity"] \
                    if metrics.get("cvssMetricV31") else None
                result["CVSSv3.1 Vector:"] = metrics.get("cvssMetricV31")[0]["cvssData"]["vectorString"] \
                    if metrics.get("cvssMetricV31") else None
                result["Cisa KEV:"] = cve.get("cisaExploitAdd")
                result["Cisa Advisory:"] = cve.get("cisaRequiredAction")
                result["CPE & Version:"] = f"CVE is still under '{cve.get("vulnStatus")}' status" if cve.get("vulnStatus") in ["Awaiting Analysis", "Undergoing Analysis"] \
                    else re.findall("cpe.*", json.dumps(data))
                result["CWE ID:"] = re.findall("CWE-\d{1,3}", json.dumps(data))
                result["Reference & Tags:"] = {item.get("url"):item.get("tags") for item in references}
                return result
            else:
                return None
        else:
            return None



    #Function to retrieve time-range CVEs data, with or without Severity
    async def fetch_cves(self, severity=None, days=1):
        now = datetime.now()
        period  = now - timedelta(days=days)
        if severity:
            url = f"{self.base_url}?cvssV3Severity={severity}&pubStartDate={period.strftime("%Y-%m-%dT%H:%M:%S")}&pubEndDate={now.strftime("%Y-%m-%dT%H:%M:%S")}"
        else:
            url = f"{self.base_url}?pubStartDate={period.strftime("%Y-%m-%dT%H:%M:%S")}&pubEndDate={now.strftime("%Y-%m-%dT%H:%M:%S")}"
        headers = {}
        data = await self._fetch(url)
        if data:
            result = []
            if data.get("vulnerabilities"):
                for item in data.get("vulnerabilities"):
                    cve = item.get("cve")
                    temp ={}
                    temp["CVE-ID"] = cve.get("id")
                    temp["Description"] = cve.get("descriptions")
                    result.append(temp)
            return result
        else:
            return None



    #Function to retrieve time-range CVEs with KEV, with or without Severity
    async def fetch_cve_hasKEV(self, severity=None, days=30):
        now = datetime.now()
        month  = now - timedelta(days=days)
        if severity:
            url = f"{self.base_url}?cvssV3Severity={severity}&pubStartDate={month.strftime("%Y-%m-%dT%H:%M:%S")}&pubEndDate={now.strftime("%Y-%m-%dT%H:%M:%S")}&hasKev"
        else:
            url = f"{self.base_url}?pubStartDate={month.strftime("%Y-%m-%dT%H:%M:%S")}&pubEndDate={now.strftime("%Y-%m-%dT%H:%M:%S")}&hasKev"
        headers = {}
        data = await self._fetch(url)
        if data:
            result = []
            if data.get("vulnerabilities"):
                for item in data.get("vulnerabilities"):
                    cve = item.get("cve")
                    temp ={}
                    temp["CVE-ID"] = cve.get("id")
                    temp["Description"] = cve.get("descriptions")
                    result.append(temp)
            return result
        else:
            return None



    #Function to retrieve time-range CVEs by Keyword
    async def fetch_cves_by_keyword(self, keyword, exact=False, days=1):
        now = datetime.now()
        month  = now - timedelta(days=days)
        if exact:
            url = f"{self.base_url}?keywordSearch={keyword}&keywordExactMatch&pubStartDate={month.strftime("%Y-%m-%dT%H:%M:%S")}&pubEndDate={now.strftime("%Y-%m-%dT%H:%M:%S")}"
        else:
            url = f"{self.base_url}?keywordSearch={keyword}&pubStartDate={month.strftime("%Y-%m-%dT%H:%M:%S")}&pubEndDate={now.strftime("%Y-%m-%dT%H:%M:%S")}"
        data = await self._fetch(url)
        if data:
            result = []
            if data.get("vulnerabilities"):
                for item in data.get("vulnerabilities"):
                    cve = item.get("cve")
                    temp ={}
                    temp["CVE-ID"] = cve.get("id")
                    temp["Description"] = cve.get("descriptions")
                    result.append(temp)
            return result
        else:
            return None



############# TEST Class #############
vuln = Vulnerability()

#CVE_ID = "CVE-2026-20153"
CVE_ID = "CVE-2021-44228"

async def main():
    data = await vuln.fetch_cve(CVE_ID)
    for item in data:
        print(item)

if __name__ == "__main__":
    asyncio.run(main())